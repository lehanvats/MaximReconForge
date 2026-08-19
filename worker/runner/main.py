"""
ARQ Worker entry point for sandboxed security tool execution.

Jobs:
- run_tool_job: Executes a single tool call request (validated tool name + arguments).
- run_recon:    Deterministic recon pipeline (subfinder → httpx → naabu → nmap).

Results are written to /engagements/<engagement_id>/ (Docker volume shared with
the backend) so the graph nodes can read them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from arq import run_worker
from arq.connections import RedisSettings

from runner.executor import execute_tool_call

logger = logging.getLogger(__name__)

ENGAGEMENTS_DIR = Path(os.environ.get("ENGAGEMENTS_DIR", "/engagements"))


def _write_findings(engagement_id: str, findings: list[dict[str, Any]]) -> Path:
    """Persist findings JSON to the shared engagements volume."""
    out_dir = ENGAGEMENTS_DIR / engagement_id / "whiteboard"
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o777)
    except Exception:
        pass
    out_file = out_dir / "findings.json"

    # Merge with any existing findings (in case multiple phases write)
    existing: list[dict[str, Any]] = []
    if out_file.exists():
        try:
            existing = json.loads(out_file.read_text(encoding="utf-8"))
        except Exception:
            existing = []

    merged = existing + findings
    out_file.write_text(json.dumps(merged, indent=2, default=str), encoding="utf-8")
    logger.info("Wrote %d findings (%d new) to %s", len(merged), len(findings), out_file)
    return out_file


def _parse_subfinder_output(stdout: str) -> list[str]:
    """Parse subfinder JSON-lines output into a list of subdomains."""
    subdomains: list[str] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host") or obj.get("input") or ""
            if host:
                subdomains.append(host)
        except json.JSONDecodeError:
            # Plain-text mode fallback (one subdomain per line)
            if "." in line and " " not in line:
                subdomains.append(line)
    return list(set(subdomains))


def _parse_httpx_output(stdout: str) -> list[dict[str, Any]]:
    """Parse httpx JSON-lines output into structured results."""
    results: list[dict[str, Any]] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append({
                "url": obj.get("url", ""),
                "status_code": obj.get("status_code", 0),
                "title": obj.get("title", ""),
                "tech": obj.get("tech", []),
                "host": obj.get("host", obj.get("input", "")),
                "content_length": obj.get("content_length", 0),
                "webserver": obj.get("webserver", ""),
                "header": obj.get("header", {}),
                "response_header": obj.get("response_header", ""),
            })
        except json.JSONDecodeError:
            continue
    return results


def _parse_naabu_output(stdout: str) -> list[dict[str, Any]]:
    """Parse naabu JSON-lines output into port results."""
    results: list[dict[str, Any]] = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            results.append({
                "host": obj.get("host", obj.get("ip", "")),
                "port": obj.get("port", 0),
            })
        except json.JSONDecodeError:
            # Plain text: "host:port"
            if ":" in line:
                parts = line.rsplit(":", 1)
                try:
                    results.append({"host": parts[0], "port": int(parts[1])})
                except ValueError:
                    pass
    return results


def _parse_nmap_xml(stdout: str) -> list[dict[str, Any]]:
    """Parse nmap XML output (-oX -) into service findings."""
    import xml.etree.ElementTree as ET

    results: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        logger.warning("Failed to parse nmap XML output")
        return results

    for host_elem in root.findall(".//host"):
        addr_elem = host_elem.find("address")
        addr = addr_elem.get("addr", "") if addr_elem is not None else ""

        for port_elem in host_elem.findall(".//port"):
            port_id = port_elem.get("portid", "0")
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            service_elem = port_elem.find("service")
            service_name = ""
            product = ""
            version = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")

            results.append({
                "host": addr,
                "port": int(port_id),
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
            })
    return results


async def startup(ctx: dict[str, Any]) -> None:
    config_dir = Path("/home/runner/.config")
    for tool in ["subfinder", "httpx", "naabu", "nuclei", "amass", "ffuf", "sqlmap"]:
        try:
            (config_dir / tool).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
    logger.info("Worker started up successfully — real tool execution enabled.")


async def shutdown(ctx: dict[str, Any]) -> None:
    logger.info("Worker shut down cleanly.")


# Tools that can legitimately run past the generic 300s default. Confirmed
# live: an unscoped nuclei -as call against the full ~14k-template set took
# ~300s and hit the default timeout exactly — a scoped ~900-template run
# completes in ~2:43, so the full set genuinely needs more than 5 minutes.
# ffuf/sqlmap get the same floor since they scale with wordlist/param count
# the same way. This only raises the floor — an explicitly larger
# caller-provided timeout is still respected.
_SLOW_TOOL_MIN_TIMEOUT = {
    "run_nuclei": 600,
    "run_ffuf": 450,
    "run_sqlmap": 450,
}


async def run_tool_job(
    ctx: dict[str, Any],
    engagement_id: str,
    tool_name: str,
    params: dict[str, Any],
    timeout_seconds: int = 300,
    output_cap_bytes: int = 1_000_000,
) -> dict[str, Any]:
    """ARQ job executing a single whitelisted tool call request."""
    logger.info("Worker received job: engagement=%s, tool=%s", engagement_id, tool_name)

    effective_timeout = max(timeout_seconds, _SLOW_TOOL_MIN_TIMEOUT.get(tool_name, 0))

    result = await execute_tool_call(
        tool_name=tool_name,
        params=params,
        timeout_seconds=effective_timeout,
        output_cap_bytes=output_cap_bytes,
    )

    return {
        "engagement_id": engagement_id,
        "tool_name": tool_name,
        "success": result.success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "result_hash": result.result_hash,
        "error": result.error,
    }


async def run_recon(ctx: dict[str, Any], engagement_id: str, domain: str = "") -> dict[str, Any]:
    """ARQ job executing the deterministic Recon pipeline.

    Pipeline: subfinder → httpx → naabu → nmap
    Each tool's output feeds the next. All findings are written to the shared
    engagements volume so the backend graph nodes can read them.
    """
    logger.info("=== RECON PIPELINE START for engagement %s (domain=%s) ===", engagement_id, domain)
    started_at = time.monotonic()

    if not domain:
        return {"engagement_id": engagement_id, "status": "error", "error": "No domain provided"}

    all_findings: list[dict[str, Any]] = []
    subdomains: list[str] = [domain]  # Always include the apex
    tool_log: list[dict[str, str]] = []

    # ── Step 1: Subdomain Discovery (subfinder) ─────────────────────────
    logger.info("[RECON 1/4] Running subfinder against %s", domain)
    sf_result = await execute_tool_call("run_subfinder", {"domain": domain}, timeout_seconds=120)
    tool_log.append({"tool": "subfinder", "success": str(sf_result.success), "exit_code": str(sf_result.exit_code)})

    if sf_result.success and sf_result.stdout:
        discovered = _parse_subfinder_output(sf_result.stdout)
        subdomains = list(set(subdomains + discovered))
        logger.info("[RECON 1/4] subfinder found %d subdomains", len(discovered))
        for sub in discovered:
            all_findings.append({
                "type": "subdomain",
                "subdomain": sub,
                "tool": "subfinder",
                "severity": "info",
                "description": f"Subdomain discovered: {sub}",
            })
    else:
        err_msg = sf_result.error or sf_result.stderr[:200] or sf_result.stdout[:200]
        logger.warning("[RECON 1/4] subfinder failed: %s", err_msg)

    # Persist after each step so a later-step timeout doesn't discard everything.
    _write_findings(engagement_id, all_findings)
    written_count = len(all_findings)

    # ── Step 2: HTTP Probing (httpx) ─────────────────────────────────────
    httpx_targets: list[str] = []
    for sub in subdomains:
        httpx_targets.extend([f"http://{sub}", f"https://{sub}"])
    httpx_targets = list(set(httpx_targets))

    logger.info("[RECON 2/4] Running httpx against %d target URLs", len(httpx_targets))
    httpx_result = await execute_tool_call(
        "run_httpx", {"targets": httpx_targets}, timeout_seconds=180
    )
    tool_log.append({"tool": "httpx", "success": str(httpx_result.success), "exit_code": str(httpx_result.exit_code)})

    live_hosts: list[str] = []
    live_hostnames: set[str] = set()
    if httpx_result.success and httpx_result.stdout:
        http_results = _parse_httpx_output(httpx_result.stdout)
        logger.info("[RECON 2/4] httpx found %d live hosts", len(http_results))
        for hr in http_results:
            live_hosts.append(hr.get("host") or hr.get("url", ""))
            # Record the hostname of every URL httpx confirmed live, so the
            # Python header/path prober (Step 2b) only touches hosts that
            # actually resolve and respond — instead of fanning out across
            # every enumerated subdomain, including ones with no DNS record
            # (that produced ~150 "probe_failed" findings, one per attempted
            # path on each dead host, and inflated the live-host count).
            hostname = urlparse(hr.get("url", "")).netloc.split(":")[0]
            if hostname:
                live_hostnames.add(hostname)
            all_findings.append({
                "type": "http_response",
                "url": hr["url"],
                "status_code": hr["status_code"],
                "title": hr.get("title", ""),
                "tech": hr.get("tech", []),
                "webserver": hr.get("webserver", ""),
                "tool": "httpx",
                "severity": "info",
                "description": f"Live host: {hr['url']} [{hr['status_code']}] {hr.get('title', '')}",
            })

    _write_findings(engagement_id, all_findings[written_count:])
    written_count = len(all_findings)

    # ── Step 2b: HTTP Header Inspection & Security Path Probing ─────────────
    # Uses `httpx` (async Python library) with HTTP/2 -> HTTP/1.1 -> Unverified 3-stage fallback,
    # explicit 10s timeouts, SSL certificate validation, and comprehensive exception findings.
    import httpx as httpx_lib
    import ssl

    async def _fetch_url_with_fallback(url: str) -> tuple[httpx_lib.Response | None, list[dict[str, Any]]]:
        extra_findings: list[dict[str, Any]] = []
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

        # Stage 1: HTTP/2 with strict SSL verification
        try:
            async with httpx_lib.AsyncClient(http2=True, verify=True, timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                return resp, extra_findings
        except Exception as e1:
            logger.info("[RECON 2b] Stage 1 (HTTP/2 verified) failed for %s: %s", url, e1)

        # Stage 2: HTTP/1.1 with strict SSL verification
        try:
            async with httpx_lib.AsyncClient(http2=False, verify=True, timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                extra_findings.append({
                    "type": "http2_negotiation_failure",
                    "target": url,
                    "severity": "info",
                    "cvss_score": 0.0,
                    "tool": "http_prober",
                    "description": f"HTTP/2 negotiation failed on {url} (ALPN fallback to HTTP/1.1 triggered)",
                })
                return resp, extra_findings
        except Exception as e2:
            logger.info("[RECON 2b] Stage 2 (HTTP/1.1 verified) failed for %s: %s", url, e2)

        # Stage 3: HTTP/1.1 unverified (captures headers despite SSL cert issues / edge proxy drops)
        try:
            async with httpx_lib.AsyncClient(http2=False, verify=False, timeout=10.0, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                extra_findings.append({
                    "type": "ssl_certificate_warning",
                    "target": url,
                    "severity": "low",
                    "cvss_score": 3.0,
                    "tool": "http_prober",
                    "description": f"Target {url} required unverified SSL context to respond",
                })
                return resp, extra_findings
        except Exception as e3:
            logger.info("[RECON 2b] Stage 3 (Unverified) failed for %s: %s", url, e3)

        # Stage 4: plain HTTP fallback. Some hosts don't serve HTTPS at all, so
        # every TLS stage above fails on connection — not a cert/negotiation
        # issue. Only meaningful if url was https://. A site reachable only over
        # plain HTTP is itself a Medium finding (no transport encryption).
        if url.startswith("https://"):
            http_url = "http://" + url[len("https://"):]
            try:
                async with httpx_lib.AsyncClient(http2=False, verify=False, timeout=10.0, follow_redirects=True) as client:
                    resp = await client.get(http_url, headers=headers)
                    extra_findings.append({
                        "type": "https_unavailable",
                        "target": http_url,
                        "severity": "medium",
                        "cvss_score": 5.3,
                        "tool": "http_prober",
                        "description": f"{url} has no working HTTPS listener; site is only reachable over plain HTTP ({http_url})",
                    })
                    return resp, extra_findings
            except Exception as e4:
                logger.warning("[RECON 2b] Stage 4 (plain HTTP) failed for %s: %s", http_url, e4)
                extra_findings.append({
                    "type": "probe_failed",
                    "target": url,
                    "severity": "info",
                    "cvss_score": 0.0,
                    "tool": "http_prober",
                    "description": f"Target {url} probe failed on all HTTPS stages and plain HTTP fallback: {e4}",
                })
        else:
            extra_findings.append({
                "type": "probe_failed",
                "target": url,
                "severity": "info",
                "cvss_score": 0.0,
                "tool": "http_prober",
                "description": f"Target {url} probe failed (connection refused/rate-limited)",
            })

        return None, extra_findings

    # Only probe hosts httpx confirmed live. Probing unresolved/dead subdomains
    # was the dominant noise source (every path attempt on a non-resolving host
    # became a separate "probe_failed" finding). If httpx returned nothing at all
    # (tool failure or an all-dead surface), fall back to probing just the apex
    # so a working root domain is never skipped — but never fan back out across
    # the unverified subdomain list.
    targets_to_check = sorted(live_hostnames) or [domain]
    logger.info("[RECON 2b] Inspecting security headers for %d live target(s): %s", len(targets_to_check), targets_to_check)

    # NOTE: this step inspects HTTP *security headers* only. Content/path
    # discovery (finding /wp-config.php, /.git, backup files, etc.) is NOT done
    # here — it is owned by the real `ffuf` binary, dispatched by the
    # exploitation phase with auto-calibration (-ac). A previous Python
    # path-prober here duplicated ffuf's job and, lacking ffuf's calibration,
    # turned every path on soft-404/WAF catch-all sites into a false "exposed"
    # finding. Header inspection stays because no scanner in the pipeline does
    # it (httpx reports headers but doesn't flag *missing* security headers).
    #
    # 8 concurrent connections against a single host tripped Vercel's edge
    # rate-limiting on a real test target (every probe came back refused).
    # 4 is still a large speedup over fully sequential while looking much
    # less like a burst/flood to WAFs with low per-IP burst thresholds.
    sem = asyncio.Semaphore(4)

    async def _bounded_fetch(url: str) -> tuple[httpx_lib.Response | None, list[dict[str, Any]]]:
        async with sem:
            return await _fetch_url_with_fallback(url)

    async def _probe_target(sub: str) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        # _fetch_url_with_fallback already cascades HTTPS (3 TLS stages) -> plain
        # HTTP internally, so a single call covers TLS-broken and HTTP-only hosts
        # (and emits an https_unavailable finding for the latter). Use the
        # response's actual URL — post-redirect / post-fallback — so findings
        # point at the location that was really inspected, not the requested one.
        resp, probe_findings = await _bounded_fetch(f"https://{sub}")
        findings.extend(probe_findings)

        if resp is not None:
            actual_url = str(resp.url)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            logger.info("[RECON 2b] Successfully fetched %s [HTTP %d] with %d headers", actual_url, resp.status_code, len(resp_headers))

            required_headers = [
                ("content-security-policy", "Medium", 5.3, "Missing Content-Security-Policy header"),
                ("x-content-type-options", "Low", 2.3, "Missing X-Content-Type-Options header"),
                ("x-frame-options", "Low", 2.3, "Missing X-Frame-Options header"),
                ("x-xss-protection", "Low", 2.3, "Missing X-XSS-Protection header"),
                ("referrer-policy", "Low", 2.3, "Missing Referrer-Policy header"),
                ("permissions-policy", "Low", 2.3, "Missing Permissions-Policy header"),
                ("cross-origin-opener-policy", "Low", 2.3, "Missing Cross-Origin-Opener-Policy header"),
                ("cross-origin-resource-policy", "Low", 2.3, "Missing Cross-Origin-Resource-Policy header"),
            ]
            for h_name, sev, score, desc in required_headers:
                if h_name not in resp_headers:
                    findings.append({
                        "type": "missing_header",
                        "target": sub,
                        "url": actual_url,
                        "header": h_name,
                        "severity": sev.lower(),
                        "cvss_score": score,
                        "tool": "http_headers",
                        "description": f"{desc} on {actual_url}",
                    })

        return findings

    target_results = await asyncio.gather(*(_probe_target(sub) for sub in targets_to_check))
    for findings in target_results:
        all_findings.extend(findings)

    _write_findings(engagement_id, all_findings[written_count:])
    written_count = len(all_findings)

    # ── Step 3: Port Scanning (naabu) ────────────────────────────────────
    logger.info("[RECON 3/4] Running naabu against %s", domain)
    naabu_result = await execute_tool_call(
        "run_naabu", {"target": domain, "ports": "top-1000"}, timeout_seconds=180
    )
    tool_log.append({"tool": "naabu", "success": str(naabu_result.success), "exit_code": str(naabu_result.exit_code)})

    open_ports: list[int] = []
    if naabu_result.success and naabu_result.stdout:
        port_results = _parse_naabu_output(naabu_result.stdout)
        open_ports = [pr["port"] for pr in port_results if pr.get("port")]
        logger.info("[RECON 3/4] naabu found %d open ports", len(open_ports))
        for pr in port_results:
            all_findings.append({
                "type": "open_port",
                "target": pr["host"],
                "port": pr["port"],
                "tool": "naabu",
                "severity": "info",
                "description": f"Open port: {pr['host']}:{pr['port']}",
            })
    else:
        logger.warning("[RECON 3/4] naabu failed: %s", naabu_result.error or naabu_result.stderr[:200])

    _write_findings(engagement_id, all_findings[written_count:])
    written_count = len(all_findings)

    # ── Step 4: Service Fingerprinting (nmap) ────────────────────────────
    port_str = ",".join(str(p) for p in open_ports) if open_ports else None
    logger.info("[RECON 4/4] Running nmap against %s (ports=%s)", domain, port_str or "default")
    nmap_params: dict[str, Any] = {"target": domain}
    if port_str:
        nmap_params["ports"] = port_str

    nmap_result = await execute_tool_call("run_nmap", nmap_params, timeout_seconds=300)
    tool_log.append({"tool": "nmap", "success": str(nmap_result.success), "exit_code": str(nmap_result.exit_code)})

    if nmap_result.success and nmap_result.stdout:
        services = _parse_nmap_xml(nmap_result.stdout)
        logger.info("[RECON 4/4] nmap found %d services", len(services))
        for svc in services:
            sev = "info"
            desc = f"Service: {svc['host']}:{svc['port']}/{svc['protocol']} — {svc['service']}"
            if svc.get("product"):
                desc += f" ({svc['product']}"
                if svc.get("version"):
                    desc += f" {svc['version']}"
                desc += ")"
            all_findings.append({
                "type": "service",
                "target": svc["host"],
                "port": svc["port"],
                "protocol": svc["protocol"],
                "state": svc["state"],
                "service": svc["service"],
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "tool": "nmap",
                "severity": sev,
                "description": desc,
            })
    else:
        logger.warning("[RECON 4/4] nmap failed: %s", nmap_result.error or nmap_result.stderr[:200])

    # ── Persist remaining findings (steps 1-3 were already written incrementally) ──
    _write_findings(engagement_id, all_findings[written_count:])

    elapsed = round(time.monotonic() - started_at, 1)
    logger.info(
        "=== RECON PIPELINE COMPLETE for %s — %d findings in %.1fs ===",
        engagement_id, len(all_findings), elapsed,
    )

    return {
        "engagement_id": engagement_id,
        "domain": domain,
        "status": "recon_completed",
        "findings_count": len(all_findings),
        "subdomains_found": len(subdomains),
        "live_hosts": len(live_hosts),
        "open_ports": len(open_ports),
        "tools_run": tool_log,
        "duration_seconds": elapsed,
    }


class WorkerSettings:
    redis_settings = RedisSettings.from_dsn(
        os.environ.get("REDIS_URL", "redis://redis:6379/0")
    )
    on_startup = startup
    on_shutdown = shutdown
    functions = [run_tool_job, run_recon]
    max_jobs = 4
    job_timeout = 900  # 15 min hard cap per job (2b probing is now parallelized; this is a safety margin, not the primary fix)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    run_worker(WorkerSettings)
