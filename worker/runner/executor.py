"""
Worker Executor — Executes whitelisted tool binaries in a sandboxed subprocess.

Security & Architectural Constraints:
- NEVER uses shell=True — arguments are passed as explicit argv lists.
- Enforces execution timeouts and stdout/stderr output size caps.
- Computes SHA256 result_hash for audit logging.
- Returns structured execution results.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _system_resolvers() -> list[str]:
    """Read nameserver IPs from /etc/resolv.conf.

    naabu ships its own DNS client that queries its default public resolver
    list directly over UDP/53, bypassing the container's configured
    resolver. On some container networks (e.g. Docker Desktop's Hyper-V/WSL2
    backend) only the container's own nameserver is reachable, so naabu's
    default/hardcoded resolvers silently fail to resolve any hostname
    ("no valid ipv4 or ipv6 targets were found"). Passing the system
    resolver explicitly via -r fixes this without hardcoding an IP that
    would only be correct on one platform.
    """
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            return [
                line.split()[1]
                for line in f
                if line.startswith("nameserver") and len(line.split()) >= 2
            ]
    except OSError:
        return []


@dataclass
class ExecutionResult:
    tool_name: str
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    result_hash: str
    error: str | None = None


def _truncate(data: bytes, cap: int, marker: bytes) -> bytes:
    """Cap ``data`` to at most ``cap`` bytes, reserving room for ``marker``."""
    if len(data) <= cap:
        return data
    keep = max(cap - len(marker), 0)
    return data[:keep] + marker


def build_cli_command(tool_name: str, params: dict[str, Any]) -> list[str]:
    """Map tool_name and validated Pydantic params to a safe argv command list."""
    if tool_name == "run_subfinder":
        # -timeout bounds each source; -max-time caps total enumeration so a
        # single slow/hanging passive source can't burn the whole job budget
        # (subfinder returns whatever it found so far when -max-time elapses).
        # -max-time is 1 min, comfortably under the 120s executor cap in
        # run_recon, so subfinder self-terminates and returns partial results
        # (success) instead of being hard-killed at the cap with nothing.
        return [
            "subfinder", "-d", str(params["domain"]),
            "-silent", "-json", "-timeout", "20", "-max-time", "1",
        ]

    elif tool_name == "run_amass":
        return ["amass", "enum", "-passive", "-d", str(params["domain"])]

    elif tool_name == "run_httpx":
        targets = params.get("targets", [])
        cmd = [
            "pd-httpx",
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
            # Without an explicit timeout/retries, httpx uses a short default and
            # gives up after one attempt. On hosts where the target has an AAAA
            # record but the box has no working IPv6 egress, the first dial stalls
            # on IPv6 and the probe is silently dropped — so genuinely-live HTTP
            # hosts get reported as dead. A longer timeout plus retries lets the
            # IPv4 attempt land instead of losing the host entirely.
            "-timeout", "15",
            "-retries", "2",
        ]
        if isinstance(targets, list):
            for t in targets:
                cmd.extend(["-u", str(t)])
        elif targets:
            cmd.extend(["-u", str(targets)])
        return cmd

    elif tool_name == "run_naabu":
        cmd = ["naabu", "-host", str(params["target"]), "-silent", "-json", "-sa", "-scan-type", "c"]
        resolvers = _system_resolvers()
        if resolvers:
            cmd.extend(["-r", ",".join(resolvers)])
        ports = params.get("ports")
        if ports == "top-1000" or not ports:
            cmd.extend(["-top-ports", "1000"])
        elif ports:
            cmd.extend(["-p", str(ports)])
        return cmd

    elif tool_name == "run_nmap":
        cmd = ["nmap", "-sV", "-sC", "-oX", "-"]
        ports = params.get("ports")
        if ports:
            cmd.extend(["-p", str(ports)])
        cmd.append(str(params["target"]))
        return cmd

    elif tool_name == "run_nuclei":
        # -rl (rate limit) capped well below nuclei's default of 150 req/s.
        # Confirmed live that the default trips real targets' burst protection
        # ("found unresponsive 30 times", scan stalls at ~23% with 0 further
        # matches); 30 req/s completes a full scan cleanly with real matches.
        # This is almost certainly why default-rate nuclei runs came back empty.
        cmd = ["nuclei", "-target", str(params["target"]), "-j", "-as", "-rl", "30"]

        # nuclei's -t flags are additive (a union), and -severity only narrows
        # AFTER every matching template is parsed into memory. Passing the full
        # /app/nuclei-templates tree (~14k files) on every call — even a scoped
        # "severity: medium" one — parses the whole tree first, which OOM-kills
        # the memory-capped worker. Only fall back to the full baked-in tree
        # when the caller scoped no specific templates.
        templates = params.get("templates", [])
        if templates:
            for t in templates:
                cmd.extend(["-t", str(t)])
        else:
            cmd.extend(["-t", "/app/nuclei-templates"])

        severity = params.get("severity")
        if severity:
            cmd.extend(["-severity", str(severity)])
        return cmd

    elif tool_name == "run_ffuf":
        cmd = [
            "ffuf",
            "-u",
            str(params["target_url"]),
            "-w",
            f"/app/wordlists/{params.get('wordlist', 'common.txt')}",
            "-r",  # Follow redirects
            # Auto-calibration: ffuf fires a batch of random-path requests first,
            # learns the response the target gives for content that does NOT
            # exist, and filters anything matching it. This is what kills the
            # false positives on WAF/catch-all sites (e.g. Cloudflare answers
            # 403 for every dotfile, which the old "-mc all -fc 404" matched as
            # a "hit" — reporting .git/.env/.htpasswd as exposed when they are
            # actually blocked). With -ac the uniform block response is filtered.
            "-ac",
            # Only surface codes that indicate a real, distinct resource. 403 and
            # 404 are deliberately excluded: 403 is the standard WAF/deny answer
            # (not an exposure) and 404 is absence. A genuinely exposed file
            # returns 200/401/redirect and is still caught.
            "-mc",
            "200,204,301,302,307,401,405,500",
            # ffuf's default User-Agent gets blocked outright by at least one
            # real target's Apache config (connection closes with EOF on every
            # request, confirmed live) — a normal browser UA fixes it.
            "-H",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            # Cap concurrency: ffuf defaults to 40 threads, which trips
            # burst-based rate limiting on real infrastructure.
            "-t",
            "10",
            "-timeout",  # per-request; default is short and drops slow/IPv6-stalled hosts
            "15",
            "-o",
            "-",
            "-of",
            "json",
            "-s",
        ]
        exts = params.get("extensions")
        if exts:
            cmd.extend(["-e", str(exts)])
        return cmd

    elif tool_name == "run_sqlmap":
        cmd = [
            "sqlmap",
            "-u",
            str(params["target_url"]),
            "--batch",
            "--random-agent",
            f"--level={params.get('level', 1)}",
            f"--risk={params.get('risk', 1)}",
        ]
        if params.get("method") == "POST" and params.get("data"):
            cmd.extend(["--data", str(params["data"])])
        return cmd

    else:
        raise ValueError(f"Unsupported tool binary: {tool_name}")


async def execute_tool_call(
    tool_name: str,
    params: dict[str, Any],
    timeout_seconds: int = 300,
    output_cap_bytes: int = 1_000_000,
) -> ExecutionResult:
    """Execute a whitelisted security tool in an isolated subprocess.

    Args:
        tool_name: Name of tool (e.g. 'run_subfinder').
        params: Validated dictionary of arguments.
        timeout_seconds: Hard execution timeout in seconds.
        output_cap_bytes: Maximum allowed bytes for stdout/stderr output.

    Returns:
        ExecutionResult containing exit code, stdout, stderr, and SHA256 hash.
    """
    try:
        cmd = build_cli_command(tool_name, params)
    except Exception as exc:
        return ExecutionResult(
            tool_name=tool_name,
            success=False,
            exit_code=-1,
            stdout="",
            stderr="",
            result_hash="",
            error=f"Command build error: {exc}",
        )

    # Log only the tool name and argument count — never the full argv, which
    # can contain sensitive data (e.g. sqlmap --data with session tokens).
    logger.info("Executing tool: %s (%d args)", tool_name, max(len(cmd) - 1, 0))

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            process.communicate(), timeout=float(timeout_seconds)
        )
    except asyncio.TimeoutError:
        try:
            process.kill()
        except OSError:
            pass
        return ExecutionResult(
            tool_name=tool_name,
            success=False,
            exit_code=-1,
            stdout="",
            stderr="",
            result_hash="",
            error=f"Tool execution timed out after {timeout_seconds}s",
        )
    except FileNotFoundError:
        return ExecutionResult(
            tool_name=tool_name,
            success=False,
            exit_code=-1,
            stdout="",
            stderr="",
            result_hash="",
            error=f"Binary for tool '{tool_name}' not found in PATH",
        )
    except Exception as exc:
        return ExecutionResult(
            tool_name=tool_name,
            success=False,
            exit_code=-1,
            stdout="",
            stderr="",
            result_hash="",
            error=f"Subprocess error: {exc}",
        )

    # Truncate if output exceeds size cap. The truncation marker is counted
    # against the cap so the returned payload never exceeds output_cap_bytes.
    stdout_bytes = _truncate(stdout_bytes, output_cap_bytes, b"\n[STDOUT TRUNCATED]")
    stderr_bytes = _truncate(stderr_bytes, output_cap_bytes, b"\n[STDERR TRUNCATED]")

    stdout_str = stdout_bytes.decode("utf-8", errors="replace")
    stderr_str = stderr_bytes.decode("utf-8", errors="replace")

    # Compute result SHA256 over stdout + stderr + exit code so the hash is a
    # stable audit anchor for both success and failure cases (some tools emit
    # their meaningful output on stderr, or produce nothing on stdout on error).
    hasher = hashlib.sha256()
    hasher.update(stdout_bytes)
    hasher.update(b"\x1e")  # record separator between streams
    hasher.update(stderr_bytes)
    hasher.update(b"\x1e")
    hasher.update(str(process.returncode).encode())
    result_hash = hasher.hexdigest()

    return ExecutionResult(
        tool_name=tool_name,
        success=(process.returncode == 0),
        exit_code=process.returncode or 0,
        stdout=stdout_str,
        stderr=stderr_str,
        result_hash=result_hash,
    )
