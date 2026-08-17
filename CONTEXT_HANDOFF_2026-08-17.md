# MaximReconForge — Development State & Handoff Summary

> **Date:** August 17, 2026
> **Status:** Docker-worker recon pipeline (`subfinder → pd-httpx → naabu → nmap`, plus LLM-dispatched `nuclei`/`ffuf`/`sqlmap`) debugged, fixed, and verified against real live targets. Commit `4c5b5f5` on `fix/hybrid-prober-worker-pipeline`.
>
> This supersedes [`CONTEXT_HANDOFF.md`](CONTEXT_HANDOFF.md) (Aug 16), which is kept for history — that session got the pipeline wired up; this one found and fixed the bugs that kept it from actually finishing a scan.

---

## 1. Starting point

The branch already had four fixes applied before this session began (binary collision, naabu privilege escalation, curl retry/resume, 3-stage HTTP TLS fallback — see prior commit `b6e70a2`). This session's job was to verify them and get a real end-to-end scan working. Verification (Phase 1 static review, Phase 2 live testing in a rebuilt Docker image) confirmed all four worked — but running the *actual* pipeline against real targets surfaced five more bugs that static testing hadn't caught, all fixed and re-verified live in this session.

---

## 2. Bugs found and fixed

### A. naabu silently failed to resolve any hostname
naabu ships its own DNS client that queries a fixed public-resolver list directly, bypassing the container's configured nameserver. On Docker Desktop's network backend, only the container's own resolver was reachable — so naabu failed on *every* hostname with `no valid ipv4 or ipv6 targets were found`, while working fine on raw IPs. Fixed by reading `/etc/resolv.conf` at runtime and passing it to naabu via `-r` ([`worker/runner/executor.py`](worker/runner/executor.py) — `_system_resolvers()`).

### B. Recon findings were only persisted once, at the very end
The 4-step recon pipeline (`run_recon` in [`worker/runner/main.py`](worker/runner/main.py)) accumulated all findings in memory and wrote them to `/engagements/<id>/whiteboard/findings.json` only after step 4 completed. If the ARQ job hit its timeout partway through (which step C below made likely), **everything collected so far — including real naabu/nmap results — was silently discarded**. Fixed: findings are now written incrementally after each of the 4 steps, so a late-stage timeout only loses that step's data, not the whole scan.

### C. Step 2b's security-probing loop was fully sequential
The HTTP header/common-path prober (`_fetch_url_with_fallback`, step "2b") checks up to 12 URLs per hostname variant (main page + 11 common paths like `/wp-admin`), each with a 3-stage TLS fallback (up to 30s if all three fail). Run sequentially across 2 hostname variants, a domain with one unreachable variant (e.g. a bare apex with no HTTPS — very common) could burn **~6 minutes**, which was consuming the entire `job_timeout` before naabu/nmap ever ran. Fixed with `asyncio.gather` + a semaphore. Started at concurrency 4→8 for speed, but **8 concurrent connections tripped Vercel's edge rate-limiting** on a real test site (every single probe, including the previously-successful main page, started coming back `connection refused`). Settled on **semaphore=4** — cuts the worst case to well under a minute while looking much less like a burst/flood to WAFs with low per-IP thresholds.

### D. nuclei's templates were never actually installed
This was the big one. Every `run_nuclei` call failed with `Could not find template '/app/nuclei-templates': no such file or directory`. Root cause, in two parts:
1. The Dockerfile's template-install step (`nuclei -update-templates -duc`) **silently no-ops** — `-duc` (disable-update-check) combined with `-update-templates` makes nuclei report success in ~10s while installing nothing, apparently because disabling the update *check* also skips the logic that decides an install is needed. Confirmed by running the same command manually without `-duc`: it correctly downloaded all 13,841 template files in ~110s.
2. Even if templates had installed, nuclei's default template directory is CWD-relative (`/app/nuclei-templates`), and the worker's `docker-compose.yml` runs the container with `read_only: true` — so nuclei could never lazily install them at runtime either. Fixed by explicitly targeting `/app/nuclei-templates` via `-ud` at build time (baked into the read-only image, which is fine — nuclei only needs to *read* them) and having `executor.py` always pass `-t /app/nuclei-templates` explicitly rather than relying on nuclei's own auto-detection.

Verified live: a scoped nuclei scan against `scanme.nmap.org` loaded 904 templates, clustered to 372 requests, and correctly fingerprinted `Apache/2.4.7` via `apache-detect.yaml` — full JSON output with request/response/matcher details.

### E. Backend had no logging configuration
`logging.basicConfig()` was never called in [`backend/app/main.py`](backend/app/main.py), so every `logger.info()` call throughout the LangGraph Commander/reasoning loop (proposed tool calls, iteration counts, phase-complete summaries) was silently dropped by Python's default WARNING-level root logger. This is what made bug D so hard to diagnose in the first place — the Commander's repeated `run_ffuf` fallback (compensating for nuclei never returning usable results) was invisible in `docker logs`. One-line fix, huge debugging-visibility win.

---

## 3. Files modified (commit `4c5b5f5`)

- [`worker/runner/executor.py`](worker/runner/executor.py) — `_system_resolvers()` + naabu `-r` fix; nuclei `-t /app/nuclei-templates` fix
- [`worker/runner/main.py`](worker/runner/main.py) — incremental `_write_findings()` calls; concurrent step-2b probing (`asyncio.Semaphore(4)`); `job_timeout` 600s → 900s (safety margin, not the primary fix)
- [`worker/Dockerfile`](worker/Dockerfile) — nuclei template install step: removed `-duc`, added explicit `-ud /app/nuclei-templates`
- [`backend/app/main.py`](backend/app/main.py) — added `logging.basicConfig(level=logging.INFO, ...)`

---

## 4. Live verification performed this session

All fixes were confirmed against real running containers and real targets, not just code review:

- **`www.gopaparthiv.in`** (user's own domain, authorized): full pipeline run completed in 209s post-fix (vs. timing out and losing everything, pre-fix). naabu found real open ports; nmap fingerprinted them; the HTTP prober correctly generated `ssl_certificate_warning`/`probe_failed` findings against real self-signed-cert and unreachable-host test sites (`self-signed.badssl.com`, `expired.badssl.com`).
- **`scanme.nmap.org`** (safe repeated-testing target): multiple full pipeline runs; recon consistently completes in ~110-210s with real service data (`Apache httpd 2.4.7` on :80, `tcpwrapped` on :8080); nuclei scoped scans return real matches.
- Compared generated reports against a prior report from the pipeline's native/inline (non-Docker) mode to confirm the real-tool pipeline's output quality and identify remaining gaps (see below).

---

## 5. Known issues NOT fixed this session (flagged, not resolved)

1. **`www.gopaparthiv.in` is currently rate-limited/blocked by Vercel's edge WAF** (`403 Forbidden`, tracked request IDs from Vercel's `bom1` region), a direct consequence of this session's own repeated automated testing volume against it. Not a code bug — needs the domain left alone for a while before testing it again.
2. **Local dev SQLite database has no volume mount.** `DATABASE_URL=sqlite+aiosqlite:///./maximreconforge.db` in `.env`, but `docker-compose.yml` only mounts `./engagements:/engagements` — every backend container restart wipes all users and engagement DB rows (though the `engagements/<id>/report` and `whiteboard` files on disk survive, since those live in the mounted volume). Test users had to be re-registered multiple times this session because of this.
3. **The Commander LLM sometimes calls `nuclei` with no severity/template scope**, triggering a full scan against all ~13,841 templates, which can take 5+ minutes and blow past the tool-dispatch timeout. This is a prompt/scoping issue in `vuln_analysis_node`, not a code bug — worth nudging the system prompt to default to a severity filter or specific template tags.
4. **The worker's HTTP prober doesn't extract TLS certificate details** (issuer, expiry, subject) — the native/inline pipeline's report included this and it's genuinely useful; the Docker-worker pipeline's `_fetch_url_with_fallback` currently doesn't parse it from the response's SSL context.
5. **Docker Desktop instability under sustained heavy use.** Across this session, Docker Desktop crashed/hung multiple times (a stale `dockerInference` reparse-point file blocking startup once, later `500 Internal Server Error` responses from the daemon with zombie processes left over from earlier crash/restart cycles). Root cause traced to host memory exhaustion (down to 2.4GB free of 15.7GB total after ~5 hours of continuous builds/execs). A full cleanup (`Stop-Process` on all Docker/WSL processes + `wsl --shutdown` + relaunch) recovered ~1.5GB but the underlying constraint (15.7GB total RAM) means this will likely recur under similarly heavy sessions.

---

## 6. Next steps for next session

1. If picking up `www.gopaparthiv.in` testing again, wait a meaningful amount of time first (hours, not minutes) or test from a different network to confirm the Vercel block has lifted.
2. Fix the SQLite volume-mount gap (#2 above) so local dev state survives container restarts — either mount the `.db` file's directory or move local dev to a proper Postgres container matching production.
3. Add a severity/tag scoping default to the vuln-analysis system prompt so nuclei calls stay bounded (#3 above).
4. Consider adding TLS certificate extraction to the HTTP prober (#4 above) to close the remaining gap vs. the native pipeline's report quality.
5. If Docker Desktop instability recurs, check free system memory first (`Get-CimInstance Win32_OperatingSystem`) before assuming it's a code/container issue — it very likely isn't.
