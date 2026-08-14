# Running MaximReconForge on localhost

This branch (`local-host-working`) runs the full assessment pipeline **inside
the FastAPI process** and streams live output to the React frontend over a
WebSocket — no Redis, no arq worker, and no Docker required.

The same LangGraph pipeline that `run_cli.py` uses now drives the browser UI:
live terminal output while it runs, then a final page that renders the generated
markdown report and lets you download it.

## Prerequisites

- Python 3.12, Node 18+
- A reachable Postgres database and a Groq API key. These are already set in the
  repo-root `.env` (`DATABASE_URL`, `GROQ_API_KEY`). The database tables are
  managed by Alembic (`cd backend && alembic upgrade head` if starting fresh).

## 1. Backend (port 8000)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # first time only
pip install -r requirements.txt                     # first time only
uvicorn app.main:app --reload --port 8000
```

The API validates scope, creates the engagement, and immediately starts running
the recon → enumeration → vuln-analysis → exploitation → reporting graph inline.
This is controlled by `RUN_SCANS_INLINE=true` (the default). Set it to `false`
to fall back to the Redis/arq worker dispatch path.

## 2. Frontend (port 3000)

```bash
cd frontend
cp .env.example .env        # VITE_API_BASE_URL=http://localhost:8000
npm install                 # first time only
npm run dev                 # http://localhost:3000
```

## 3. Use it

1. Open http://localhost:3000 and register / log in.
2. Enter a target domain and click **Start Scan**.
3. Watch the live terminal + pipeline progress as the real scan runs.
4. When it completes, the **Report** tab renders the generated markdown; click
   **Download .md** to save it.

> Targets on the scope blocklist (`localhost`, `google.com`, `example.com`) and
> anything resolving to a private IP are rejected. `scanme.nmap.org` is a good
> public test target.

## How the live stream works

- `POST /engagements` launches `app/live/runner.run_engagement_inline` as a
  background task and returns immediately.
- The runner publishes `phase`, `log`, `counts`, `complete`, and `error` events
  to an in-process bus (`app/live/bus.py`) as the graph executes.
- `GET ws://localhost:8000/ws/engagements/{id}/live` authenticates from the same
  httpOnly cookie as the REST API, verifies ownership, and relays those events.
- `GET /engagements/{id}/report` returns the rendered markdown;
  `GET /engagements/{id}/report/download` returns it as a file attachment.
