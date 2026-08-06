"""Live engagement streaming (localhost mode).

Runs the supervisor graph inline inside the FastAPI process and pushes
progress + log events to subscribers over an in-memory pub/sub bus, so the
frontend can render live output without needing Redis/arq or a Docker worker.
"""
