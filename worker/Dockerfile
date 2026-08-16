# syntax=docker/dockerfile:1
#
# Multi-stage build for the sandboxed scanner worker.
#
# Stage 1 compiles the Go-based ProjectDiscovery/ffuf/amass binaries with a
# MODERN Go toolchain (Debian's golang-go is 1.19, too old for nuclei v3 /
# naabu / amass which need Go >= 1.21). Stage 2 is a slim runtime that copies
# only the finished binaries plus the apt-packaged scanners (nmap, sqlmap).
#
# This image intentionally installs the full tool set so that when the
# worker-dispatch path is wired up, every whitelisted tool is already present.

# ---------------------------------------------------------------------------
# Stage 1 — build the Go security binaries
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS gotools

# Pinned versions for reproducible builds. Bump these deliberately, never @latest.
ARG SUBFINDER_VERSION=v2.6.6
ARG HTTPX_VERSION=v1.6.9
ARG NAABU_VERSION=v2.3.3
ARG NUCLEI_VERSION=v3.3.7
ARG FFUF_VERSION=v2.1.0
ARG AMASS_VERSION=v4.2.0

ENV GOPATH=/go
ENV GOBIN=/go/bin
ENV CGO_ENABLED=1

# naabu links against libpcap at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
 && go install -v github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
 && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION} \
 && go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
 && go install -v github.com/ffuf/ffuf/v2@${FFUF_VERSION} \
 && go install -v github.com/owasp-amass/amass/v4/...@${AMASS_VERSION}

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim

# apt-packaged scanners + runtime libs. libpcap0.8 is naabu's runtime dep;
# dnsutils/ca-certificates/curl are useful for the recon tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    ca-certificates \
    curl \
    git \
    dnsutils \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Pull in the compiled Go binaries onto the PATH.
COPY --from=gotools /go/bin/ /usr/local/bin/

RUN useradd -m -u 1000 runner

# Pre-fetch nuclei templates into a world-readable, image-baked location so the
# read-only worker can run nuclei without needing to download them at runtime.
# The dispatch code should call nuclei with `-t /opt/nuclei-templates`.
# Guarded with `|| true` so a GitHub hiccup never fails the whole build.
ENV HOME=/opt
RUN nuclei -update-templates || true \
 && chmod -R a+rX /opt/nuclei-templates 2>/dev/null || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runner ./runner

# Ensure the runner user owns the app tree and wordlists dir.
RUN mkdir -p /app/wordlists && chown -R runner:runner /app

# At runtime the container root FS is read-only (see docker-compose.yml), so
# point HOME at the writable tmpfs for any tool scratch/config files.
ENV HOME=/tmp

USER runner
CMD ["python", "-m", "runner.main"]
