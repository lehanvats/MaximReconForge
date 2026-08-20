FROM python:3.12-slim

# Install system dependencies, libpcap-dev for naabu, and apt-packaged scanners.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sqlmap \
    ca-certificates \
    curl \
    git \
    unzip \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Pinned release tags for pre-compiled GitHub release tarballs
ARG SUBFINDER_VER=2.6.6
ARG HTTPX_VER=1.6.9
ARG NAABU_VER=2.3.3
ARG NUCLEI_VER=3.3.7
ARG FFUF_VER=2.1.0
ARG AMASS_VER=4.2.0
# nuclei-templates release to bake in. Pinned + fetched as a tarball (below)
# rather than via `nuclei -update-templates`, which resolves the release
# through the GitHub *API* (60 req/hr unauthenticated) and silently installs
# nothing when that quota is exhausted — a non-deterministic build failure.
ARG NUCLEI_TEMPLATES_VER=10.4.7

# Install pre-compiled Linux x86_64 binaries directly from official GitHub releases.
# Add unzip -o flag so zip archives containing common files like LICENSE.md or README.md do not prompt.
RUN curl --retry 10 --retry-delay 2 --retry-all-errors -C - -fSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VER}/subfinder_${SUBFINDER_VER}_linux_amd64.zip" -o /tmp/sf.zip && unzip -o -q /tmp/sf.zip -d /usr/local/bin && rm /tmp/sf.zip

RUN curl --retry 10 --retry-delay 2 --retry-all-errors -C - -fSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_amd64.zip" -o /tmp/httpx.zip && unzip -o -q /tmp/httpx.zip -d /tmp/httpx && mv /tmp/httpx/httpx /usr/local/bin/pd-httpx && rm -rf /tmp/httpx*

RUN curl --retry 10 --retry-delay 2 --retry-all-errors -C - -fSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VER}/naabu_${NAABU_VER}_linux_amd64.zip" -o /tmp/naabu.zip && unzip -o -q /tmp/naabu.zip -d /usr/local/bin && rm /tmp/naabu.zip

RUN curl --retry 10 --retry-delay 2 --retry-all-errors -C - -fSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip && unzip -o -q /tmp/nuclei.zip -d /usr/local/bin && rm /tmp/nuclei.zip

RUN curl --retry 10 --retry-delay 2 --retry-all-errors -C - -fSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" -o /tmp/ffuf.tgz && tar -xzf /tmp/ffuf.tgz -C /usr/local/bin ffuf && rm /tmp/ffuf.tgz

RUN curl --retry 10 --retry-delay 2 --retry-all-errors -C - -fSL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VER}/amass_linux_amd64.zip" -o /tmp/amass.zip && unzip -o -q /tmp/amass.zip -d /tmp/amass && find /tmp/amass -name amass -type f -exec mv {} /usr/local/bin/ \; && rm -rf /tmp/amass*

RUN useradd -m -u 1000 runner
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=100 --retries 5 -r requirements.txt

COPY runner ./runner

# Ensure runner user has access to app, wordlists, and config directory
RUN mkdir -p /app/wordlists /home/runner/.config/subfinder /home/runner/.config/nuclei

# Download common wordlist for ffuf directory brute-forcing
RUN curl -fSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -o /app/wordlists/common.txt

RUN chown -R runner:runner /app /home/runner

USER runner

# Bake the nuclei templates into the image at a fixed, read-only path
# (/app/nuclei-templates). executor.py always passes `-t /app/nuclei-templates`
# so nuclei never needs to auto-detect or install them at runtime (the runtime
# root filesystem is read-only, and HOME/.config is an empty tmpfs).
#
# We download the templates as a release *tarball* from codeload (which is not
# subject to the GitHub API's 60 req/hr unauthenticated limit) instead of
# `nuclei -update-templates`, whose GitHub-API dependency silently no-ops when
# that quota is exhausted, producing an image where every nuclei run dies with
# "no templates found". The `[ "$COUNT" -gt 1000 ]` guard fails the build loudly
# if the install ever comes up empty again, instead of shipping a broken image.
# --retry 10/-C-/--max-time 1200: nuclei-templates is a large tarball and the
# link to GitHub can be slow/flaky (observed ~80KB/s). Resume (-C -) plus
# generous retries tolerate a mid-download drop instead of failing the build.
RUN curl --retry 10 --retry-delay 5 --retry-all-errors -C - --max-time 1200 -fSL \
        "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/v${NUCLEI_TEMPLATES_VER}" \
        -o /tmp/nuclei-templates.tgz \
    && mkdir -p /app/nuclei-templates \
    && tar -xzf /tmp/nuclei-templates.tgz -C /app/nuclei-templates --strip-components=1 \
    && rm /tmp/nuclei-templates.tgz \
    && COUNT="$(find /app/nuclei-templates -name '*.yaml' | wc -l)" \
    && echo "Installed ${COUNT} nuclei templates (v${NUCLEI_TEMPLATES_VER})" \
    && { [ "${COUNT}" -gt 1000 ] || { echo "FATAL: nuclei template install produced only ${COUNT} templates" >&2; exit 1; }; }

CMD ["python", "-m", "runner.main"]