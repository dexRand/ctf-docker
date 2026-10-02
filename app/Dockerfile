# StegSuite — self-hosted steganography/forensics workbench.
#
# Multi-stage: the Vue 3 SPA is built with Node, then served by FastAPI.
# The toolset base is pinned by digest (AperiSolve, MIT) so upstream updates
# can never break a rebuild. StegSuite's own code is independent.
#
# Build from the repository root:
#   docker build -t stegsuite:dev -f app/Dockerfile .

# ---------- frontend ----------
FROM node:20-alpine AS frontend
WORKDIR /fe
COPY app/frontend/package.json /fe/package.json
RUN npm install --no-audit --no-fund
COPY app/frontend/ /fe/
RUN npm run build

# ---------- backend + toolset ----------
FROM ghcr.io/zeecka/aperisolve@sha256:d45e1e129f210dd96aef7b2f046cb79d4ea1727591514c391dcd4d4d580d6ec5

USER root

# hex viewers, OCR, audio + password-cracking toolset
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates \
        xxd hexyl bsdmainutils \
        tesseract-ocr multimon-ng sox zbar-tools qrencode \
        unzip zip fcrackzip pdfcrack hashcat pocl-opencl-icd libmhash2 \
 && curl -fsSL -o /tmp/stegseek.deb \
        https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb \
 && dpkg -i /tmp/stegseek.deb \
 && rm -f /tmp/stegseek.deb \
 && apt-get -f install -y \
 && rm -rf /var/lib/apt/lists/*

# most-used big wordlist (small lists are mounted at /wordlists)
RUN mkdir -p /opt/wordlists \
 && ( curl -fsSL -o /tmp/rockyou.tar.gz \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
      && mkdir -p /tmp/rk && tar -xzf /tmp/rockyou.tar.gz -C /tmp/rk \
      && find /tmp/rk -name 'rockyou.txt' -exec mv {} /opt/wordlists/rockyou.txt \; \
      && rm -rf /tmp/rockyou.tar.gz /tmp/rk ) \
 || echo "WARN: rockyou download skipped"

COPY app/backend/requirements.txt /opt/stegsuite/requirements.txt
RUN python3 -m venv /opt/stegsuite/venv \
 && /opt/stegsuite/venv/bin/pip install --no-cache-dir -U pip \
 && /opt/stegsuite/venv/bin/pip install --no-cache-dir -r /opt/stegsuite/requirements.txt

COPY app/backend/ /opt/stegsuite/backend/
COPY triage/third_party/ /opt/third_party/
COPY app/term.bashrc /etc/stegsuite/term.bashrc
# replace the placeholder SPA with the built Vue app
RUN rm -rf /opt/stegsuite/backend/static
COPY --from=frontend /fe/dist /opt/stegsuite/backend/static

WORKDIR /data
EXPOSE 19014
CMD ["/opt/stegsuite/venv/bin/uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", "--port", "19014", "--app-dir", "/opt/stegsuite"]
