# StegSuite — self-hosted steganography/forensics workbench.
#
# Base toolset is pinned by digest so upstream updates can never break a rebuild.
# The toolset image is AperiSolve (MIT); StegSuite's own code is independent.
#
# Build from the repository root:
#   docker build -t stegsuite:dev -f app/Dockerfile .
FROM ghcr.io/zeecka/aperisolve@sha256:d45e1e129f210dd96aef7b2f046cb79d4ea1727591514c391dcd4d4d580d6ec5

USER root

# hex viewers + password-cracking toolset
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates \
        xxd hexyl bsdmainutils \
        tesseract-ocr multimon-ng sox \
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

WORKDIR /data
EXPOSE 19014
CMD ["/opt/stegsuite/venv/bin/uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", "--port", "19014", "--app-dir", "/opt/stegsuite"]
