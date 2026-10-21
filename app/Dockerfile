# StegSuite — self-hosted steganography/forensics workbench.
#
# Multi-stage: the Vue 3 SPA is built with Node, then served by FastAPI.
# The toolset base is pinned by digest (AperiSolve, MIT) so upstream updates
# can never break a rebuild. StegSuite's own code is independent.
#
# Build from the repository root:
#   docker build -t stegsuite:dev -f app/Dockerfile .

# ---------- frontend ----------
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS frontend
WORKDIR /fe
COPY app/frontend/package.json app/frontend/package-lock.json /fe/
RUN npm ci --no-audit --no-fund
COPY app/frontend/ /fe/
RUN npm run build

# ---------- backend + toolset ----------
FROM ghcr.io/zeecka/aperisolve@sha256:d45e1e129f210dd96aef7b2f046cb79d4ea1727591514c391dcd4d4d580d6ec5

USER root

# hex viewers, OCR, audio + password-cracking toolset
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        curl ca-certificates \
        xxd hexyl bsdmainutils binutils git tree \
        tesseract-ocr tesseract-ocr-ita multimon-ng sox zbar-tools qrencode tshark \
        unzip zip fcrackzip pdfcrack hashcat pocl-opencl-icd libmhash2 \
 && curl -fsSL -o /tmp/stegseek.deb \
        https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends /tmp/stegseek.deb \
 && rm -f /tmp/stegseek.deb \
 && rm -rf /var/lib/apt/lists/*

# bkcrack (ZipCrypto known-plaintext attacks), pinned prebuilt binary
RUN mkdir -p /tmp/bk && cd /tmp/bk \
 && case "$(uname -m)" in \
      x86_64) url="https://github.com/kimci86/bkcrack/releases/download/v1.8.1/bkcrack-1.8.1-Linux-x86_64.tar.gz" ;; \
      aarch64|arm64) url="https://github.com/kimci86/bkcrack/releases/download/v1.8.1/bkcrack-1.8.1-Linux-aarch64.tar.gz" ;; \
      *) url="" ;; \
    esac \
 && if [ -n "$url" ]; then \
      curl -fsSL -o bk.tgz "$url" && tar -xzf bk.tgz \
      && install -m 0755 "$(find . -name bkcrack -type f | head -1)" /usr/local/bin/bkcrack; \
    fi \
 && rm -rf /tmp/bk

# most-used big wordlist (small lists are mounted at /wordlists). The build
# fails if it can't be fetched (an image silently missing rockyou cracks less);
# offline builds can opt out with --build-arg ROCKYOU=0.
ARG ROCKYOU=1
RUN mkdir -p /opt/wordlists \
 && if [ "$ROCKYOU" = "1" ]; then \
      curl -fsSL -o /tmp/rockyou.tar.gz \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
      && mkdir -p /tmp/rk && tar -xzf /tmp/rockyou.tar.gz -C /tmp/rk \
      && find /tmp/rk -name 'rockyou.txt' -exec mv {} /opt/wordlists/rockyou.txt \; \
      && test -s /opt/wordlists/rockyou.txt \
      && rm -rf /tmp/rockyou.tar.gz /tmp/rk; \
    fi

COPY app/backend/requirements.txt /opt/stegsuite/requirements.txt
RUN python3 -m venv /opt/stegsuite/venv \
 && /opt/stegsuite/venv/bin/pip install --no-cache-dir -U pip \
 && /opt/stegsuite/venv/bin/pip install --no-cache-dir -r /opt/stegsuite/requirements.txt

COPY app/backend/ /opt/stegsuite/backend/
COPY third_party/ /opt/third_party/
COPY app/term.bashrc /etc/stegsuite/term.bashrc
# ---- Terminale CTF (:19022, servizio `term`): ttyd + zellij + docker CLI ----
# Stessa immagine di StegSuite (tutti i tool); la tab `rev` entra nel sandbox
# con `docker exec` passando da term-proxy (solo exec, niente create/stop).
ARG TTYD_VER=1.7.7
ARG ZELLIJ_VER=0.45.1
ARG DOCKER_CLI_VER=27.3.1
RUN case "$(uname -m)" in aarch64|arm64) a=aarch64 ;; *) a=x86_64 ;; esac \
 && curl -fsSL -o /usr/local/bin/ttyd "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VER}/ttyd.${a}" \
 && curl -fsSL "https://github.com/zellij-org/zellij/releases/download/v${ZELLIJ_VER}/zellij-no-web-${a}-unknown-linux-musl.tar.gz" \
      | tar -xz -C /usr/local/bin zellij \
 && curl -fsSL "https://download.docker.com/linux/static/stable/${a}/docker-${DOCKER_CLI_VER}.tgz" \
      | tar -xz -C /usr/local/bin --strip-components=1 docker/docker \
 && chmod +x /usr/local/bin/ttyd /usr/local/bin/zellij /usr/local/bin/docker \
 && zellij --version && docker --version
COPY app/term/config.kdl /root/.config/zellij/config.kdl
COPY app/term/ctf.kdl /root/.config/zellij/layouts/ctf.kdl
COPY app/term/entry.sh /usr/local/bin/ctf-term
COPY app/term/rev-shell.sh /usr/local/bin/ctf-rev-shell
RUN chmod +x /usr/local/bin/ctf-term /usr/local/bin/ctf-rev-shell
# same prompt/aliases/cdp in shells opened with docker exec (Terminale, :19022)
RUN echo '[ -f /etc/stegsuite/term.bashrc ] && . /etc/stegsuite/term.bashrc' >> /etc/bash.bashrc
# replace the placeholder SPA with the built Vue app
RUN rm -rf /opt/stegsuite/backend/static
COPY --from=frontend /fe/dist /opt/stegsuite/backend/static

WORKDIR /data
EXPOSE 19014
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:19014/api/v1/health || exit 1
CMD ["/opt/stegsuite/venv/bin/uvicorn", "backend.main:app", \
     "--host", "0.0.0.0", "--port", "19014", "--app-dir", "/opt/stegsuite"]
