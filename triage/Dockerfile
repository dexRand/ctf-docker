# CTF Triage — deep recursive analysis + web GUI on top of the AperiSolve image.
#
# The base image is already a Debian 13 toolbox with the whole steg suite
# (binwalk, foremost, exiftool, steghide, outguess, jsteg, jphide, jpseek,
# zsteg, openstego, pngcheck, 7z, ffmpeg, GraphicsMagick, Flask, gunicorn...).
# Here we add what is missing for password attacks and the web GUI.
FROM ghcr.io/zeecka/aperisolve:latest

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates \
        john fcrackzip pdfcrack unzip zip xz-utils sox pngtools libmhash2 \
        hashcat pocl-opencl-icd \
 && curl -fsSL -o /tmp/stegseek.deb \
        https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb \
 && dpkg -i /tmp/stegseek.deb \
 && rm -f /tmp/stegseek.deb \
 && apt-get -f install -y \
 && rm -rf /var/lib/apt/lists/*

# Bake the most-used big wordlist (rockyou). Small lists are mounted from the
# repo at /wordlists so they can be edited without rebuilding.
RUN mkdir -p /opt/wordlists \
 && ( curl -fsSL -o /tmp/rockyou.tar.gz \
        https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz \
      && mkdir -p /tmp/rk && tar -xzf /tmp/rockyou.tar.gz -C /tmp/rk \
      && find /tmp/rk -name 'rockyou.txt' -exec mv {} /opt/wordlists/rockyou.txt \; \
      && rm -rf /tmp/rockyou.tar.gz /tmp/rk ) \
 || echo "WARN: rockyou download skipped"

COPY triage.py /usr/local/lib/triage/triage.py
COPY webapp.py /usr/local/lib/triage/webapp.py
COPY patterns.txt /usr/local/share/triage/patterns.txt
# vendored, MIT, zero-dependency zip2john replacement (hashcat hashes)
COPY third_party/ /opt/third_party/
RUN printf '#!/bin/sh\nexec python3 /usr/local/lib/triage/triage.py "$@"\n' > /usr/local/bin/triage \
 && chmod +x /usr/local/bin/triage

WORKDIR /data
EXPOSE 19013
# One worker: the run state lives in-process (background thread + polling API).
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:19013", \
     "--chdir", "/usr/local/lib/triage", "webapp:app"]
