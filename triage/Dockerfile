# CTF Triage — deep recursive analysis on top of the AperiSolve image.
#
# The base image is already a Debian 13 toolbox with the whole steg suite
# (binwalk, foremost, exiftool, steghide, outguess, jsteg, jphide, jpseek,
# zsteg, openstego, pngcheck, 7z, ffmpeg, GraphicsMagick, ...). Here we only
# add what is missing for password attacks and recursion:
#   - stegseek   : fast steghide passphrase cracker (wordlist)
#   - john       : archive/PDF/office hash cracking
#   - fcrackzip  : zip password cracking
#   - unzip/zip/xz-utils/sox/pngtools for extra formats
FROM ghcr.io/zeecka/aperisolve:latest

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        curl ca-certificates \
        john fcrackzip pdfcrack unzip zip xz-utils sox pngtools libmhash2 \
 && curl -fsSL -o /tmp/stegseek.deb \
        https://github.com/RickdeJager/stegseek/releases/download/v0.6/stegseek_0.6-1.deb \
 && dpkg -i /tmp/stegseek.deb \
 && rm -f /tmp/stegseek.deb \
 && apt-get -f install -y \
 && rm -rf /var/lib/apt/lists/*

COPY triage.py /usr/local/bin/triage
COPY patterns.txt /usr/local/share/triage/patterns.txt
RUN chmod +x /usr/local/bin/triage

WORKDIR /data

# Long-running idle container: the pipeline is driven by `./ctf triage <file>`.
CMD ["sleep", "infinity"]
