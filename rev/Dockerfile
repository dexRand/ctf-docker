# rev — sandbox per analisi ATTIVA di binari sconosciuti (ELF / PE / APK).
#
# Base upstream `pwntools/pwntools` (gdb, binutils, python, pwntools) + ttyd
# (terminale web) + qemu-user (arch diverse) + strace/ltrace + reversing
# (radare2, upx, apktool, jadx per PE/APK).
#
# L'isolamento lo impone il compose: rete interna senza internet, cap_drop ALL
# (+ SYS_PTRACE per gdb), no-new-privileges, limiti mem/cpu/pids. NON eseguire
# binari hostili fuori da questo container.
FROM pwntools/pwntools:stable@sha256:243d643d77ab8366e716158183c624d5f1d4493397ec7cb906e340d2025437ac

USER root

# ELF/PE/APK reversing: binutils (objdump legge i PE), radare2, upx, apktool (DEX).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        qemu-user qemu-user-static strace ltrace file socat gdb curl ca-certificates \
        radare2 upx-ucl apktool unzip \
 && rm -rf /var/lib/apt/lists/*

# ttyd from the distro, falling back to the upstream static release
RUN ( apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ttyd \
      && rm -rf /var/lib/apt/lists/* ) \
 || ( case "$(uname -m)" in \
        x86_64) a=ttyd.x86_64 ;; \
        aarch64|arm64) a=ttyd.aarch64 ;; \
        *) a=ttyd.x86_64 ;; \
      esac \
      && curl -fsSL -o /usr/local/bin/ttyd \
           "https://github.com/tsl0922/ttyd/releases/download/1.7.7/$a" \
      && chmod +x /usr/local/bin/ttyd )

ENV TERM=xterm-256color
WORKDIR /work
# no "checking for new versions" noise (the sandbox has no network anyway)
RUN printf '[update]\ninterval = never\n' > /etc/pwn.conf

# ---- Ghidra headless (CLI decompiler) ----
# Ghidra 12 needs a JDK (not just a JRE): install JDK 21 headless, then Ghidra.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless unzip \
 && rm -rf /var/lib/apt/lists/*
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip
RUN curl -fsSL -o /tmp/ghidra.zip "$GHIDRA_URL" \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && mv /opt/ghidra_*_PUBLIC /opt/ghidra \
 && rm -f /tmp/ghidra.zip \
 && chmod +x /opt/ghidra/support/analyzeHeadless
COPY ghidra/DecompileAll.java /opt/ghidra_scripts/DecompileAll.java
COPY ghidra-decompile.sh /usr/local/bin/ghidra-decompile
RUN chmod +x /usr/local/bin/ghidra-decompile

# ---- jadx (DEX -> Java; not packaged by the distro) ----
ARG JADX_VER=1.5.0
RUN curl -fsSL -o /tmp/jadx.zip \
      "https://github.com/skylot/jadx/releases/download/v${JADX_VER}/jadx-${JADX_VER}.zip" \
 && unzip -q /tmp/jadx.zip -d /opt/jadx \
 && rm -f /tmp/jadx.zip \
 && chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui \
 && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx

# ---- emulazione / report / constraint solving / esecuzione simbolica ----
# unicorn + capstone arrivano già con pwntools; aggiungiamo z3 (SMT), il helper
# `emulate` (esegue funzioni self-contained), `rev-report` (report di primo
# passaggio) e angr (esecuzione simbolica; pin `bitstring<5` per pyvex).
RUN pip install --no-cache-dir --break-system-packages z3-solver angr "bitstring<5"
COPY emulate.py /usr/local/bin/emulate
COPY rev_web.py /usr/local/bin/rev-web
COPY report.py /usr/local/bin/rev-report
COPY angr_run.py /usr/local/bin/angr-run
COPY entry.sh /usr/local/bin/rev-entry
RUN chmod +x /usr/local/bin/emulate /usr/local/bin/rev-web \
             /usr/local/bin/rev-report /usr/local/bin/angr-run /usr/local/bin/rev-entry

# web terminal + emulation GUI: banner + scorciatoie ad ogni login shell
COPY profile.sh /etc/profile.d/rev.sh
RUN chmod 0644 /etc/profile.d/rev.sh \
 && printf '\n# rev sandbox: scorciatoie e banner anche nelle shell non-login (code-server)\n. /etc/profile.d/rev.sh\n' >> /root/.bashrc

# 7681 = terminale web (ttyd), 8080 = GUI di emulazione. Entrambe sono
# raggiunte solo tramite i proxy localhost del compose: il sandbox non ha egress.
EXPOSE 7681 8080
ENTRYPOINT ["/usr/local/bin/rev-entry"]
