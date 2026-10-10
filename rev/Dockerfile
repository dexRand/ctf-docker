# rev — sandbox per analisi ATTIVA di binari sconosciuti (ELF / PE / APK).
#
# Base upstream `pwntools/pwntools` (gdb, binutils, python, pwntools) + ttyd
# (terminale web) + qemu-user (arch diverse) + strace/ltrace + reversing
# (radare2, upx, apktool, jadx per PE/APK).
#
# L'isolamento lo impone il compose: rete interna senza internet, cap_drop ALL
# (+ SYS_PTRACE per gdb), no-new-privileges, limiti mem/cpu/pids. NON eseguire
# binari hostili fuori da questo container.
FROM pwntools/pwntools:stable

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

# web terminal: writable shell on port 7681 (published on 127.0.0.1 only)
# banner + scorciatoie (menu, dec, sec) ad ogni login shell
COPY profile.sh /etc/profile.d/rev.sh
RUN chmod 0644 /etc/profile.d/rev.sh

EXPOSE 7681
ENTRYPOINT ["ttyd", "-W", "-p", "7681", "-t", "fontSize=14", "bash", "-l"]
