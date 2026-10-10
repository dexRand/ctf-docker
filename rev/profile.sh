# rev sandbox: banner + scorciatoie per l'analisi sfida (ELF / PE / APK).
# Copiato in /etc/profile.d/rev.sh (sorgente per le login shell di ttyd).

menu() {
  cat <<'EOF'
============================================================
 rev sandbox  ·  ELF / PE / APK  ·  rete isolata (no internet)
 File: mettili in ./data/rev (montato qui come /work)
------------------------------------------------------------
  file BIN                 tipo, architettura, stripping
  checksec --file=BIN      RELRO / Canary / NX / PIE   (pwntools)
  readelf -a BIN           header, sezioni, simboli, reloc   (ELF)
  objdump -d -M intel BIN  disassemblaggio  (legge anche i PE/.exe)
  rabin2 -I BIN / r2 -A BIN   header/info e analisi con radare2
  strings -a BIN           stringhe (cerca la flag!)
  upx -d BIN               scompatta un binario packed con UPX
  dec BIN                  decompila con Ghidra headless (in ./dec_out)
  gdb BIN                  debug interattivo
  strace BIN / ltrace BIN  syscall / librerie a runtime
  apk FILE.apk             apktool: estrae manifest/smali in FILE_apktool/
  jd FILE.apk              jadx: decompila in Java in FILE_jadx/
  qemu-x86_64 BIN   qemu-aarch64 BIN   qemu-riscv64 BIN
  python3                  pwntools gia' importabile:  from pwn import *
  menu | help-rev          rimostra questo aiuto
============================================================
EOF
}

# scorciatoie
dec()  { ghidra-decompile "$@"; }
sec()  { checksec --file="$1"; }
apk()  { apktool d -f "$1" -o "${1%.*}_apktool"; }
jd()   { jadx -d "${1%.*}_jadx" "$1"; }
help-rev() { menu; }
alias rev-help='menu'

# mostra il menu all'apertura di una shell interattiva
case "$-" in
  *i*) menu ;;
esac
