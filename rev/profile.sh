# rev sandbox: banner + scorciatoie per l'analisi ELF attiva.
# Copiato in /etc/profile.d/rev.sh (sorgente per le login shell di ttyd).

menu() {
  cat <<'EOF'
============================================================
 ELF sandbox (rev)  ·  rete isolata, nessun accesso a internet
 Binari: mettili in ./data/rev (montato qui come /work)
------------------------------------------------------------
  file BIN                 tipo, architettura, stripping
  checksec --file=BIN      RELRO / Canary / NX / PIE   (pwntools)
  readelf -a BIN           header, sezioni, simboli, reloc
  objdump -d -M intel BIN  disassemblaggio (Intel)
  strings -a BIN           stringhe (cerca la flag!)
  dec BIN                  decompila con Ghidra headless (in ./dec_out)
  gdb BIN                  debug interattivo
  strace BIN / ltrace BIN  syscall / librerie a runtime
  qemu-x86_64 BIN   qemu-aarch64 BIN   qemu-riscv64 BIN   (altre arch)
  python3                  pwntools gia' importabile:  from pwn import *
  menu | help-rev          rimostra questo aiuto
============================================================
EOF
}

# scorciatoie
dec()  { ghidra-decompile "$@"; }
sec()  { checksec --file="$1"; }
help-rev() { menu; }
alias rev-help='menu'

# mostra il menu all'apertura di una shell interattiva
case "$-" in
  *i*) menu ;;
esac
