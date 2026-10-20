#!/usr/bin/env python3
"""Invia file locali a StegSuite (API) e stampa flag/password trovate.

    scan.py file.png
    scan.py a.png b.pcapng --mode check
    scan.py file --json

Configurazione da ambiente (impostata da `./ctf scan`): STEGSUITE, STEGSUITE_API_KEY.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stegsuite_client as ss  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctf scan", description="Analizza file con StegSuite e stampa le flag.")
    ap.add_argument("files", nargs="+", help="uno o più file locali")
    ap.add_argument("--mode", default="auto", choices=["auto", "check"])
    ap.add_argument("--timeout", type=int, default=900, help="attesa massima in secondi")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    for f in args.files:
        if not Path(f).is_file():
            print(f"[x] file non trovato: {f}", file=sys.stderr)
            return 2
    try:
        ss.call("/health")  # sanity check: StegSuite raggiungibile?
    except Exception as exc:  # noqa: BLE001
        print(f"[x] StegSuite non raggiungibile su {ss.ROOT}: {exc}", file=sys.stderr)
        print("    avvialo con:  ./ctf up", file=sys.stderr)
        return 2

    res = ss.analyze([Path(f) for f in args.files], args.mode, timeout_s=args.timeout)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"progetto {res['project']} · status {res['status']} · "
              f"{len(res['flags'])} flag · {res['seconds']}s")
        for v in res["flags"]:
            print(f"  FLAG  {v}")
        for v in res["passwords"]:
            print(f"  pass  {v}")
        print(f"  GUI:   {ss.ROOT}/#/p/{res['project']}")
    return 1 if res["status"] in ("timeout", "error") else 0


if __name__ == "__main__":
    raise SystemExit(main())
