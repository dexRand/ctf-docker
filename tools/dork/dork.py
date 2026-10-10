#!/usr/bin/env python3
"""Dork generator (CLI) — costruisce query Google/GitHub/Shodan da un target.

Non fa scraping: stampa le query e i link pronti da aprire. Usa gli stessi preset
della web UI (config/dork/presets.json), così le due interfacce restano allineate.

    dork.py esempio.com
    dork.py esempio.com --preset docs,conf --engine google,shodan
    dork.py --list
    dork.py esempio.com --json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote_plus

DEFAULT_PRESETS = Path(__file__).resolve().parents[2] / "config" / "dork" / "presets.json"


def load_presets(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def normalize_target(raw: str) -> str:
    """Riduce un URL al suo host (per i dork `site:`)."""
    t = (raw or "").strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        t = t.split(sep, 1)[0]
    return t.rstrip(".")


def build_url(template: str, query: str) -> str:
    return template.replace("{q}", quote_plus(query))


def render(data: dict, target: str, preset_ids: list[str], engine_ids: list[str], as_json: bool) -> str:
    engines = [e for e in data["meta"]["engines"] if e["id"] in engine_ids]
    rows: list[dict] = []
    for p in data["presets"]:
        if p["id"] not in preset_ids:
            continue
        engs = [e for e in engines if e["kind"] == p["kind"]]
        if not engs:
            continue
        query = p["q"].replace("{t}", target)
        rows.append({
            "id": p["id"], "group": p["group"], "name": p["name"], "query": query,
            "links": [{"engine": e["name"], "url": build_url(e["url"], query)} for e in engs],
        })
    if as_json:
        return json.dumps({"target": target, "dorks": rows}, ensure_ascii=False, indent=2)
    if not rows:
        return "nessun dork per i motori/preset selezionati"
    out: list[str] = [f"# target: {target}  ({len(rows)} dork)\n"]
    for r in rows:
        out.append(f"## {r['group']} — {r['name']}")
        out.append(f"   {r['query']}")
        for l in r["links"]:
            out.append(f"   - {l['engine']}: {l['url']}")
        out.append("")
    return "\n".join(out).rstrip()


def list_all(data: dict) -> str:
    out = ["PRESET:"]
    for p in data["presets"]:
        out.append(f"  {p['id']:<11} [{p['kind']:<4}] {p['group']:<8} {p['name']}")
    out.append("\nMOTORI:")
    for e in data["meta"]["engines"]:
        out.append(f"  {e['id']:<10} [{e['kind']:<4}] {e['name']}")
    out.append(f"\ndefault engines: {', '.join(data['meta'].get('default_engines', []))}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctf dork", description="Genera dork (Google/GitHub/Shodan) da un target.")
    ap.add_argument("target", nargs="?", help="dominio o keyword (es. esempio.com)")
    ap.add_argument("--preset", "-p", help="id preset, separati da virgola (default: tutti)")
    ap.add_argument("--engine", "-e", help="id motore, separati da virgola (default: dal preset file)")
    ap.add_argument("--list", "-l", action="store_true", help="elenca preset e motori")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--out", "-o", help="scrive il report su file (es. ./data/dork/report.md)")
    ap.add_argument("--presets-file", default=os.environ.get("DORK_PRESETS", str(DEFAULT_PRESETS)))
    args = ap.parse_args(argv)

    path = Path(args.presets_file)
    if not path.is_file():
        print(f"[x] preset non trovati: {path}", file=sys.stderr)
        return 2
    data = load_presets(path)

    if args.list:
        print(list_all(data))
        return 0

    if not args.target:
        ap.print_help()
        return 1

    target = normalize_target(args.target)
    preset_ids = [s.strip() for s in args.preset.split(",")] if args.preset else [p["id"] for p in data["presets"]]
    engine_ids = ([s.strip() for s in args.engine.split(",")] if args.engine
                  else data["meta"].get("default_engines", [e["id"] for e in data["meta"]["engines"]]))
    unknown = set(preset_ids) - {p["id"] for p in data["presets"]}
    if unknown:
        print(f"[x] preset sconosciuti: {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    text = render(data, target, preset_ids, engine_ids, args.json)
    if args.out:
        outp = Path(args.out)
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(text + "\n", encoding="utf-8")
        print(f"[+] salvato: {outp}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
