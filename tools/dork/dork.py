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
import datetime as dt
import html
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from urllib.parse import quote_plus

DEFAULT_PRESETS = Path(__file__).resolve().parents[2] / "config" / "dork" / "presets.json"
DEFAULT_GHDB = DEFAULT_PRESETS.with_name("ghdb.json")
GHDB_URL = "https://www.exploit-db.com/google-hacking-database"


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


# --------------------------------------------------------------------- GHDB
def clean_ghdb_title(url_title: str) -> str:
    """Estrae il testo del dork dall'HTML `<a href="/ghdb/N">DORK</a>`."""
    m = re.search(r">([^<]*)</a>", url_title or "")
    return html.unescape((m.group(1) if m else url_title or "")).strip()


def parse_ghdb_record(rec: dict) -> dict:
    cat = (rec.get("category") or {}).get("cat_title")
    if not cat:
        cid = rec.get("cat_id") or ["", "?"]
        cat = cid[1] if len(cid) > 1 else "?"
    return {"id": int(rec["id"]), "cat": cat, "d": clean_ghdb_title(rec.get("url_title", ""))}


def fetch_ghdb(url: str = GHDB_URL, page: int = 1000, timeout: int = 60) -> list[dict]:
    """Scarica tutta la GHDB via l'endpoint DataTables di exploit-db (paginato)."""
    out: list[dict] = []
    start = 0
    while True:
        req = urllib.request.Request(  # noqa: S310
            f"{url}?draw=1&start={start}&length={page}",
            headers={"User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest",
                     "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        rows = payload.get("data") or []
        out.extend(parse_ghdb_record(r) for r in rows)
        start += page
        if not rows or start >= int(payload.get("recordsTotal") or 0):
            break
    return out


def update_ghdb(out_path: Path, url: str = GHDB_URL) -> dict:
    dorks = fetch_ghdb(url)
    data = {"source": url, "updated": dt.date.today().isoformat(), "count": len(dorks),
            "categories": sorted({d["cat"] for d in dorks}), "dorks": dorks}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return data


def search_ghdb(path: Path, keyword: str, category: str, limit: int = 300) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    kw, cat = (keyword or "").lower(), (category or "").lower()
    out: list[dict] = []
    for d in data["dorks"]:
        if kw and kw not in d["d"].lower() and kw not in d["cat"].lower():
            continue
        if cat and cat not in d["cat"].lower():
            continue
        out.append(d)
        if len(out) >= limit:
            break
    return out


def render_ghdb(rows: list[dict], as_json: bool) -> str:
    if as_json:
        return json.dumps({"dorks": rows}, ensure_ascii=False, indent=2)
    if not rows:
        return "nessun dork GHDB corrispondente"
    out: list[str] = []
    for d in rows:
        out.append(f"## GHDB {d['id']} [{d['cat']}]")
        out.append(f"   {d['query']}")
        for l in d.get("links", []):
            out.append(f"   - {l['engine']}: {l['url']}")
        out.append("")
    return "\n".join(out).rstrip()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctf dork", description="Genera dork (Google/GitHub/Shodan) da un target.")
    ap.add_argument("target", nargs="?", help="dominio o keyword (es. esempio.com)")
    ap.add_argument("--preset", "-p", help="id preset, separati da virgola (default: tutti)")
    ap.add_argument("--engine", "-e", help="id motore, separati da virgola (default: dal preset file)")
    ap.add_argument("--list", "-l", action="store_true", help="elenca preset e motori")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--out", "-o", help="scrive il report su file (es. ./data/dork/report.md)")
    ap.add_argument("--update", action="store_true", help="scarica/aggiorna la GHDB locale (config/dork/ghdb.json)")
    ap.add_argument("--ghdb", metavar="KEYWORD", help="cerca nella GHDB locale (dork + link motori)")
    ap.add_argument("--ghdb-cat", help="filtra la GHDB per categoria (con --ghdb)")
    ap.add_argument("--ghdb-file", default=os.environ.get("DORK_GHDB", str(DEFAULT_GHDB)))
    ap.add_argument("--limit", type=int, default=300, help="max risultati GHDB (default 300)")
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

    if args.update:
        upd = update_ghdb(Path(args.ghdb_file))
        print(f"[+] GHDB aggiornata: {upd['count']} dork, {len(upd['categories'])} categorie -> {args.ghdb_file}")
        return 0

    if args.ghdb is not None or args.ghdb_cat:
        try:
            found = search_ghdb(Path(args.ghdb_file), args.ghdb or "", args.ghdb_cat or "", args.limit)
        except FileNotFoundError:
            print(f"[x] GHDB non trovata: {args.ghdb_file}\n    esegui: ./ctf dork --update", file=sys.stderr)
            return 2
        target = normalize_target(args.target) if args.target else ""
        engine_ids = ([s.strip() for s in args.engine.split(",")] if args.engine
                      else data["meta"].get("default_engines", []))
        engs = [e for e in data["meta"]["engines"] if e["id"] in engine_ids and e["kind"] == "web"]
        rows = []
        for d in found:
            q = f"site:{target} {d['d']}" if target else d["d"]
            rows.append({"id": d["id"], "cat": d["cat"], "query": q,
                         "links": [{"engine": e["name"], "url": build_url(e["url"], q)} for e in engs]})
        text = render_ghdb(rows, args.json)
        if args.out:
            outp = Path(args.out)
            outp.parent.mkdir(parents=True, exist_ok=True)
            outp.write_text(text + "\n", encoding="utf-8")
            print(f"[+] salvato: {outp}")
        else:
            print(text)
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
