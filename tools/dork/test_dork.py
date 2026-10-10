#!/usr/bin/env python3
"""Test per il dork generator.

Il *riferimento* viene da fonti pubbliche su Google Dorking (raccolte e
ricontrollate contro il materiale online):

- Google Hacking Database (OffSec / exploit-db.com/google-hacking-database):
  categorie Footholds, Sensitive Directories, Files Containing Passwords/Juicy
  Info, Pages Containing Login Portals, Various Online Devices…
- Group-IB, ShadowDragon, Imperva, Secra: operatori `site: inurl: intitle:
  filetype:/ext: intext: cache:` e le query tipiche di un audit
  (`site:x filetype:pdf`, `site:x intitle:"index of"`, `site:x inurl:login`,
  `site:x ext:sql OR ext:bak OR ext:env`, `inurl:.git`).

I test verificano che i preset siano query ben formate, che i link generati siano
URL validi (con round-trip della query) e che le categorie di riferimento siano
coperte. In più: parsing e ricerca della GHDB (con righe reali come fixture).
Eseguibile anche senza pytest:  python3 tools/dork/test_dork.py
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote_plus, unquote_plus, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import dork  # noqa: E402  (import dopo sys.path)

DATA = dork.load_data(dork.DEFAULT_DORKS, dork.DEFAULT_PROVIDERS, dork.DEFAULT_META)
PRESETS = DATA["presets"]
ENGINES = {e["id"]: e for e in DATA["providers"]}

# operatori riconosciuti (dalla letteratura sui Google dork) + i nostri (host)
KNOWN_OPS = ("site:", "inurl:", "intitle:", "allinurl:", "allintitle:", "intext:",
             "ext:", "filetype:", "cache:", "hostname:", "org:", "ssl.", "ip:", "port:")

# copertura rispetto alle categorie di riferimento: ogni voce deve comparire in
# almeno un preset (keyword, case-insensitive)
REFERENCE_COVERAGE = {
    "documents":   ["ext:pdf", "ext:doc"],
    "dir_listing": ['intitle:"index of"'],
    "admin_login": ["inurl:admin", "inurl:login"],
    "config":      ["ext:env", "ext:yml"],
    "backup":      ["ext:sql", "ext:bak"],
    "vcs":         ["inurl:.git"],
    "subdomains":  ["site:*."],
    "errors":      ["stack trace", "sql syntax"],
    "secrets":     ["api_key", "password", "secret", "token"],
    "devices":     ["webcam", "axis-cgi"],
    "footholds":   ["phpinfo.php", "phpmyadmin"],
}

# esempi "da manuale": per ognuno deve esistere un preset che copre l'operatore e
# la keyword chiave (controllo che il generatore li sappia produrre)
REFERENCE_DORKS = {
    "docs":        ("site:example.com filetype:pdf", ["ext:pdf"]),
    "listing":     ('site:example.com intitle:"index of"', ['intitle:"index of"']),
    "admin":       ("site:example.com inurl:login", ["inurl:login"]),
    "dump":        ("site:example.com ext:sql OR ext:bak OR ext:env", ["ext:sql", "ext:env"]),
    "vcs":         ("inurl:.git site:example.com", ["inurl:.git"]),
    "subs":        ("site:.example.com", ["site:*."]),
    "keys":        ("site:example.com secret password", ["secret", "password"]),
    "cams":        ("site:example.com intitle:webcam", ["webcam"]),
    "footholds":   ("site:example.com inurl:phpinfo.php", ["phpinfo.php"]),
}


def gen(target="example.com", presets=None, engines=None):
    p = presets or [x["id"] for x in PRESETS]
    e = engines or dork.default_engine_ids(DATA["providers"])
    return json.loads(dork.render(DATA, target, p, e, True))


def balanced(q: str) -> bool:
    return (q.count("(") == q.count(")") and q.count("[") == q.count("]")
            and q.count('"') % 2 == 0)


# --------------------------------------------------------------------------- unit
def test_normalize_target():
    assert dork.normalize_target("example.com") == "example.com"
    assert dork.normalize_target("https://www.example.com/path?x=1") == "www.example.com"
    assert dork.normalize_target("http://a.b.c:8080/") == "a.b.c:8080"
    assert dork.normalize_target("  Example.COM.  ") == "Example.COM"
    assert dork.normalize_target("") == ""


def test_build_url_is_encoded_and_reversible():
    u = dork.build_url("https://www.google.com/search?q={q}", 'site:a.com "b c"')
    assert u.startswith("https://www.google.com/search?q=")
    assert "site%3Aa.com" in u
    # il parametro q fa il round-trip
    q = unquote_plus(u.split("q=", 1)[1])
    assert q == 'site:a.com "b c"'
    assert quote_plus('site:a.com "b c"') in u


def test_kind_matching():
    rows = {r["id"]: r for r in gen(presets=["docs", "gh-secret", "host-name"],
                                    engines=["google", "github", "shodan"])["dorks"]}
    # web -> solo motori web; code -> solo github; host -> solo shodan
    assert {l["engine"] for l in rows["docs"]["links"]} == {"Google"}
    assert {l["engine"] for l in rows["gh-secret"]["links"]} == {"GitHub"}
    assert {l["engine"] for l in rows["host-name"]["links"]} == {"Shodan"}


def test_no_engine_means_no_dork():
    # un preset "code" senza motori "code" selezionati non produce nulla
    out = gen(presets=["gh-secret"], engines=["google"])["dorks"]
    assert out == []


# ------------------------------------------------------------ conformità query
def test_every_preset_is_a_wellformed_query():
    for p in PRESETS:
        q = p["q"].replace("{t}", "example.com")
        assert q.strip(), p["id"]
        assert balanced(q), f"parentesi/virgolette non bilanciate in {p['id']}: {q}"
        # i preset "code" (GitHub/GitLab) sono termini/quoted string, non dork con
        # operatori: un operatore e' richiesto solo per web/host.
        if p["kind"] != "code":
            assert any(op in q for op in KNOWN_OPS), f"{p['id']}: nessun operatore noto ({q})"


def test_every_generated_url_is_valid_and_reversible():
    t = "sub.example.com"
    engs = [e["id"] for e in DATA["providers"]]
    for r in gen(target=t, engines=engs)["dorks"]:
        q = r["query"]
        for l in r["links"]:
            u = urlparse(l["url"])
            assert u.scheme in ("http", "https"), (l["engine"], l["url"])
            assert u.netloc, l["url"]
            assert quote_plus(q) in l["url"], (l["engine"], q)


def test_target_is_substituted_everywhere():
    for r in gen(target="target.tld")["dorks"]:
        assert "{t}" not in r["query"]
        assert "target.tld" in r["query"]


# ------------------------------------------------------------------- copertura
def test_reference_categories_are_covered():
    pool = " ".join(p["q"].lower() for p in PRESETS)
    missing = {cat: kws for cat, kws in REFERENCE_COVERAGE.items()
               if not any(kw.lower() in pool for kw in kws)}
    assert not missing, f"categorie non coperte: {missing}"


def test_reference_dorks_operators_are_supported():
    pool = " ".join(p["q"].lower() for p in PRESETS)
    for name, (_example, needles) in REFERENCE_DORKS.items():
        assert any(n.lower() in pool for n in needles), f"{name}: manca {needles}"


# ------------------------------------------------------------------------- CLI
def test_cli_list():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = dork.main(["--list"])
    assert rc == 0
    out = buf.getvalue()
    assert "PRESET:" in out and "PROVIDER" in out
    for p in PRESETS:
        assert p["id"] in out


def test_cli_json_output():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = dork.main(["example.com", "-p", "docs", "-e", "google", "--json"])
    assert rc == 0
    data = json.loads(buf.getvalue())
    assert data["target"] == "example.com"
    assert data["dorks"][0]["id"] == "docs"


def test_cli_out_writes_file():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "nested" / "report.md"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = dork.main(["example.com", "-p", "docs", "-e", "google", "-o", str(out)])
        assert rc == 0
        assert out.is_file()
        assert "site:example.com" in out.read_text(encoding="utf-8")


def test_cli_unknown_preset():
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = dork.main(["example.com", "-p", "does-not-exist"])
    assert rc == 2
    assert "sconosciut" in err.getvalue().lower()


def test_cli_normalizes_url_target():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        dork.main(["https://foo.example.com/x?y=1", "-p", "docs", "-e", "google", "--json"])
    assert json.loads(buf.getvalue())["target"] == "foo.example.com"


# ----------------------------------------------------------- provider (plugin)
def test_dork_plugins_are_valid():
    files = sorted(dork.DEFAULT_DORKS.glob("*.json"))
    assert files, "nessun dork-plugin in config/dork/dorks/"
    for f in files:
        blob = json.loads(f.read_text(encoding="utf-8"))
        assert isinstance(blob, dict) and "presets" in blob, f"{f.name}: manca 'presets'"
        for p in blob["presets"]:
            for k in ("id", "group", "kind", "name", "q"):
                assert k in p, f"{f.name}/{p.get('id')}: manca '{k}'"
            assert p["kind"] in ("web", "code", "host"), f"{p['id']}: kind={p['kind']}"
            assert "{t}" in p["q"], f"{p['id']}: la query non usa {{t}}"


def test_dork_bundle_matches_plugins():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "presets.json"
        presets = dork.build_presets(dork.DEFAULT_DORKS, out, dork.DEFAULT_META)
        assert json.loads(out.read_text(encoding="utf-8"))["presets"] == presets
    committed = json.loads(dork.DEFAULT_PRESETS.read_text(encoding="utf-8"))["presets"]
    assert committed == presets, "config/dork/presets.json non allineato: esegui ./ctf dork --build"


def test_unique_dork_ids():
    ids = [p["id"] for p in PRESETS]
    assert len(ids) == len(set(ids)), "id dork duplicati tra i plugin"


def test_provider_plugins_are_valid():
    files = sorted(dork.DEFAULT_PROVIDERS.glob("*.json"))
    assert files, "nessun provider in config/dork/providers/"
    for f in files:
        p = json.loads(f.read_text(encoding="utf-8"))
        for k in ("id", "name", "kind", "url"):
            assert k in p, f"{f.name}: manca '{k}'"
        assert p["kind"] in ("web", "code", "host"), f"{f.name}: kind non valido ({p['kind']})"
        assert "{q}" in p["url"], f"{f.name}: l'url non contiene {{q}}"
        assert f.stem == p["id"], f"{f.name}: id '{p['id']}' != nome file"


def test_provider_bundle_matches_plugins():
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "providers.json"
        providers = dork.build_providers(dork.DEFAULT_PROVIDERS, out)
        assert json.loads(out.read_text(encoding="utf-8"))["providers"] == providers
    committed = json.loads(dork.PROVIDERS_BUNDLE.read_text(encoding="utf-8"))["providers"]
    assert committed == providers, "config/dork/providers.json non allineato: esegui ./ctf dork --build"


def test_default_engines_are_flagged():
    defaults = dork.default_engine_ids(DATA["providers"])
    assert defaults, "nessun provider marcato default"
    assert all(ENGINES[i].get("default") for i in defaults)


# ---------------------------------------------------------- GHDB (exploit-db)
# Righe reali scaricate da https://www.exploit-db.com/google-hacking-database
# (usate come fixture, così i test non richiedono rete).
GHDB_FIXTURE = [
    {"id": 2, "cat": "Files Containing Juicy Info", "d": 'intitle:"Ganglia" "Cluster Report for"'},
    {"id": 169, "cat": "Files Containing Juicy Info", "d": "allinurl:/examples/jsp/snp/snoop.jsp"},
    {"id": 550, "cat": "Various Online Devices", "d": "camera linksys inurl:main.cgi"},
    {"id": 618, "cat": "Files Containing Passwords", "d": 'intitle:"index of" passwd'},
]
GHDB_RAW_TITLE = '<a href="/ghdb/2">intitle:"Ganglia" "Cluster Report for"</a>'


def test_clean_ghdb_title():
    assert dork.clean_ghdb_title(GHDB_RAW_TITLE) == 'intitle:"Ganglia" "Cluster Report for"'
    assert dork.clean_ghdb_title("no-anchor-here") == "no-anchor-here"


def test_parse_ghdb_record():
    rec = {"id": "2", "date": "2003-06-24", "url_title": GHDB_RAW_TITLE,
           "cat_id": ["8", "Files Containing Juicy Info"],
           "category": {"cat_title": "Files Containing Juicy Info"}}
    assert dork.parse_ghdb_record(rec) == {
        "id": 2, "cat": "Files Containing Juicy Info",
        "d": 'intitle:"Ganglia" "Cluster Report for"'}
    # fallback sulla categoria se manca l'oggetto `category`
    assert dork.parse_ghdb_record({"id": 9, "url_title": "x", "cat_id": ["1", "Footholds"]})["cat"] == "Footholds"


def _write_ghdb(d):
    p = Path(d) / "ghdb.json"
    p.write_text(json.dumps({
        "count": len(GHDB_FIXTURE),
        "categories": ["Files Containing Juicy Info", "Various Online Devices", "Files Containing Passwords"],
        "dorks": GHDB_FIXTURE,
    }), encoding="utf-8")
    return p


def test_search_ghdb_by_keyword_and_category():
    with tempfile.TemporaryDirectory() as d:
        p = _write_ghdb(d)
        assert {x["id"] for x in dork.search_ghdb(p, "camera", "")} == {550}
        assert {x["id"] for x in dork.search_ghdb(p, "", "passwords")} == {618}
        assert {x["id"] for x in dork.search_ghdb(p, "index of", "")} == {618}
        assert len(dork.search_ghdb(p, "", "")) == len(GHDB_FIXTURE)


def test_search_ghdb_missing_file():
    try:
        dork.search_ghdb(Path("/nonexistent/ghdb.json"), "x", "")
    except FileNotFoundError:
        return
    raise AssertionError("atteso FileNotFoundError")


def test_cli_ghdb_search_prefixes_target():
    with tempfile.TemporaryDirectory() as d:
        p = _write_ghdb(d)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = dork.main(["example.com", "--ghdb", "camera", "-e", "google",
                            "--ghdb-file", str(p), "--json"])
        assert rc == 0
        rows = json.loads(buf.getvalue())["dorks"]
        assert rows[0]["query"] == "site:example.com camera linksys inurl:main.cgi"
        assert rows[0]["links"][0]["url"].startswith("https://www.google.com/search?q=")


def test_cli_ghdb_missing_file_errors():
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = dork.main(["--ghdb", "x", "--ghdb-file", "/nonexistent/ghdb.json"])
    assert rc == 2
    assert "update" in err.getvalue().lower()


# ------------------------------------------------------------------- runner
def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  [PASS] {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  [FAIL] {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  [ERROR] {t.__name__}: {type(e).__name__}: {e}")
    total = len(tests)
    print(f"\n* {total - failed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
