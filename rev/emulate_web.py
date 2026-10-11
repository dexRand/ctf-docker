#!/usr/bin/env python3
"""emulate-web — small web GUI for the `emulate` helper inside the rev sandbox.

Serves a single page: pick or upload a binary, choose how to reach the routine
(symbol / absolute addr / objdump vaddr), pass integer arguments and/or hex
buffers, and see `rax` plus any memory dump. The page talks to three endpoints:

  GET  /api/files   -> list the files found under the workdir
  POST /api/upload  -> write a raw body (header X-Filename) into the workdir
  POST /api/run     -> run `emulate ... --json` and return its structured result

It runs *inside* the isolated `rev` container (no network egress); the host only
reaches it through the localhost socat proxy. Stdlib only, so the image needs no
extra server dependency. Shared visual language with the dashboard and StegSuite
(same design tokens + CRT treatment).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

EMULATE = os.environ.get("EMULATE_BIN", "/usr/local/bin/emulate")
WORK = os.environ.get("EMULATE_WORK", "/work")
MAX_BODY = 64 * 1024
MAX_UPLOAD = 128 * 1024 * 1024
RUN_TIMEOUT = int(os.environ.get("EMULATE_TIMEOUT", "30"))
MAX_STEPS = 50_000_000

_NUM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+)$")
_HEX = re.compile(r"^[0-9a-fA-F\s]*$")
_MEM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+):-?(0x[0-9a-fA-F]+|\d+)$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


def list_files(root: str) -> list[str]:
    out: list[str] = []
    for base, dirs, files in os.walk(root):
        depth = base[len(root):].count(os.sep)
        if depth >= 4:
            dirs[:] = []
        for name in files:
            out.append(os.path.relpath(os.path.join(base, name), root))
            if len(out) >= 2000:
                return sorted(out)
    return sorted(out)


def _safe_path(rel: str) -> str:
    rel = (rel or "").strip()
    full = os.path.realpath(os.path.join(WORK, rel))
    if not full.startswith(os.path.realpath(WORK) + os.sep) and full != os.path.realpath(WORK):
        raise ValueError("path escapes the workdir")
    if not os.path.isfile(full):
        raise ValueError("no such file in the workdir")
    return full


def build_argv(p: dict) -> list[str]:
    argv = [EMULATE, _safe_path(p.get("binary", ""))]
    mode = p.get("mode", "auto")
    if mode == "func" and p.get("func"):
        argv += ["--func", str(p["func"])]
    elif mode == "addr" and p.get("addr"):
        argv += ["--addr", str(p["addr"])]
    elif mode == "vaddr" and p.get("vaddr"):
        argv += ["--vaddr", str(p["vaddr"])]
    if p.get("raw"):
        argv.append("--raw")
    if p.get("base"):
        argv += ["--base", str(p["base"])]
    for h in _as_list(p.get("argbuf")):
        if not _HEX.match(h):
            raise ValueError(f"argbuf is not hex: {h!r}")
        argv += ["--argbuf", h.replace(" ", "")]
    for v in _as_list(p.get("args")):
        if not _NUM.match(v):
            raise ValueError(f"arg is not an integer: {v!r}")
        argv += ["--arg", v]
    for m in _as_list(p.get("mem")):
        if not _MEM.match(m):
            raise ValueError(f"mem must be ADDR:LEN, got {m!r}")
        argv += ["--mem", m]
    steps = int(p.get("steps") or 1_000_000)
    argv += ["--steps", str(max(1, min(steps, MAX_STEPS)))]
    argv.append("--json")
    return argv


def _as_list(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in re.split(r"[,\s]+", str(v)) if x.strip()]


def run(p: dict) -> dict:
    argv = build_argv(p)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=RUN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {RUN_TIMEOUT}s", "argv": argv[1:]}
    if proc.returncode != 0:
        return {"ok": False, "error": (proc.stderr or proc.stdout).strip(), "argv": argv[1:]}
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        return {"ok": True, "raw": proc.stdout, "argv": argv[1:]}
    return {"ok": True, "result": data, "argv": argv[1:]}


PAGE = r"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTF Toolbox — emulate (rev)</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Ctext y='14' font-size='14'%3E%3E_%3C/text%3E%3C/svg%3E">
<style>
  :root {
    --ink: 12 14 16; --panel: 20 23 26; --panel2: 26 30 34;
    --edge: 38 43 49; --edge2: 56 64 73;
    --acc: 69 224 140; --accdim: 20 51 37;
    --warn: 245 197 66; --info: 95 208 242;
    --danger: 255 97 102; --dangerlite: 255 179 182;
    --dim: 102 113 124; --fg: 215 221 227; --fglite: 170 180 189; --fgx: 244 247 249;
    --font: ui-monospace, 'JetBrains Mono', 'Cascadia Code', 'Fira Code', Menlo, Consolas,
      'Liberation Mono', 'DejaVu Sans Mono', monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; min-height: 100%; }
  body {
    background: rgb(var(--ink)); color: rgb(var(--fg)); font-family: var(--font);
    font-size: 14px; line-height: 1.5; padding: 1rem 1.25rem 3rem;
  }
  body::before {
    content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 1; opacity: .3;
    background: repeating-linear-gradient(0deg, rgba(0,0,0,.14) 0 1px, transparent 1px 4px),
      radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,.4));
  }
  main, header, footer { position: relative; z-index: 2; max-width: 1080px; margin: 0 auto; }
  h1 { font-size: 1.05rem; margin: 0 0 .2rem; color: rgb(var(--acc)); }
  h1 .prompt { opacity: .7; }
  p.sub { color: rgb(var(--dim)); margin: 0 0 1.2rem; font-size: 12px; }
  p.sub b { color: rgb(var(--fglite)); }
  p.hint { color: rgb(var(--fglite)); font-size: 12px; margin: -0.8rem 0 1.1rem;
    border-left: 2px solid rgb(var(--acc) / .6); padding-left: .6rem; }
  p.hint b { color: rgb(var(--acc)); font-weight: 600; }
  fieldset { border: 1px solid rgb(var(--edge)); border-radius: 4px; padding: .7rem .8rem; margin: 0 0 1rem; }
  legend { color: rgb(var(--acc)); text-transform: uppercase; font-size: 10px; letter-spacing: .18em; padding: 0 .4rem; }
  label { color: rgb(var(--fglite)); display: block; }
  label.check { margin-top: .6rem; }
  label.check input { width: auto; margin-right: .4rem; }
  input[type="text"], input[type="file"], select {
    width: 100%; background: rgb(var(--ink)); color: rgb(var(--fgx));
    border: 1px solid rgb(var(--edge)); border-radius: 4px; padding: .5rem .6rem;
    font: inherit; margin-top: .35rem;
  }
  input[type="text"]:focus, select:focus { outline: none; border-color: rgb(var(--acc)); }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; }
  .grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: .8rem; margin-top: .8rem; }
  @media (max-width: 700px) { .grid, .grid3 { grid-template-columns: 1fr; } }
  .modes { display: flex; flex-wrap: wrap; gap: .8rem; margin: .35rem 0 .2rem; }
  .modes label { display: flex; gap: .4rem; align-items: baseline; color: rgb(var(--fg)); }
  .modes input { width: auto; }
  .toolbar { display: flex; flex-wrap: wrap; gap: .5rem; margin: 0 0 1rem; align-items: center; }
  button {
    font: inherit; font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
    border: 1px solid rgb(var(--edge)); background: rgb(var(--panel)); color: rgb(var(--fglite));
    border-radius: 4px; padding: .35rem .8rem; cursor: pointer; min-height: 28px;
  }
  button:hover { border-color: rgb(var(--acc)); color: rgb(var(--fgx)); background: rgb(var(--panel2)); }
  button.acc { background: rgb(var(--acc)); border-color: rgb(var(--acc)); color: rgb(var(--ink)); font-weight: 700; }
  button.acc:hover { color: rgb(var(--ink)); }
  button:disabled { opacity: .5; cursor: wait; }
  .card { border: 1px solid rgb(var(--edge)); border-radius: 4px; background: rgb(var(--panel)); padding: .7rem .8rem; }
  .card.err { border-color: rgb(var(--danger) / .6); }
  .card .head { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; }
  .rax { color: rgb(var(--acc)); font-weight: 700; font-size: 1.15rem; }
  .card code {
    display: block; margin: .5rem 0 0; padding: .4rem .5rem; overflow-x: auto; white-space: pre;
    background: rgb(var(--ink)); border: 1px solid rgb(var(--edge)); border-radius: 3px;
    color: rgb(var(--fglite)); font-size: 12px;
  }
  pre.mem { margin: .5rem 0 0; padding: .5rem; overflow-x: auto; white-space: pre; font-size: 12px;
    background: rgb(var(--ink)); border: 1px solid rgb(var(--edge)); border-radius: 3px; color: rgb(var(--fglite)); }
  .err { color: rgb(var(--dangerlite)); }
  .muted { color: rgb(var(--dim)); }
  .banner { color: rgb(var(--acc)); }
  footer { margin-top: 1.5rem; color: rgb(var(--dim)); font-size: 11px;
    border-top: 1px solid rgb(var(--edge)); padding-top: .6rem; }
  footer b { color: rgb(var(--fglite)); }
  a { color: rgb(var(--info)); }
  code { word-break: break-word; }
</style>
</head>
<body>
<header>
  <h1><span class="prompt">$&nbsp;</span>emulate <span class="muted">· rev sandbox</span></h1>
  <p class="sub">Esegue una funzione <b>self-contained</b> (hash, KDF, de-offuscatori) con <b>Unicorn</b> e legge <code>rax</code> — più rapido che riscrivere la routine a mano.</p>
  <p class="hint">Come si usa: scegli (o <b>carica</b>) il <b>binario</b> → indica l'<b>entry</b> (simbolo ELF / indirizzo) → passa gli <b>argomenti</b> (interi e/o buffer hex) → <b>run</b>.</p>
</header>

<main>
  <form id="f">
    <fieldset>
      <legend>Target</legend>
      <label for="binary">Binario dal workdir <span class="muted">(./data/rev)</span></label>
      <select id="binary" required aria-label="binario dal workdir"></select>
      <p class="muted" id="filehint">caricamento…</p>
      <label for="upload">… oppure carica un binario <span class="muted">(max 128 MB)</span></label>
      <input type="file" id="upload" aria-label="carica un binario nel workdir">
    </fieldset>

    <fieldset>
      <legend>Entry</legend>
      <div class="modes" role="group" aria-label="come raggiungere la routine">
        <label><input type="radio" name="mode" value="func" checked> simbolo ELF <span class="muted">--func</span></label>
        <label><input type="radio" name="mode" value="addr"> assoluto <span class="muted">--addr</span></label>
        <label><input type="radio" name="mode" value="vaddr"> vaddr <span class="muted">--vaddr</span></label>
        <label><input type="radio" name="mode" value="auto"> entrypoint</label>
      </div>
      <input id="func" type="text" placeholder="secret_hash" autocomplete="off" spellcheck="false" aria-label="simbolo funzione">
      <input id="addr" type="text" placeholder="0x140001480" autocomplete="off" spellcheck="false" aria-label="indirizzo assoluto" hidden>
      <input id="vaddr" type="text" placeholder="0x1149" autocomplete="off" spellcheck="false" aria-label="indirizzo virtuale relativo" hidden>
    </fieldset>

    <fieldset>
      <legend>Argomenti</legend>
      <div class="grid">
        <label>Interi <span class="muted">(rdi,rsi,… · rcx,rdx,… su PE)</span>
          <input id="args" type="text" placeholder="5, 2" autocomplete="off" spellcheck="false"></label>
        <label>Buffer hex <span class="muted">(--argbuf, argomenti puntatore)</span>
          <input id="argbuf" type="text" placeholder="41424344, aabb" autocomplete="off" spellcheck="false"></label>
      </div>
      <div class="grid3">
        <label>steps<input id="steps" type="text" value="1000000" autocomplete="off" spellcheck="false"></label>
        <label>load base <span class="muted">(PIE/raw)</span><input id="base" type="text" placeholder="auto" autocomplete="off" spellcheck="false"></label>
        <label>dump di memoria <span class="muted">ADDR:LEN</span><input id="mem" type="text" placeholder="0x2000:16" autocomplete="off" spellcheck="false"></label>
      </div>
      <label class="check"><input type="checkbox" id="raw" aria-label="tratta il file come blob di codice"> blob di codice raw <span class="muted">--raw</span></label>
    </fieldset>

    <div class="toolbar">
      <button id="go" class="acc" type="submit">run</button>
      <button id="copy" type="button" disabled>copia comando</button>
    </div>
  </form>

  <section id="out" aria-live="polite"><p class="muted">—</p></section>
</main>

<footer>
  Solo funzioni <b>self-contained</b>: le chiamate a import/PLT (libc, KERNEL32) fermano l'emulazione. x86-64; su PE i primi 4 argomenti. La sandbox resta <b>senza rete in uscita</b>.
</footer>

<script>
const $ = (id) => document.getElementById(id);
let lastCmd = '';

function modeUI(){
  const m = document.querySelector('input[name=mode]:checked').value;
  $('func').hidden  = m !== 'func';
  $('addr').hidden  = m !== 'addr';
  $('vaddr').hidden = m !== 'vaddr';
}
document.querySelectorAll('input[name=mode]').forEach(r => r.addEventListener('change', modeUI));
modeUI();

async function loadFiles(){
  try{
    const files = await (await fetch('api/files', {cache:'no-cache'})).json();
    const sel = $('binary'); const cur = sel.value; sel.innerHTML = '';
    if(!files.length){ $('filehint').textContent = 'nessun file nel workdir — caricane uno o mettili in ./data/rev'; return; }
    files.forEach(f => { const o = document.createElement('option'); o.value = f; o.textContent = f; sel.appendChild(o); });
    if(files.includes(cur)) sel.value = cur;
    $('filehint').textContent = files.length + ' file nel workdir';
  }catch(e){ $('filehint').textContent = 'impossibile elencare i file: ' + e; }
}
loadFiles();

$('upload').addEventListener('change', async (ev) => {
  const file = ev.target.files[0];
  if(!file) return;
  $('filehint').textContent = 'carico ' + file.name + ' …';
  try{
    const r = await fetch('api/upload', {method:'POST', headers:{'X-Filename': file.name}, body: file});
    const j = await r.json();
    if(!j.ok) throw new Error(j.error || ('HTTP ' + r.status));
    await loadFiles();
    $('binary').value = j.name;
    $('filehint').textContent = 'caricato ' + j.name + ' (' + j.size + ' byte)';
  }catch(e){ $('filehint').textContent = 'upload fallito: ' + e; }
  ev.target.value = '';
});

$('copy').addEventListener('click', () => {
  if(lastCmd) navigator.clipboard.writeText(lastCmd).catch(() => {});
});

$('f').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const body = {
    binary: $('binary').value,
    mode: document.querySelector('input[name=mode]:checked').value,
    func: $('func').value, addr: $('addr').value, vaddr: $('vaddr').value,
    args: $('args').value, argbuf: $('argbuf').value, mem: $('mem').value,
    steps: $('steps').value, base: $('base').value, raw: $('raw').checked,
  };
  $('go').disabled = true;
  $('out').innerHTML = '<p class="muted">esecuzione…</p>';
  try{
    const r = await (await fetch('api/run', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(body)})).json();
    render(r);
  }catch(e){ $('out').innerHTML = '<div class="card err"><div class="head err">richiesta fallita</div><p class="muted">' + esc(e) + '</p></div>'; }
  finally{ $('go').disabled = false; }
});

function cmdLine(argv){ return 'emulate ' + (argv || []).map(esc).join(' '); }

function render(r){
  const out = $('out');
  if(!r.ok){
    lastCmd = r.argv ? cmdLine(r.argv) : '';
    $('copy').disabled = !lastCmd;
    out.innerHTML = '<div class="card err"><div class="head"><span class="err">errore</span></div>' +
      '<p class="err">' + esc(r.error || 'esecuzione fallita') + '</p>' +
      (r.argv ? '<code>' + cmdLine(r.argv) + '</code>' : '') + '</div>';
    return;
  }
  lastCmd = r.argv ? cmdLine(r.argv) : '';
  $('copy').disabled = !lastCmd;
  if(r.raw){
    out.innerHTML = '<div class="card"><pre class="mem">' + esc(r.raw) + '</pre></div>';
    return;
  }
  const d = r.result;
  let h = '<div class="card"><div class="head"><span class="rax">rax = 0x' + d.rax.toString(16) +
          '</span><span class="muted">(' + d.rax + ')</span></div>';
  h += '<p class="muted">format ' + esc(d.format) + ' · entry 0x' + d.entry.toString(16) +
       (d.load_base ? (' · base 0x' + d.load_base.toString(16)) : '') + '</p>';
  if(r.argv) h += '<code>' + cmdLine(r.argv) + '</code>';
  if(d.mem && d.mem.length){
    h += '<pre class="mem">';
    d.mem.forEach(m => { h += 'mem 0x' + m[0].toString(16) + '  ' + esc(m[1]) + '\n'; });
    h += '</pre>';
  }
  h += '</div>';
  out.innerHTML = h;
}

function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "emulate-web"

    def log_message(self, fmt, *args):  # keep the container logs tidy
        sys.stderr.write("emulate-web %s\n" % (fmt % args))

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/files":
            self._json(200, list_files(WORK))
        elif path == "/healthz":
            self._send(200, b"ok", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/upload":
            self._upload()
            return
        if path != "/api/run":
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            self._json(400, {"ok": False, "error": "bad body size"})
            return
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json(400, {"ok": False, "error": "invalid JSON"})
            return
        try:
            self._json(200, run(payload))
        except ValueError as exc:
            self._json(200, {"ok": False, "error": str(exc)})
        except Exception as exc:  # pragma: no cover
            self._json(200, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    def _upload(self) -> None:
        name = os.path.basename((self.headers.get("X-Filename") or "").strip())
        if not name or name in (".", "..") or not _NAME.match(name):
            self._json(400, {"ok": False, "error": "missing or invalid X-Filename"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._json(400, {"ok": False, "error": "empty upload"})
            return
        if length > MAX_UPLOAD:
            self._json(413, {"ok": False,
                             "error": f"file too large (max {MAX_UPLOAD // (1024 * 1024)} MB)"})
            return
        dest = os.path.join(WORK, name)
        remaining = length
        with open(dest, "wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(65536, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                remaining -= len(chunk)
        self._json(200, {"ok": True, "name": name, "size": length})


def main() -> int:
    host = os.environ.get("EMULATE_HOST", "0.0.0.0")
    port = int(os.environ.get("EMULATE_PORT", "8080"))
    if not os.path.isdir(WORK):
        print(f"emulate-web: workdir {WORK} missing", file=sys.stderr)
    if not os.access(EMULATE, os.X_OK):
        print(f"emulate-web: {EMULATE} is not executable", file=sys.stderr)
    print(f"emulate-web listening on {host}:{port} (workdir {WORK})", file=sys.stderr)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
