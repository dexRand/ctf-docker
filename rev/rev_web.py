#!/usr/bin/env python3
"""rev-web — small web workbench for the rev sandbox (emulate / brute / report).

Serves one page with three tabs over the sandbox tools, so the recurring moves
are a form instead of a command line:

  emulate  run a self-contained x86-64 function with Unicorn and read rax
  brute    sweep the first argument until rax (or a memory window) matches
  report   first-pass report (checksec/imports/strings/Ghidra) via rev-report

Endpoints:
  GET  /api/files   list files under the workdir
  POST /api/upload  write a raw body (header X-Filename) into the workdir
  POST /api/run     emulate a single call (structured JSON result)
  POST /api/brute   emulate --brute (text result)
  POST /api/report  rev-report --print (Markdown result)

Runs *inside* the isolated `rev` container (no egress); the host reaches it only
through the localhost socat proxy. Stdlib only. Same visual language as the
dashboard and StegSuite (shared design tokens + CRT).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

EMULATE = os.environ.get("EMULATE_BIN", "emulate")
REPORT = os.environ.get("REV_REPORT_BIN", "rev-report")
WORK = os.environ.get("REV_WEB_WORK", "/work")
MAX_BODY = 64 * 1024
MAX_UPLOAD = 128 * 1024 * 1024
RUN_TIMEOUT = int(os.environ.get("REV_RUN_TIMEOUT", "30"))
BRUTE_TIMEOUT = int(os.environ.get("REV_BRUTE_TIMEOUT", "300"))
REPORT_TIMEOUT = int(os.environ.get("REV_REPORT_TIMEOUT", "600"))
MAX_STEPS = 50_000_000

_NUM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+)$")
_HEX = re.compile(r"^[0-9a-fA-F\s]*$")
_MEM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+):-?(0x[0-9a-fA-F]+|\d+)$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


# --------------------------------------------------------------------------- #
# workdir helpers
# --------------------------------------------------------------------------- #
def list_files(root: str) -> list[str]:
    out: list[str] = []
    for base, dirs, files in os.walk(root):
        if base == root and "reports" in dirs:      # generated output, not an input binary
            dirs.remove("reports")
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


def _as_list(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in re.split(r"[,\s]+", str(v)) if x.strip()]


def build_argv(p: dict, json_out: bool = True) -> list[str]:
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
    if p.get("brute"):
        argv += ["--brute", str(p["brute"])]
        if p.get("expected"):
            argv += ["--expected", str(p["expected"])]
        if p.get("expected_mem"):
            if ":" not in str(p["expected_mem"]):
                raise ValueError("expected-mem must be ADDR:LEN:HEX")
            argv += ["--expected-mem", str(p["expected_mem"])]
    if json_out:
        argv.append("--json")
    return argv


def _exec(argv: list[str], timeout: int):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "", f"timeout dopo {timeout}s", True
    return proc.returncode, proc.stdout or "", proc.stderr or "", False


def run_emulate(p: dict) -> dict:
    argv = build_argv(p, json_out=True)
    rc, out, err, timed = _exec(argv, RUN_TIMEOUT)
    if timed:
        return {"ok": False, "error": err, "argv": argv[1:]}
    if rc != 0:
        return {"ok": False, "error": (err or out).strip(), "argv": argv[1:]}
    try:
        return {"ok": True, "result": json.loads(out), "argv": argv[1:]}
    except ValueError:
        return {"ok": True, "raw": out, "argv": argv[1:]}


def run_brute(p: dict) -> dict:
    if not p.get("brute"):
        return {"ok": False, "error": "serve un range (es. 0:100000 o 1,2,3)"}
    if not p.get("expected") and not p.get("expected_mem"):
        return {"ok": False, "error": "serve --expected (rax) e/o una memoria attesa"}
    argv = build_argv(p, json_out=False)
    rc, out, err, timed = _exec(argv, BRUTE_TIMEOUT)
    if timed:
        return {"ok": False, "error": err, "argv": argv[1:]}
    return {"ok": rc == 0, "stdout": out, "stderr": err.strip(), "argv": argv[1:]}


def run_report(p: dict) -> dict:
    argv = [REPORT, _safe_path(p.get("binary", "")), "--print"]
    if p.get("fast"):
        argv.append("--fast")
    rc, out, err, timed = _exec(argv, REPORT_TIMEOUT)
    if timed:
        return {"ok": False, "error": err, "argv": argv[1:]}
    if rc != 0:
        return {"ok": False, "error": (err or out).strip(), "argv": argv[1:]}
    return {"ok": True, "markdown": out, "argv": argv[1:]}


# --------------------------------------------------------------------------- #
# page
# --------------------------------------------------------------------------- #
PAGE = r"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTF Toolbox — rev workbench</title>
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
  .tabs { display: flex; gap: .4rem; margin: 0 0 1rem; flex-wrap: wrap; }
  .tabs button { text-transform: none; font-size: 13px; }
  .tabs button.on { background: rgb(var(--acc)); border-color: rgb(var(--acc)); color: rgb(var(--ink)); font-weight: 700; }
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
  pre { margin: .5rem 0 0; padding: .6rem; overflow: auto; max-height: 60vh; font-size: 12px;
    background: rgb(var(--ink)); border: 1px solid rgb(var(--edge)); border-radius: 3px;
    color: rgb(var(--fglite)); white-space: pre-wrap; word-break: break-word; }
  .err { color: rgb(var(--dangerlite)); }
  .muted { color: rgb(var(--dim)); }
  footer { margin-top: 1.5rem; color: rgb(var(--dim)); font-size: 11px;
    border-top: 1px solid rgb(var(--edge)); padding-top: .6rem; }
  footer b { color: rgb(var(--fglite)); }
  a { color: rgb(var(--info)); }
  code { word-break: break-word; }
</style>
</head>
<body>
<header>
  <h1><span class="prompt">$&nbsp;</span>rev <span class="muted">· workbench</span></h1>
  <p class="sub"><b>emulate</b> una funzione con Unicorn · <b>brute</b>-forza il primo argomento · <b>report</b> di primo passaggio (Ghidra, checksec, stringhe).</p>
  <p class="hint">Scegli (o <b>carica</b>) il <b>binario</b>, imposta l'<b>entry</b>, poi usa la scheda che ti serve. Solo codice <b>self-contained</b> (niente import/PLT); la sandbox resta senza rete.</p>
</header>

<main>
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

  <div class="tabs" role="tablist">
    <button id="tab-emulate" class="on" type="button" role="tab">emulate</button>
    <button id="tab-brute" type="button" role="tab">brute</button>
    <button id="tab-report" type="button" role="tab">report</button>
  </div>

  <section id="view-emulate">
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
      <button id="go-emulate" class="acc" type="button">run</button>
      <button id="copy" type="button" disabled>copia comando</button>
    </div>
  </section>

  <section id="view-brute" hidden>
    <fieldset>
      <legend>Sweep</legend>
      <div class="grid">
        <label>Range/lista del 1° argomento <span class="muted">START:END[:STEP] o 1,2,3</span>
          <input id="brute" type="text" placeholder="0:100000" autocomplete="off" spellcheck="false"></label>
        <label>rax atteso <span class="muted">--expected</span>
          <input id="expected" type="text" placeholder="0xdeadbeef" autocomplete="off" spellcheck="false"></label>
      </div>
      <div class="grid3">
        <label>memoria attesa <span class="muted">ADDR:LEN:HEX</span>
          <input id="expected_mem" type="text" placeholder="0x300000000000:1:01" autocomplete="off" spellcheck="false"></label>
        <label>buffer hex <span class="muted">(--argbuf)</span>
          <input id="b_argbuf" type="text" placeholder="00" autocomplete="off" spellcheck="false"></label>
        <label>altri interi <span class="muted">(--arg, dopo lo sweep)</span>
          <input id="b_args" type="text" placeholder="" autocomplete="off" spellcheck="false"></label>
      </div>
      <p class="muted">Serve <code>--expected</code> e/o una memoria attesa. Lo sweep va sul <b>primo</b> argomento intero.</p>
    </fieldset>
    <div class="toolbar">
      <button id="go-brute" class="acc" type="button">brute</button>
      <button id="copy-brute" type="button" disabled>copia comando</button>
    </div>
  </section>

  <section id="view-report" hidden>
    <fieldset>
      <legend>Report</legend>
      <p class="muted">Tipo, hash, sezioni/import, checksec, funzioni pericolose, packer, stringhe con candidati flag e decompilato Ghidra.</p>
      <label class="check"><input type="checkbox" id="fast" aria-label="salta il decompilato Ghidra"> salta il decompilato <span class="muted">--fast</span></label>
    </fieldset>
    <div class="toolbar">
      <button id="go-report" class="acc" type="button">genera report</button>
    </div>
  </section>

  <section id="out" aria-live="polite"><p class="muted">—</p></section>
</main>

<footer>
  Solo funzioni <b>self-contained</b>: le chiamate a import/PLT (libc, KERNEL32) fermano l'emulazione. x86-64; su PE i primi 4 argomenti. La sandbox resta <b>senza rete in uscita</b>.
</footer>

<script>
const $ = (id) => document.getElementById(id);
let lastCmd = '';

/* tabs */
function showTab(which){
  for (const t of ['emulate','brute','report']) {
    $('tab-'+t).classList.toggle('on', t === which);
    $('view-'+t).hidden = t !== which;
  }
}
for (const t of ['emulate','brute','report']) $('tab-'+t).addEventListener('click', () => showTab(t));

/* entry mode */
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

function entry(){
  return {
    binary: $('binary').value,
    mode: document.querySelector('input[name=mode]:checked').value,
    func: $('func').value, addr: $('addr').value, vaddr: $('vaddr').value,
  };
}
function post(url, body, btn){
  if(btn) btn.disabled = true;
  $('out').innerHTML = '<p class="muted">esecuzione…</p>';
  return fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json())
    .catch(e => ({ok:false, error:String(e)}))
    .finally(() => { if(btn) btn.disabled = false; });
}

$('go-emulate').addEventListener('click', async () => {
  const body = Object.assign(entry(), {
    args: $('args').value, argbuf: $('argbuf').value, mem: $('mem').value,
    steps: $('steps').value, base: $('base').value, raw: $('raw').checked,
  });
  renderEmulate(await post('api/run', body, $('go-emulate')));
});

$('go-brute').addEventListener('click', async () => {
  const body = Object.assign(entry(), {
    brute: $('brute').value, expected: $('expected').value, expected_mem: $('expected_mem').value,
    argbuf: $('b_argbuf').value, args: $('b_args').value, base: $('base').value,
  });
  renderText(await post('api/brute', body, $('go-brute')), 'brute');
});

$('go-report').addEventListener('click', async () => {
  const body = Object.assign(entry(), {fast: $('fast').checked});
  const r = await post('api/report', body, $('go-report'));
  lastCmd = r.argv ? 'rev-report ' + r.argv.map(esc).join(' ') : '';
  if(r.ok){ $('out').innerHTML = '<div class="card"><div class="head"><span class="rax">report</span></div>' +
    (r.argv ? '<code>' + lastCmd + '</code>' : '') + '<pre>' + esc(r.markdown) + '</pre></div>'; }
  else { $('out').innerHTML = '<div class="card err"><div class="head err">errore</div><p class="err">' + esc(r.error||'') + '</p></div>'; }
});

function cmdLine(argv){ return 'emulate ' + (argv || []).map(esc).join(' '); }

function renderEmulate(r){
  if(!r.ok){ lastCmd = r.argv ? cmdLine(r.argv) : ''; $('copy').disabled = !lastCmd; return error(r); }
  lastCmd = r.argv ? cmdLine(r.argv) : '';
  $('copy').disabled = !lastCmd;
  if(r.raw){ $('out').innerHTML = '<div class="card"><pre>' + esc(r.raw) + '</pre></div>'; return; }
  const d = r.result;
  let h = '<div class="card"><div class="head"><span class="rax">rax = 0x' + d.rax.toString(16) +
          '</span><span class="muted">(' + d.rax + ')</span></div>';
  h += '<p class="muted">format ' + esc(d.format) + ' · entry 0x' + d.entry.toString(16) +
       (d.load_base ? (' · base 0x' + d.load_base.toString(16)) : '') + '</p>';
  if(r.argv) h += '<code>' + cmdLine(r.argv) + '</code>';
  if(d.mem && d.mem.length){
    h += '<pre>';
    d.mem.forEach(m => { h += 'mem 0x' + m[0].toString(16) + '  ' + esc(m[1]) + '\n'; });
    h += '</pre>';
  }
  $('out').innerHTML = h + '</div>';
}

function renderText(r, which){
  if(r.argv) lastCmd = (which === 'brute' ? 'emulate ' : '') + r.argv.map(esc).join(' ');
  const copyBtn = which === 'brute' ? $('copy-brute') : $('copy');
  copyBtn.disabled = !lastCmd;
  if(!r.ok && !r.stdout){ return error(r); }
  let h = '<div class="card' + (r.ok ? '' : ' err') + '"><div class="head">' +
          '<span class="' + (r.ok ? 'rax' : 'err') + '">' + (r.ok ? 'match' : 'nessun match') + '</span></div>';
  if(r.argv) h += '<code>' + esc(lastCmd) + '</code>';
  if(r.stdout) h += '<pre>' + esc(r.stdout) + '</pre>';
  if(r.stderr) h += '<pre class="muted">' + esc(r.stderr) + '</pre>';
  $('out').innerHTML = h + '</div>';
}

function error(r){
  lastCmd = r.argv ? cmdLine(r.argv) : '';
  $('copy').disabled = !lastCmd;
  $('out').innerHTML = '<div class="card err"><div class="head"><span class="err">errore</span></div>' +
    '<p class="err">' + esc(r.error || 'esecuzione fallita') + '</p>' +
    (r.argv ? '<code>' + esc(lastCmd) + '</code>' : '') + '</div>';
}

function copyText(){ if(lastCmd) navigator.clipboard.writeText(lastCmd).catch(() => {}); }
$('copy').addEventListener('click', copyText);
$('copy-brute').addEventListener('click', copyText);

function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "rev-web"

    def log_message(self, fmt, *args):
        sys.stderr.write("rev-web %s\n" % (fmt % args))

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

    def _payload(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            raise ValueError("bad body size")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/upload":
            self._upload()
            return
        routes = {"/api/run": run_emulate, "/api/brute": run_brute, "/api/report": run_report}
        fn = routes.get(path)
        if fn is None:
            self._send(404, b"not found", "text/plain")
            return
        try:
            payload = self._payload()
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"ok": False, "error": "invalid JSON body"})
            return
        try:
            self._json(200, fn(payload))
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
    host = os.environ.get("REV_WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("REV_WEB_PORT", "8080"))
    if not os.path.isdir(WORK):
        print(f"rev-web: workdir {WORK} missing", file=sys.stderr)
    print(f"rev-web listening on {host}:{port} (workdir {WORK})", file=sys.stderr)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
