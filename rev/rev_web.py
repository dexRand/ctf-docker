#!/usr/bin/env python3
"""rev-web — small web workbench for the rev sandbox (report / emulate / brute).

One linear flow instead of a wall of fields: pick a binary, pick an action,
fill the few fields it needs, run, read the result. Secondary options stay
behind "opzioni avanzate".

  report   first-pass report (checksec/imports/strings/Ghidra) via rev-report
  emulate  run a self-contained x86-64 function with Unicorn and read rax
  brute    sweep the first argument until rax (or a memory window) matches

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
        if base == root and "reports" in dirs:      # generated output, not an input
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
        return {"ok": False, "error": "serve un valore atteso: rax o memoria"}
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
    --gap: 1.1rem;
    --font: ui-monospace, 'JetBrains Mono', 'Cascadia Code', 'Fira Code', Menlo, Consolas,
      'Liberation Mono', 'DejaVu Sans Mono', monospace;
  }
  * { box-sizing: border-box; }
  [hidden] { display: none !important; }
  html, body { margin: 0; min-height: 100%; }
  body {
    background: rgb(var(--ink)); color: rgb(var(--fg)); font-family: var(--font);
    font-size: 14px; line-height: 1.55; padding: 1.1rem 1.25rem 3rem;
  }
  body::before {
    content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 1; opacity: .3;
    background: repeating-linear-gradient(0deg, rgba(0,0,0,.14) 0 1px, transparent 1px 4px),
      radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,.4));
  }
  ::selection { background: rgb(var(--acc) / .3); color: rgb(var(--fgx)); }
  * { scrollbar-width: thin; scrollbar-color: rgb(var(--edge2)) transparent; }
  *::-webkit-scrollbar { width: 9px; height: 9px; }
  *::-webkit-scrollbar-thumb { background: rgb(var(--edge2)); }
  main, header, footer { position: relative; z-index: 2; max-width: 940px; margin: 0 auto; }

  header { margin-bottom: var(--gap); }
  h1 { font-size: 1rem; margin: 0 0 .15rem; color: rgb(var(--acc)); font-weight: 600; }
  h1 .prompt { opacity: .65; }
  p.sub { color: rgb(var(--dim)); margin: 0; font-size: 12px; }

  .bar { display: flex; gap: .6rem; align-items: stretch; }
  .bar select { flex: 1; min-width: 0; }
  label.file { display: inline-flex; align-items: center; }
  .vh { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden;
        clip: rect(0 0 0 0); white-space: nowrap; border: 0; }
  .filehint { color: rgb(var(--dim)); font-size: 12px; margin: .5rem 0 var(--gap); min-height: 1em; }

  input[type="text"], select {
    width: 100%; background: rgb(var(--ink)); color: rgb(var(--fgx));
    border: 1px solid rgb(var(--edge)); border-radius: 4px; padding: .5rem .6rem; font: inherit;
  }
  input[type="text"]:focus, select:focus { outline: none; border-color: rgb(var(--acc)); box-shadow: 0 0 0 1px rgb(var(--accdim)); }
  input::placeholder { color: rgb(var(--dim)); }

  button {
    font: inherit; font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
    border: 1px solid rgb(var(--edge)); background: rgb(var(--panel)); color: rgb(var(--fglite));
    border-radius: 4px; padding: .45rem .85rem; cursor: pointer; min-height: 32px;
  }
  button:hover { border-color: rgb(var(--acc)); color: rgb(var(--fgx)); background: rgb(var(--panel2)); }
  button.acc { background: rgb(var(--acc)); border-color: rgb(var(--acc)); color: rgb(var(--ink)); font-weight: 700; }
  button.acc:hover { color: rgb(var(--ink)); }
  button:disabled { opacity: .5; cursor: wait; }
  button:focus-visible, select:focus-visible, input:focus-visible, summary:focus-visible {
    outline: 2px solid rgb(var(--acc)); outline-offset: 1px;
  }

  .seg { display: inline-flex; border: 1px solid rgb(var(--edge)); border-radius: 4px; overflow: hidden; margin-bottom: var(--gap); }
  .seg button { border: 0; border-radius: 0; border-right: 1px solid rgb(var(--edge)); background: transparent; text-transform: none; font-size: 13px; padding: .5rem 1.1rem; }
  .seg button:last-child { border-right: 0; }
  .seg button.on { background: rgb(var(--acc)); color: rgb(var(--ink)); font-weight: 700; }

  .fields { display: grid; gap: var(--gap); margin-bottom: var(--gap); }
  label.f { display: block; color: rgb(var(--fglite)); font-size: 12px; }
  label.f > span { color: rgb(var(--dim)); }
  label.f input { margin-top: .35rem; }
  .two { display: grid; grid-template-columns: 1fr 1fr; gap: .9rem; }
  .three { display: grid; grid-template-columns: repeat(3, 1fr); gap: .9rem; }
  @media (max-width: 640px) { .two, .three { grid-template-columns: 1fr; } }

  details { border-top: 1px solid rgb(var(--edge)); padding-top: .7rem; }
  summary { color: rgb(var(--dim)); font-size: 12px; cursor: pointer; list-style: none; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: "+ "; color: rgb(var(--acc)); }
  details[open] summary::before { content: "– "; }
  details .three { margin-top: .9rem; }

  .go { display: flex; gap: .6rem; align-items: center; margin-bottom: var(--gap); }
  .check { display: flex; align-items: center; gap: .5rem; color: rgb(var(--fglite)); font-size: 13px; }
  .check input { width: auto; }
  #modes { display: flex; flex-wrap: wrap; gap: 1rem; margin: .5rem 0 0; font-size: 13px; }

  .res { border: 1px solid rgb(var(--edge)); border-radius: 4px; background: rgb(var(--panel)); padding: .8rem .9rem; }
  .res.bad { border-color: rgb(var(--danger) / .55); }
  .res .lead { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; }
  .rax { color: rgb(var(--acc)); font-weight: 700; font-size: 1.2rem; }
  .res.bad .rax { color: rgb(var(--dangerlite)); }
  .res .cmd { display: block; margin-top: .6rem; color: rgb(var(--fglite)); font-size: 12px;
    background: rgb(var(--ink)); border: 1px solid rgb(var(--edge)); border-radius: 3px; padding: .4rem .5rem;
    overflow-x: auto; white-space: pre; }
  pre { margin: .6rem 0 0; padding: .6rem; overflow: auto; max-height: 62vh; font-size: 12px;
    background: rgb(var(--ink)); border: 1px solid rgb(var(--edge)); border-radius: 3px;
    color: rgb(var(--fglite)); white-space: pre-wrap; word-break: break-word; }
  .empty { border: 1px dashed rgb(var(--edge)); border-radius: 4px; padding: 1.4rem; text-align: center; color: rgb(var(--dim)); }
  .muted { color: rgb(var(--dim)); }
  footer { margin-top: 1.6rem; color: rgb(var(--dim)); font-size: 11px; }
  code { color: rgb(var(--acc)); word-break: break-word; }
</style>
</head>
<body>
<header>
  <h1><span class="prompt">$&nbsp;</span>rev <span class="muted">· workbench</span></h1>
  <p class="sub">Analizza, emula o brute-forza un binario — dentro la sandbox rev.</p>
</header>

<main>
  <div class="bar">
    <select id="binary" aria-label="binario dal workdir"></select>
    <button type="button" id="pick">carica</button>
    <input type="file" id="upload" class="vh" tabindex="-1" aria-hidden="true">
  </div>
  <div class="filehint" id="filehint">…</div>

  <div class="seg" role="tablist" aria-label="azione">
    <button id="act-report" type="button" role="tab">report</button>
    <button id="act-emulate" class="on" type="button" role="tab">emulate</button>
    <button id="act-brute" type="button" role="tab">brute</button>
  </div>

  <div id="entry" class="fields">
    <label class="f">Entry
      <span class="muted" id="modes">
        <label class="check"><input type="radio" name="mode" value="func" checked aria-label="simbolo funzione"> simbolo</label>
        <label class="check"><input type="radio" name="mode" value="addr" aria-label="indirizzo assoluto"> indirizzo</label>
        <label class="check"><input type="radio" name="mode" value="vaddr" aria-label="vaddr relativo"> vaddr</label>
        <label class="check"><input type="radio" name="mode" value="auto" aria-label="entrypoint"> entrypoint</label>
      </span>
      <input id="func" type="text" placeholder="secret_hash" autocomplete="off" spellcheck="false" aria-label="simbolo funzione">
      <input id="addr" type="text" placeholder="0x140001480" autocomplete="off" spellcheck="false" aria-label="indirizzo assoluto" hidden>
      <input id="vaddr" type="text" placeholder="0x1149" autocomplete="off" spellcheck="false" aria-label="indirizzo virtuale relativo" hidden>
    </label>
  </div>

  <div id="p-emulate" class="fields">
    <div class="two">
      <label class="f">Argomenti interi <span>(rdi,rsi,… · rcx,rdx,… su PE)</span>
        <input id="args" type="text" placeholder="5, 2" autocomplete="off" spellcheck="false"></label>
      <label class="f">Buffer hex <span>(--argbuf)</span>
        <input id="argbuf" type="text" placeholder="41424344" autocomplete="off" spellcheck="false"></label>
    </div>
    <details>
      <summary>opzioni avanzate</summary>
      <div class="three">
        <label class="f">steps<input id="steps" type="text" value="1000000" autocomplete="off" spellcheck="false"></label>
        <label class="f">load base <span>(PIE/raw)</span><input id="base" type="text" placeholder="auto" autocomplete="off" spellcheck="false"></label>
        <label class="f">dump memoria <span>ADDR:LEN</span><input id="mem" type="text" placeholder="0x2000:16" autocomplete="off" spellcheck="false"></label>
      </div>
      <label class="check" style="margin-top:.8rem"><input type="checkbox" id="raw" aria-label="tratta il file come blob di codice"> blob di codice raw <span class="muted">--raw</span></label>
    </details>
  </div>

  <div id="p-brute" class="fields" hidden>
    <div class="two">
      <label class="f">Range del 1° argomento <span>START:END[:STEP] o 1,2,3</span>
        <input id="brute" type="text" placeholder="0:100000" autocomplete="off" spellcheck="false"></label>
      <label class="f">rax atteso <span>--expected</span>
        <input id="expected" type="text" placeholder="0xdeadbeef" autocomplete="off" spellcheck="false"></label>
    </div>
    <div class="two">
      <label class="f">memoria attesa <span>ADDR:LEN:HEX</span>
        <input id="expected_mem" type="text" placeholder="0x300000000000:1:01" autocomplete="off" spellcheck="false"></label>
      <label class="f">buffer hex <span>(--argbuf)</span>
        <input id="b_argbuf" type="text" placeholder="00" autocomplete="off" spellcheck="false"></label>
    </div>
    <details>
      <summary>opzioni avanzate</summary>
      <div class="two">
        <label class="f">steps<input id="b_steps" type="text" value="1000000" autocomplete="off" spellcheck="false"></label>
        <label class="f">load base <span>(PIE/raw)</span><input id="b_base" type="text" placeholder="auto" autocomplete="off" spellcheck="false"></label>
      </div>
    </details>
  </div>

  <div id="p-report" class="fields" hidden>
    <label class="check"><input type="checkbox" id="fast" aria-label="salta il decompilato Ghidra"> salta il decompilato Ghidra <span class="muted">--fast</span></label>
  </div>

  <div class="go">
    <button id="go" class="acc" type="button">esegui</button>
    <button id="copy" type="button" disabled>copia comando</button>
  </div>

  <section id="out" aria-live="polite"></section>
</main>

<footer>
  Solo codice <b>self-contained</b>: le chiamate a import/PLT fermano l'emulazione. Sandbox senza rete in uscita.
</footer>

<script>
const $ = (id) => document.getElementById(id);
let act = 'emulate';
let lastCmd = '';
const LABEL = { report: 'analizza', emulate: 'esegui', brute: 'brute' };

function setAct(next){
  act = next;
  for (const a of ['report','emulate','brute']) $('act-'+a).classList.toggle('on', a === next);
  $('entry').hidden = next === 'report';
  $('p-emulate').hidden = next !== 'emulate';
  $('p-brute').hidden = next !== 'brute';
  $('p-report').hidden = next !== 'report';
  $('go').textContent = LABEL[next];
  $('copy').hidden = next === 'report';
}
for (const a of ['report','emulate','brute']) $('act-'+a).addEventListener('click', () => setAct(a));

function modeUI(){
  const m = document.querySelector('input[name=mode]:checked').value;
  $('func').hidden  = m !== 'func';
  $('addr').hidden  = m !== 'addr';
  $('vaddr').hidden = m !== 'vaddr';
}
document.querySelectorAll('input[name=mode]').forEach(r => r.addEventListener('change', modeUI));
modeUI();

async function loadFiles(){
  const sel = $('binary'); const cur = sel.value;
  try{
    const files = await (await fetch('api/files', {cache:'no-cache'})).json();
    sel.innerHTML = '';
    files.forEach(f => { const o = document.createElement('option'); o.value = f; o.textContent = f; sel.appendChild(o); });
    if(files.includes(cur)) sel.value = cur;
    $('filehint').textContent = files.length ? files.length + ' file in ./data/rev' : 'nessun binario — caricane uno';
    sel.disabled = !files.length;
  }catch(e){ $('filehint').textContent = 'impossibile elencare i file: ' + e; }
}
loadFiles();

$('pick').addEventListener('click', () => $('upload').click());
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
  return { binary: $('binary').value, mode: document.querySelector('input[name=mode]:checked').value,
           func: $('func').value, addr: $('addr').value, vaddr: $('vaddr').value };
}
function post(url, body, btn){
  btn.disabled = true;
  $('out').innerHTML = '<div class="empty">esecuzione…</div>';
  return fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json()).catch(e => ({ok:false, error:String(e)})).finally(() => { btn.disabled = false; });
}

$('go').addEventListener('click', async () => {
  if(act === 'emulate'){
    renderEmulate(await post('api/run', Object.assign(entry(), {
      args: $('args').value, argbuf: $('argbuf').value, mem: $('mem').value,
      steps: $('steps').value, base: $('base').value, raw: $('raw').checked }), $('go')));
  } else if(act === 'brute'){
    renderBrute(await post('api/brute', Object.assign(entry(), {
      brute: $('brute').value, expected: $('expected').value, expected_mem: $('expected_mem').value,
      argbuf: $('b_argbuf').value, steps: $('b_steps').value, base: $('b_base').value }), $('go')));
  } else {
    renderReport(await post('api/report', Object.assign(entry(), {fast: $('fast').checked}), $('go')));
  }
});

function cmd(argv, tool){ return tool + ' ' + (argv || []).map(esc).join(' '); }
function setCmd(argv, tool){
  lastCmd = argv ? cmd(argv, tool) : '';
  $('copy').disabled = !lastCmd;
}
function show(html){ $('out').innerHTML = html; }
function errCard(r, tool){
  setCmd(r.argv, tool);
  show('<div class="res bad"><div class="lead"><span class="rax">errore</span></div>' +
    '<p>' + esc(r.error || 'esecuzione fallita') + '</p>' +
    (lastCmd ? '<code class="cmd">' + esc(lastCmd) + '</code>' : '') + '</div>');
}

function renderEmulate(r){
  if(!r.ok || !r.result){ if(r.raw){ setCmd(r.argv,'emulate'); return show('<div class="res"><pre>' + esc(r.raw) + '</pre></div>'); } return errCard(r, 'emulate'); }
  setCmd(r.argv, 'emulate');
  const d = r.result;
  let h = '<div class="res"><div class="lead"><span class="rax">rax = 0x' + d.rax.toString(16) + '</span>' +
          '<span class="muted">(' + d.rax + ')</span></div>' +
          '<p class="muted" style="margin:.3rem 0 0">' + esc(d.format) + ' · entry 0x' + d.entry.toString(16) +
          (d.load_base ? ' · base 0x' + d.load_base.toString(16) : '') + '</p>';
  if(lastCmd) h += '<code class="cmd">' + esc(lastCmd) + '</code>';
  if(d.mem && d.mem.length){ h += '<pre>'; d.mem.forEach(m => { h += 'mem 0x' + m[0].toString(16) + '  ' + esc(m[1]) + '\n'; }); h += '</pre>'; }
  show(h + '</div>');
}

function renderBrute(r){
  setCmd(r.argv, 'emulate');
  if(!r.ok && !r.stdout) return errCard(r, 'emulate');
  let h = '<div class="res' + (r.ok ? '' : ' bad') + '"><div class="lead"><span class="rax">' +
          (r.ok ? 'match' : 'nessun match') + '</span></div>';
  if(lastCmd) h += '<code class="cmd">' + esc(lastCmd) + '</code>';
  if(r.stdout) h += '<pre>' + esc(r.stdout) + '</pre>';
  if(r.stderr) h += '<pre class="muted">' + esc(r.stderr) + '</pre>';
  show(h + '</div>');
}

function renderReport(r){
  setCmd(r.argv, 'rev-report');
  if(!r.ok) return errCard(r, 'rev-report');
  show('<div class="res"><div class="lead"><span class="rax">report</span></div>' +
    (lastCmd ? '<code class="cmd">' + esc(lastCmd) + '</code>' : '') +
    '<pre>' + esc(r.markdown) + '</pre></div>');
}

$('copy').addEventListener('click', () => { if(lastCmd) navigator.clipboard.writeText(lastCmd).catch(() => {}); });
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
