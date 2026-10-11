#!/usr/bin/env python3
"""emulate-web — small web GUI for the `emulate` helper inside the rev sandbox.

Serves a single page: pick a binary from the mounted workdir, choose how to
reach the routine (symbol / absolute addr / objdump vaddr), pass integer
arguments and/or hex buffers, and see `rax` plus any memory dump. The page talks
to two JSON endpoints:

  GET  /api/files   -> list the files found under the workdir
  POST /api/run     -> run `emulate ... --json` and return its structured result

It runs *inside* the isolated `rev` container (no network egress); the host only
reaches it through the localhost socat proxy. Stdlib only, so the image needs no
extra server dependency.
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
RUN_TIMEOUT = int(os.environ.get("EMULATE_TIMEOUT", "30"))
MAX_STEPS = 50_000_000

_NUM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+)$")
_HEX = re.compile(r"^[0-9a-fA-F\s]*$")
_MEM = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+):-?(0x[0-9a-fA-F]+|\d+)$")


def list_files(root: str) -> list[str]:
    out: list[str] = []
    for base, dirs, files in os.walk(root):
        depth = base[len(root):].count(os.sep)
        if depth >= 4:
            dirs[:] = []
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), root)
            out.append(rel)
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
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>emulate · rev sandbox</title>
<link rel="icon" href="data:,">
<style>
  :root{
    --ink:12 14 16; --panel:20 23 26; --panel2:26 30 34; --edge:38 43 49;
    --acc:69 224 140; --accdim:20 51 37; --warn:245 197 66; --danger:255 97 102;
    --dim:102 113 124; --fg:215 221 227;
    --font:ui-monospace,'JetBrains Mono','Cascadia Code',Menlo,Consolas,monospace;
  }
  *{box-sizing:border-box}
  html,body{margin:0;background:rgb(var(--ink));color:rgb(var(--fg));font-family:var(--font);font-size:14px}
  body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:9999;opacity:.28;
    background:repeating-linear-gradient(0deg,rgba(0,0,0,.14) 0 1px,transparent 1px 4px),
               radial-gradient(ellipse at center,transparent 60%,rgba(0,0,0,.4))}
  header{padding:18px 20px 8px;max-width:1000px;margin:0 auto}
  h1{color:rgb(var(--acc));font-size:18px;margin:0 0 4px}
  .sub{color:rgb(var(--dim));font-size:12px}
  main{max-width:1000px;margin:0 auto;padding:10px 20px 60px}
  fieldset{border:1px solid rgb(var(--edge));border-radius:8px;background:rgb(var(--panel));padding:14px 16px;margin:0 0 14px}
  legend{color:rgb(var(--acc));padding:0 6px;font-size:12px;letter-spacing:.05em;text-transform:uppercase}
  label,.cap{display:block;color:rgb(var(--dim));font-size:12px;margin:10px 0 4px}
  input,select{width:100%;background:rgb(var(--panel2));color:rgb(var(--fg));border:1px solid rgb(var(--edge));
    border-radius:6px;padding:8px 10px;font:inherit}
  input:focus,select:focus{outline:none;border-color:rgb(var(--acc));box-shadow:0 0 0 1px rgb(var(--accdim))}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  .row3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
  .modes{display:flex;gap:14px;flex-wrap:wrap;margin-top:6px}
  .modes label{display:flex;gap:6px;align-items:center;margin:0;color:rgb(var(--fg));font-size:13px}
  .modes input{width:auto}
  button{background:rgb(var(--acc));color:rgb(var(--ink));border:0;border-radius:6px;padding:9px 16px;
    font:inherit;font-weight:700;cursor:pointer}
  button:hover{filter:brightness(1.08)}
  button:disabled{opacity:.5;cursor:wait}
  pre{background:rgb(var(--panel2));border:1px solid rgb(var(--edge));border-radius:8px;padding:12px;
    overflow:auto;white-space:pre-wrap;word-break:break-word;margin:0}
  .rax{font-size:22px;color:rgb(var(--acc));font-weight:700}
  .muted{color:rgb(var(--dim));font-size:12px}
  .err{color:rgb(var(--danger))}
  .k{color:rgb(var(--dim))}
  .hint{color:rgb(var(--dim));font-size:12px;line-height:1.5}
  code{color:rgb(var(--acc))}
</style>
</head>
<body>
<header>
  <h1>emulate <span class="muted">· rev sandbox</span></h1>
  <div class="sub">Run a self-contained x86-64 function with Unicorn and read <code>rax</code>.</div>
</header>
<main>
  <form id="f">
    <fieldset>
      <legend>target</legend>
      <label for="binary">binary (from the workdir — mount files in ./data/rev)</label>
      <select id="binary" required aria-label="binary from the workdir"></select>
      <div class="hint" id="filehint">loading…</div>

      <div class="cap">entry</div>
      <div class="modes" role="group" aria-label="how to reach the routine">
        <label><input type="radio" name="mode" value="func" checked> ELF symbol <span class="muted">--func</span></label>
        <label><input type="radio" name="mode" value="addr"> absolute <span class="muted">--addr</span></label>
        <label><input type="radio" name="mode" value="vaddr"> vaddr <span class="muted">--vaddr</span></label>
        <label><input type="radio" name="mode" value="auto"> entrypoint</label>
      </div>
      <input id="func" placeholder="secret_hash" autocomplete="off" aria-label="function symbol">
      <input id="addr" placeholder="0x140001480" autocomplete="off" aria-label="absolute address" style="display:none">
      <input id="vaddr" placeholder="0x1149" autocomplete="off" aria-label="relative virtual address" style="display:none">
    </fieldset>

    <fieldset>
      <legend>arguments</legend>
      <div class="row">
        <div>
          <label for="args">integers (rdi,rsi,… / rcx,rdx,… on PE) — comma separated</label>
          <input id="args" placeholder="5, 2" autocomplete="off">
        </div>
        <div>
          <label for="argbuf">hex buffers (<code>--argbuf</code>, pointer args) — comma separated</label>
          <input id="argbuf" placeholder="41424344, aabb" autocomplete="off">
        </div>
      </div>
      <div class="row3">
        <div><label for="steps">steps</label><input id="steps" value="1000000" autocomplete="off"></div>
        <div><label for="base">load base (PIE/raw)</label><input id="base" placeholder="auto" autocomplete="off"></div>
        <div><label for="mem">mem dumps ADDR:LEN</label><input id="mem" placeholder="0x2000:16" autocomplete="off"></div>
      </div>
      <div class="modes"><label><input type="checkbox" id="raw" aria-label="treat the file as a raw code blob"> raw code blob (<code>--raw</code>)</label></div>
    </fieldset>

    <button type="submit" id="go">run</button>
  </form>

  <fieldset style="margin-top:14px">
    <legend>result</legend>
    <div id="out" class="muted">—</div>
  </fieldset>
</main>
<script>
const $ = id => document.getElementById(id);
function modeUI(){
  const m = document.querySelector('input[name=mode]:checked').value;
  $('func').style.display  = m==='func'  ? 'block':'none';
  $('addr').style.display  = m==='addr'  ? 'block':'none';
  $('vaddr').style.display = m==='vaddr' ? 'block':'none';
}
document.querySelectorAll('input[name=mode]').forEach(r=>r.addEventListener('change',modeUI));
modeUI();

async function loadFiles(){
  try{
    const files = await (await fetch('api/files')).json();
    const sel = $('binary'); sel.innerHTML='';
    if(!files.length){ $('filehint').textContent='no files under the workdir — add some in ./data/rev'; return; }
    files.forEach(f=>{ const o=document.createElement('option'); o.value=f; o.textContent=f; sel.appendChild(o); });
    $('filehint').textContent = files.length + ' file(s) in the workdir';
  }catch(e){ $('filehint').textContent = 'could not list files: '+e; }
}
loadFiles();

$('f').addEventListener('submit', async ev=>{
  ev.preventDefault();
  const body = {
    binary: $('binary').value,
    mode: document.querySelector('input[name=mode]:checked').value,
    func: $('func').value, addr: $('addr').value, vaddr: $('vaddr').value,
    args: $('args').value, argbuf: $('argbuf').value, mem: $('mem').value,
    steps: $('steps').value, base: $('base').value, raw: $('raw').checked,
  };
  $('go').disabled = true;
  $('out').className='muted'; $('out').textContent='running…';
  try{
    const r = await (await fetch('api/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)})).json();
    render(r);
  }catch(e){ $('out').className='err'; $('out').textContent='request failed: '+e; }
  finally{ $('go').disabled=false; }
});

function render(r){
  const out=$('out');
  if(!r.ok){ out.className='err'; out.innerHTML='<b>error</b><br>'+esc(r.error||'failed')+
    (r.argv?'<div class="muted" style="margin-top:8px">emulate '+r.argv.map(esc).join(' ')+'</div>':''); return; }
  out.className='';
  if(r.raw){ out.innerHTML='<pre>'+esc(r.raw)+'</pre>'; return; }
  const d=r.result;
  let h='<div class="rax">rax = 0x'+d.rax.toString(16)+'  <span class="muted">('+d.rax+')</span></div>';
  h+='<div class="muted" style="margin:8px 0 12px">format '+esc(d.format)+
     ' · entry 0x'+d.entry.toString(16)+(d.load_base?(' · base 0x'+d.load_base.toString(16)):'')+'</div>';
  h+='<div class="hint">emulate '+ (r.argv||[]).map(esc).join(' ') +'</div>';
  if(d.mem && d.mem.length){
    h+='<pre style="margin-top:10px">';
    d.mem.forEach(m=>{ h+= 'mem 0x'+m[0].toString(16)+'  '+esc(m[1])+'\n'; });
    h+='</pre>';
  }
  out.innerHTML=h;
}
function esc(s){ return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
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
        if urlparse(self.path).path != "/api/run":
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
