#!/usr/bin/env python3
"""Web GUI for CTF Triage.

Modes:
  * auto  - run everything, try every wordlist smallest -> largest
  * check - scan first, then show the file tree + locked items and let the
            user choose, per item, which wordlist to use (or skip)

Single-process state: run with one gunicorn worker.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, Response, abort, jsonify, request, send_file

import triage

app = Flask(__name__)
RUNS: dict[str, "Run"] = {}
RUNS_LOCK = threading.Lock()
ACTIVE = {"id": None}
WEB_ROOT = Path("/data/triage-web")


class Run:
    def __init__(self, rid: str, mode: str):
        self.id = rid
        self.mode = mode
        self.targets: list[str] = []
        self.status = "running"  # running | waiting | done | error
        self.log: list[str] = []
        self.lock = threading.Lock()
        self.event = threading.Event()
        self.answers: dict | None = None
        self.pending: dict | None = None
        self.result: dict | None = None
        self.error: str | None = None
        self.work = WEB_ROOT / rid
        self.created = time.time()

    def add_log(self, line: str) -> None:
        with self.lock:
            self.log.append(line)
            if len(self.log) > 5000:
                del self.log[:2500]

    def snapshot(self) -> dict:
        with self.lock:
            data = {
                "id": self.id, "mode": self.mode, "status": self.status,
                "log": self.log[-500:], "pending": self.pending, "error": self.error,
                "work": str(self.work),
            }
        if self.result:
            data.update({
                "flags": self.result.get("flags", []),
                "passwords": self.result.get("passwords", []),
                "extracted": self.result.get("extracted", []),
                "count": self.result.get("count"),
                "elapsed": self.result.get("elapsed"),
                "warnings": self.result.get("warnings", []),
            })
        return data


def web_asker(run: Run):
    def asker(entries, candidates):
        tree = [f["path"] for f in list(triage.PER_FILE)]
        with run.lock:
            run.pending = {
                "items": entries,
                "tree": tree,
                "wordlists": [
                    {"name": w.name, "size": w.stat().st_size, "lines": triage.line_count(w)}
                    for w in candidates
                ],
            }
            run.answers = None
            run.event.clear()
            run.status = "waiting"
        run.event.wait()
        with run.lock:
            ans = run.answers or {}
            run.pending = None
            run.status = "running"
        decisions: dict[int, list] = {}
        for key, val in ans.items():
            try:
                idx = int(key)
            except (TypeError, ValueError):
                continue
            if val in (None, "", "skip"):
                continue
            if val == "all":
                decisions[idx] = list(candidates)
            else:
                try:
                    decisions[idx] = [candidates[int(val) - 1]]
                except (ValueError, IndexError):
                    pass
        return decisions
    return asker


def auto_asker(entries, candidates):
    return {e["index"]: list(candidates) for e in entries}


def worker(run: Run) -> None:
    triage.set_logger(run.add_log)
    try:
        asker = web_asker(run) if run.mode == "check" else auto_asker
        run.result = triage.execute(
            run.targets, run.work, crack=True, jobs=min(4, os.cpu_count() or 2),
            depth=3, asker=asker, make_latest=False,
        )
        with run.lock:
            run.status = "done"
    except Exception as exc:  # pragma: no cover - surfaced in the UI
        run.error = str(exc)
        run.add_log(f"[x] errore: {exc}")
        with run.lock:
            run.status = "error"
    finally:
        with RUNS_LOCK:
            if ACTIVE["id"] == run.id:
                ACTIVE["id"] = None
        run.event.set()  # release a pending asker if any


@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.post("/api/run")
def api_run():
    mode = request.form.get("mode", "check")
    if mode not in ("auto", "check"):
        mode = "check"
    files = request.files.getlist("files")
    if not files:
        return jsonify(error="nessun file caricato"), 400
    with RUNS_LOCK:
        if ACTIVE["id"]:
            return jsonify(error="una run è già in corso"), 409
        rid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        ACTIVE["id"] = rid
    run = Run(rid, mode)
    up = Path("/tmp/webup") / rid
    up.mkdir(parents=True, exist_ok=True)
    for f in files:
        name = os.path.basename(f.filename or "file")
        dest = up / name
        f.save(dest)
        run.targets.append(str(dest))
    with RUNS_LOCK:
        RUNS[rid] = run
    threading.Thread(target=worker, args=(run,), daemon=True).start()
    return jsonify(id=rid)


@app.get("/api/run/<rid>")
def api_status(rid):
    run = RUNS.get(rid)
    if not run:
        abort(404)
    return jsonify(run.snapshot())


@app.post("/api/run/<rid>/answer")
def api_answer(rid):
    run = RUNS.get(rid)
    if not run:
        abort(404)
    data = request.get_json(force=True, silent=True) or {}
    with run.lock:
        run.answers = {str(k): v for k, v in (data.get("answers") or {}).items()}
    run.event.set()
    return jsonify(ok=True)


@app.get("/api/run/<rid>/report")
def api_report(rid):
    run = RUNS.get(rid)
    if not run:
        abort(404)
    p = run.work / "report.md"
    if not p.exists():
        abort(404)
    return Response(p.read_text(errors="replace"), mimetype="text/markdown")


@app.get("/api/run/<rid>/file")
def api_file(rid):
    run = RUNS.get(rid)
    if not run:
        abort(404)
    target = (run.work / request.args.get("path", "")).resolve()
    if not str(target).startswith(str(run.work.resolve())) or not target.is_file():
        abort(404)
    return send_file(target, as_attachment=request.args.get("dl") == "1")


@app.get("/api/runs")
def api_runs():
    with RUNS_LOCK:
        out = [{"id": r.id, "mode": r.mode, "status": r.status, "created": r.created}
               for r in RUNS.values()]
    return jsonify(sorted(out, key=lambda x: x["created"], reverse=True))


INDEX_HTML = r"""<!doctype html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTF Triage</title>
<style>
  :root{--bg:#0f172a;--card:#1e293b;--fg:#e2e8f0;--mut:#94a3b8;--acc:#6e56cf;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444}
  *{box-sizing:border-box} body{margin:0;font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
  header{padding:18px 24px;border-bottom:1px solid #334155;display:flex;align-items:baseline;gap:12px}
  h1{font-size:20px;margin:0} h2{font-size:15px;margin:0 0 8px}
  main{padding:18px 24px;max-width:1100px;margin:0 auto}
  .panel{background:var(--card);border:1px solid #334155;border-radius:12px;padding:16px;margin-bottom:16px}
  label{display:inline-flex;align-items:center;gap:6px;margin-right:18px}
  input[type=file]{color:var(--fg)}
  button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 16px;cursor:pointer;font-weight:600}
  button.secondary{background:#334155} button:disabled{opacity:.5;cursor:not-allowed}
  .row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
  a{color:#a5b4fc}
  pre.log{background:#0b1220;border:1px solid #334155;border-radius:10px;padding:12px;max-height:380px;overflow:auto;font:12px/1.45 ui-monospace,Menlo,monospace;white-space:pre-wrap}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #334155;vertical-align:top}
  select{background:#0b1220;color:var(--fg);border:1px solid #334155;border-radius:6px;padding:4px 6px}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;background:#334155}
  .flag{color:#86efac;font-family:ui-monospace,monospace} .pw{color:#fca5a5;font-family:ui-monospace,monospace}
  .mut{color:var(--mut)} .tree{max-height:160px;overflow:auto;font:12px ui-monospace,monospace;color:var(--mut)}
  .status-running{color:var(--warn)} .status-done{color:var(--ok)} .status-waiting{color:#60a5fa} .status-error{color:var(--err)}
</style>
</head>
<body>
<header>
  <h1>🔬 CTF Triage</h1>
  <span class="mut">estrazione ricorsiva · cracking wordlist · flag hunt</span>
</header>
<main>
  <div class="panel">
    <div class="row">
      <label><input type="radio" name="mode" value="check" checked> <b>Check</b> <span class="mut">(chiede su cosa concentrarsi)</span></label>
      <label><input type="radio" name="mode" value="auto"> <b>Auto</b> <span class="mut">(prova tutto lui)</span></label>
    </div>
    <div class="row" style="margin-top:12px">
      <input type="file" id="files" multiple>
      <button id="start">Analizza</button>
      <span id="hint" class="mut"></span>
    </div>
  </div>

  <div class="panel" id="pendingPanel" style="display:none">
    <h2>🔒 Elementi bloccati — scegli cosa attaccare e con quale wordlist</h2>
    <div class="mut" style="margin-bottom:6px">Albero dei file analizzati:</div>
    <div class="tree" id="tree"></div>
    <table id="items"><thead><tr><th>File</th><th>Tipo</th><th>Wordlist</th></tr></thead><tbody></tbody></table>
    <div style="margin-top:12px"><button id="confirm">Conferma e prosegui</button></div>
  </div>

  <div class="panel">
    <h2>Log <span id="status" class="badge status-running">running</span></h2>
    <pre class="log" id="log"></pre>
  </div>

  <div class="panel" id="results" style="display:none">
    <h2>Risultati</h2>
    <div id="summary" class="mut"></div>
    <h2 style="margin-top:14px">🚩 Flag</h2><div id="flags"></div>
    <h2 style="margin-top:14px">🔑 Password</h2><div id="passwords"></div>
    <h2 style="margin-top:14px">📦 File estratti</h2><div id="extracted" class="tree" style="max-height:300px"></div>
    <div style="margin-top:14px">
      <a id="reportLink" href="#" target="_blank">Apri report.md</a>
      &nbsp;·&nbsp; <a href="http://localhost:19012" target="_blank">FileBrowser (tutti i report)</a>
    </div>
  </div>
</main>
<script>
let runId = null, timer = null, currentPending = null;

function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}

document.getElementById('start').onclick = async () => {
  const files = document.getElementById('files').files;
  if(!files.length){ document.getElementById('hint').textContent = "Seleziona almeno un file."; return; }
  const mode = document.querySelector('input[name=mode]:checked').value;
  const fd = new FormData();
  fd.append('mode', mode);
  for(const f of files) fd.append('files', f);
  document.getElementById('start').disabled = true;
  document.getElementById('hint').textContent = "Caricamento…";
  const r = await fetch('/api/run', {method:'POST', body: fd});
  const j = await r.json();
  if(!r.ok){ document.getElementById('hint').textContent = j.error || 'errore'; document.getElementById('start').disabled=false; return; }
  runId = j.id; currentPending = null;
  document.getElementById('pendingPanel').style.display='none';
  document.getElementById('results').style.display='none';
  document.getElementById('hint').textContent = '';
  document.getElementById('reportLink').href = '/api/run/'+runId+'/report';
  timer = setInterval(poll, 1000); poll();
};

async function poll(){
  if(!runId) return;
  const r = await fetch('/api/run/'+runId);
  if(!r.ok) return;
  const d = await r.json();
  document.getElementById('log').textContent = (d.log||[]).join('\n');
  document.getElementById('log').scrollTop = document.getElementById('log').scrollHeight;
  const st = document.getElementById('status');
  st.textContent = d.status; st.className = 'badge status-'+d.status;
  if(d.pending && d.status==='waiting'){
    renderPending(d.pending);
  }
  if(d.status==='done'){
    clearInterval(timer); timer=null;
    document.getElementById('start').disabled=false;
    document.getElementById('pendingPanel').style.display='none';
    renderResults(d);
  }
  if(d.status==='error'){ clearInterval(timer); timer=null; document.getElementById('start').disabled=false; }
}

function renderPending(p){
  document.getElementById('pendingPanel').style.display='block';
  currentPending = p;
  document.getElementById('tree').textContent = (p.tree||[]).join('\n') || '(nessuno)';
  const tb = document.querySelector('#items tbody'); tb.innerHTML='';
  const opts = ['<option value="skip">— salta —</option>','<option value="all">tutte (piccola→grande)</option>']
    .concat(p.wordlists.map((w,i)=>`<option value="${i+1}">${esc(w.name)} (${w.lines} voci, ${w.size}B)</option>`)).join('');
  for(const it of p.items){
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(it.rel)}</td><td><span class="badge">${esc(it.kind)}</span></td>
      <td><select data-index="${it.index}">${opts}</select></td>`;
    tb.appendChild(tr);
  }
}

document.getElementById('confirm').onclick = async () => {
  const answers = {};
  document.querySelectorAll('#items select').forEach(s => answers[s.dataset.index] = s.value);
  document.getElementById('confirm').disabled = true;
  await fetch('/api/run/'+runId+'/answer', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({answers})});
  document.getElementById('confirm').disabled = false;
  document.getElementById('pendingPanel').style.display='none';
};

function renderResults(d){
  document.getElementById('results').style.display='block';
  document.getElementById('summary').textContent = `${(d.flags||[]).length} flag · ${(d.passwords||[]).length} password · ${(d.extracted||[]).length} file estratti · ${d.count||0} analizzati · ${d.elapsed||0}s`;
  document.getElementById('flags').innerHTML = (d.flags||[]).map(f=>`<div>🚩 <span class="flag">${esc(f.value)}</span> <span class="mut">— ${esc((f.where||[]).join(', '))}</span></div>`).join('') || '<span class="mut">nessuna</span>';
  document.getElementById('passwords').innerHTML = (d.passwords||[]).map(p=>`<div>🔑 <span class="pw">${esc(p.password)}</span> <span class="mut">(${esc(p.tool)}) su ${esc(p.file)}</span></div>`).join('') || '<span class="mut">nessuna</span>';
  document.getElementById('extracted').innerHTML = (d.extracted||[]).map(f=>`<div><a href="/api/run/${runId}/file?path=${encodeURIComponent(f.path)}&dl=1">${esc(f.path)}</a> <span class="mut">(${f.size}B)</span></div>`).join('') || '<span class="mut">nessuno</span>';
}
</script>
</body>
</html>
"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("TRIAGE_WEB_PORT", "19013")), threaded=True)
