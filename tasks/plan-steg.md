# Implementation Plan — StegoForge

Obiettivo: trasformare `triage` in un'app completa (backend API-first + GUI)
che sostituisce AperiSolve, con ricorsione ordinata, terminale, history/delete e
API per singolo tool. Vedi `SPEC-steg.md`.

## Architecture Decisions
- **FastAPI + uvicorn** (async, OpenAPI automatico) al posto di Flask: serve
  l'API-first e le WebSocket nella stessa app.
- **SQLite (WAL)** per progetti/file/tool-run/finding; filesystem per artefatti.
- **Vue 3 + Vite + Tailwind** SPA (build statico servito dall'app) + **xterm.js**.
- **Riuso** del base image AperiSolve (MIT) come toolset; l'app è nostra.
- **Orchestrazione sequenziale ordinata** (come richiesto), pool bounded opzionale.
- **Terminale PTY** integrato (`pty`+`asyncio`+WS), `cwd` = progetto.
- Refactor di `triage.py`: il motore diventa `backend/analyzers` + `orchestrator`;
  i tool esistenti vengono portati a plugin.

## Struttura prevista
```
app/
  backend/
    main.py            # FastAPI, static SPA, WS, auth
    db.py              # SQLModel/SQLAlchemy + SQLite
    models.py          # Project, FileNode, ToolRun, Finding, ...
    api/               # routers: projects, files, tools, crack, wordlists, ws
    orchestrator.py    # BFS/DFS ordinato + estrazione + ricorsione
    analyzers/         # plugin: registry + un file per tool
    cracking.py        # stegseek/fcrackzip/hashcat/pdfcrack + zip2hashcat
    terminal.py        # PTY over WebSocket
    config.py
  frontend/            # Vue 3 + Vite + Tailwind (xterm.js)
  Dockerfile           # FROM aperisolve + backend + frontend build
  tests/
```

## Task List

### Phase 1 — Foundation & backend core
- [ ] T1.1 Scaffolding `app/backend` + `requirements` + config env.
- [ ] T1.2 Modelli SQLite (project/file/tool_run/artifact/finding/attempt/event).
- [ ] T1.3 API progetti: create (upload), list (history), get, delete.
- [ ] T1.4 Storage su disco `/data/projects/<id>/{uploads,files,work}` + hashing.
- [ ] T1.5 Servire la SPA statica + `/health` + `/version`.

### Checkpoint A
- [ ] `pytest` CRUD progetti verde; upload e delete funzionano via curl.

### Phase 2 — Analyzer framework + API tool singoli
- [ ] T2.1 Registry plugin + `ToolResult` + runner subprocess (timeout, cattura).
- [ ] T2.2 Port dei tool "identità/metadati/testo": file, exiftool, identify,
      strings, pdfinfo, pdfid, pdftotext, ffprobe.
- [ ] T2.3 Tool estrazione: binwalk (scan + `-e`), foremost, 7z, pngcheck, pcrt.
- [ ] T2.4 Tool steg: zsteg, steghide, outguess, jsteg, jphide/jpseek, openstego,
      bit-layers e color-remap (PIL), spettrogramma (ffmpeg/sox).
- [ ] T2.5 `GET /tools` (catalogo) + `POST /tools/{tool}` stateless (file upload).

### Checkpoint B
- [ ] Ogni tool eseguibile via API su un file; catalogo completo; test unit.

### Phase 3 — Orchestrazione ricorsiva + findings
- [ ] T3.1 Orchestratore: ordine di scoperta, esecuzione sequenziale per file.
- [ ] T3.2 Estrazione → `file_node` figli → ricorsione fino a depth/esaurimento.
- [ ] T3.3 Flag-hunt (pattern configurabili) + rilevazione password (locked).
- [ ] T3.4 Endpoint `start/pause/resume/cancel`, `tree`, `findings`.

### Checkpoint C
- [ ] Su fixture (png+payload) l'albero è completo e ordinato; flag corrette.

### Phase 4 — Cracking & wordlist
- [ ] T4.1 Port cracking: stegseek, fcrackzip, hashcat+zip2hashcat, pdfcrack.
- [ ] T4.2 Ordine wordlist piccola→grande, stop al primo successo, ripple sui figli.
- [ ] T4.3 `GET /wordlists` + `POST /projects/{id}/crack` (scelta per item).

### Checkpoint D
- [ ] Zip AES crackato via API con wordlist; password riusata; flag trovata.

### Phase 5 — Live (WebSocket) & log
- [ ] T5.1 Bus eventi + `WS /ws/projects/{id}` (status, log, progressi).
- [ ] T5.2 Persistenza `event` (log consultabile in history).

### Phase 6 — Terminale web
- [ ] T6.1 `WS /ws/projects/{id}/terminal` con PTY (`pty`+`asyncio`), cwd progetto.
- [ ] T6.2 Vincoli sicurezza (localhost/token), resize, chiusura pulita.

### Phase 7 — Frontend SPA (Vue 3)
- [ ] T7.1 Setup Vite+Tailwind+router+store; layout, tema.
- [ ] T7.2 Home/Nuova analisi (drag&drop, modalità Auto/Check).
- [ ] T7.3 Vista progetto: albero file + dettaglio tool + anteprime + findings.
- [ ] T7.4 Log live + pannello cracking (scelta wordlist per item).
- [ ] T7.5 Terminale xterm.js + tasto Elimina / Keep in history.
- [ ] T7.6 History: elenco/revisione/eliminazione.

### Checkpoint E
- [ ] Flusso completo da browser: upload → analisi → estrazione → crack →
      terminale → delete/history; build frontend inclusa nell'immagine.

### Phase 8 — Integrazione, doc, hardening
- [ ] T8.1 Servizio `stego` in compose (porta 19014) + card dashboard.
- [ ] T8.2 Migrazione/parità col vecchio `triage` (CLI opzionale `stegcli`).
- [ ] T8.3 README (EN/IT) + attribuzioni (AperiSolve MIT, zip2hashcat MIT).
- [ ] T8.4 Test E2E + `docker compose config` + commit/push.

## Risks and Mitigations
| Rischio | Impatto | Mitigazione |
|---|---|---|
| Porting di ~20 tool | Alto | partire da metadati/strings, poi estrazione, poi steg |
| hashcat/pocl pesanti e lenti | Medio | budget, wordlist piccola→grande, Check mode |
| Terminale = shell | Alto | localhost-only, API key, cwd confinato, no host mount |
| Build frontend nell'immagine | Medio | build multi-stage, cache layer |
| Ricorsione incontrollata | Medio | depth max, cap file, dedup per hash |

## Parallelizzazione
- Sicuri in parallelo: plugin tool indipendenti, frontend, test.
- Sequenziali: modelli DB → API → orchestratore → frontend.

## Open Questions
Vedi `SPEC-steg.md` §7 (nome app, Vue vs HTMX, base image, retention).
