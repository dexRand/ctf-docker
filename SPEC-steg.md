# Spec — StegSuite (single stego/forensics workbench)

> Sostituisce AperiSolve e il `triage` CLI, unificandoli in un'unica app
> self-hosted, **API-first**, con GUI completa.

## 1. Objective

Un solo strumento self-hosted per **steganografia e forensics** che:

1. prende uno o più file caricati e li analizza **uno ad uno, in ordine**, con
   metadati, `strings` e i tool steg appropriati;
2. **estrae e ricorre** su tutto ciò che trova, continuando finché l'albero non
   è esaurito, e mostra **tutte** le cose trovate (flag, password, artefatti);
3. offre una **GUI eccellente** (albero file, risultati per tool, anteprime,
   log live) con in basso un **terminale web** per navigare i file del progetto;
4. gestisce il **ciclo di vita del progetto**: "finisci ed elimina tutto" con un
   tasto, oppure lascialo in **history** per rivederlo;
5. espone **tutto via API REST** (progetti, file, tool singoli, cracking,
   wordlist), così è usabile anche da fuori/automazioni;
6. **adotta il set di tool di AperiSolve** (MIT) e ne estende il concetto a più
   livelli.

Non-goal: multi-utente, cloud, GPU distribuite. È un tool locale single-user
(con API apribili opzionalmente).

## 2. Decisions (proposte)

- **Backend:** Python **FastAPI** + **uvicorn** — async, OpenAPI automatico
  (`/api/docs`) per l'API-first, stesso linguaggio del motore tool.
- **Storage:** **SQLite** (WAL) per progetti/file/tool-run/finding + filesystem
  per gli artefatti. Semplice, veloce, interrogabile, perfetto per history.
- **Frontend:** SPA **Vue 3 + Vite + Tailwind** (coerente con l'altro progetto
  dell'utente), terminale con **xterm.js**, live update via WebSocket.
- **Base toolset:** immagine **AperiSolve** (MIT) come layer di tool, estesa con
  hashcat/pocl + `zip2hashcat`. Il codice dell'app è nostro; se in futuro
  vogliamo un base image nostro, si sostituisce senza toccare l'app.
- **Orchestrazione:** elaborazione **sequenziale e ordinata** per file (come
  richiesto), con pool bounded per i tool più lenti opzionale.
- **Terminale:** **PTY integrato** nel backend (WebSocket + xterm.js), shell con
  `cwd` = cartella del progetto. Niente servizio esterno (niente ttyd).
- **Auth:** localhost-only di default; `X-API-Key` opzionale per accesso da LAN.

## 3. Architecture

```
            ┌───────────────────────── ctf container ─────────────────────────┐
 browser ── │ Vue SPA (static)        FastAPI /api/v1  +  WS /ws             │
   │        │        │                    │                                 │
   │        │        │           ┌────────┴─────────┐                       │
   │        │        │           │  Orchestrator    │  SQLite (projects)    │
   │        │        │           │  (sequenziale)   │  filesystem (artefatti)
   │        │        │           └────────┬─────────┘                       │
   │        │        │                    │ registry                          │
   │        │        │           ┌────────┴─────────┐                       │
   └────────┴────────┴───────────│  Analyzer plugins │  binwalk, zsteg…     │
                                 └──────────────────┘                       │
                                                                             │
 /data/projects/<id>/{uploads,files,work,project.db-ish}  ← terminale PTY ───┘
```

### 3.1 Modello dati (SQLite)

| Tabella | Campi principali |
|---|---|
| `project` | id, name, created_at, updated_at, status, mode, settings_json |
| `file_node` | id, project_id, parent_id, rel_path, name, size, mime, sha256, md5, depth, order_index, origin, created_at |
| `tool_run` | id, project_id, file_id, tool, status, started_at, finished_at, exit_code, summary, needs_password |
| `artifact` | id, tool_run_id, file_id, kind, path, size |
| `finding` | id, project_id, file_id, kind(flag/password/note), value, source |
| `attempt` | id, project_id, file_id, tool, wordlist, status, result, ts |
| `event` | id, project_id, ts, level, message (log/history) |

### 3.2 Analizzatori (plugin)

Ogni plugin dichiara: `name, category, description, needs_password,
has_archive, display_order, run(input, workdir, ctx) -> ToolResult`.
Registry con auto-discovery. Categorie e tool:

- **Identità/metadati:** `file`, `exiftool`, `identify`, `pdfinfo`, `ffprobe`.
- **Testo:** `strings`, `pdfid`, `pdftotext`, `binwalk` (scan).
- **Estrazione/carving:** `binwalk -e`, `foremost`, `7z`, `pngcheck`, `pcrt`.
- **Steg immagine:** `zsteg`, `steghide`, `stegseek`, `outguess`, `jsteg`,
  `jphide/jpseek`, `openstego`, **bit-layers** e **color-remap** (PIL).
- **Audio/video:** `ffmpeg` (spettrogramma/waveform), `sox`.
- **Documenti:** `pdfinfo`, `pdfid`, `pdftotext`.
- **Cracking:** `stegseek`, `fcrackzip`, `hashcat` (+`zip2hashcat`), `pdfcrack`.
- **Utility:** hexdump, entropia, magic.

### 3.3 Orchestrazione ricorsiva

1. I file caricati diventano `file_node` di livello 0 (order_index = ordine di upload).
2. Per ogni file **in ordine**: esegue i tool applicabili (metadati → strings →
   steg → estrazione), salva `tool_run`/`artifact`/`finding`.
3. Gli artefatti estratti diventano `file_node` figli (order_index progressivo) e
   vengono accodati → ricorsione fino a `--depth` o esaurimento.
4. Un `finding` tipo `flag`/`password` è evidenziato.
5. Eventi e log sono trasmessi in streaming.

### 3.4 API REST (`/api/v1`, OpenAPI su `/api/docs`)

**Progetti**
- `POST /projects` (multipart, mode) → crea
- `GET /projects` → history (filtri: status, q)
- `GET /projects/{id}` · `DELETE /projects/{id}`
- `POST /projects/{id}/start|pause|resume|cancel`
- `GET /projects/{id}/tree` (file + tool-run) · `/findings` · `/events` (SSE)
- `WS /ws/projects/{id}` (log/status live)
- `GET /projects/{id}/files/{fid}` · `/files/{fid}/content` (download) · `/files/{fid}/preview`
- `GET /projects/{id}/files/{fid}/runs/{rid}` (output tool)

**Tool singoli (stateless, per automazioni)**
- `GET /tools` → catalogo (nome, categoria, descrizione, flags)
- `POST /tools/{tool}` (multipart file + params) → esegue **un** tool su un file
  caricato e restituisce output + artefatti (zip o link)

**Cracking / wordlist**
- `GET /wordlists` → liste disponibili (nome, voci, dimensione)
- `POST /projects/{id}/crack` `{file_id, tool, wordlists[]}` → job

**Terminale**
- `WS /ws/projects/{id}/terminal` → PTY shell nel progetto (xterm.js)

**Sistema**
- `GET /health` · `GET /version`
- Auth opzionale: header `X-API-Key`.

### 3.5 GUI (Vue 3)

- **Home / Nuova analisi:** drag&drop, scelta modalità (Auto / Check), avvio.
- **Vista progetto:**
  - **Sinistra:** albero file (nesting, badge tipo, icone finding, ordine).
  - **Centro:** dettaglio file con tab → *Overview* (metadati), *Tool* (output
    per analizzatore, collassabili), *Estratti* (figli), *Preview* (immagine,
    audio, testo, hex).
  - **Destra:** pannello *Finding* (flag 🚩, password 🔑) e **log live**.
  - **Sotto:** **terminale** (xterm.js) con `cwd` = cartella del progetto.
  - **Azioni:** Run/Resume, Pause/Cancel, **Crack** (scelta wordlist per ogni
    elemento bloccato), **Elimina** (con conferma), **Keep in history**.
- **History:** elenco progetti (data, stato, n. finding), apri per revisionare o
  elimina.

### 3.6 Ciclo di vita

- I progetti restano in **history** finché non li elimini (default).
- `DELETE` rimuove DB + filesystem.
- Opzione (env) di retention automatica (es. `RETENTION_DAYS`) disattivata di default.
- Stati: `queued → running → (paused) → done | error | cancelled`.

### 3.7 Terminale

- WebSocket + PTY (`pty`+`asyncio`), shell `bash` con `cwd` = `/data/projects/<id>`.
- `xterm.js` nel frontend; resize, copia/incolla; token/​API-key se esposto.
- Vincoli: bind localhost di default; niente mount host oltre `/data`.

### 3.8 Sicurezza

- GUI/API su `127.0.0.1` di default; `API_KEY` opzionale per LAN.
- Container con limiti mem/cpu; input non fidato.
- Terminale = accesso shell: documentato, localhost-only, cwd confinato.
- Nessun segreto nel repo; `.env` ignorato.

### 3.9 Performance

- FastAPI async + SQLite WAL; analizzatori subprocess in pool bounded.
- Elaborazione sequenziale ordinata; niente race sui risultati.
- Frontend build statico servito dall'app; aggiornamenti via WebSocket.

## 4. Testing

- **Backend unit:** patterns/flag-hunt, orchestratore (fixture), parser output.
- **API:** `pytest` + `TestClient` (CRUD progetto, per-tool, crack, delete).
- **E2E fixture:** zip AES (hashcat), steghide (stegseek), PNG con payload
  (binwalk), pdf cifrato (pdfcrack).
- **Frontend:** build + smoke (Playwright opzionale).

## 5. Deployment

- Servizio `stego` (nuova porta GUI/API 19014, terminale in WS sulla stessa) +
  eventuale `stego-worker` se separiamo l'orchestrazione.
- Card nella dashboard Homepage.
- Volume `/data` condiviso (history, artefatti, wordlist).

## 6. Acceptance criteria

- [ ] Carico N file → analisi **ordinata** uno ad uno, con metadati + strings.
- [ ] Estrazione ricorsiva: gli artefatti compaiono come figli e vengono analizzati.
- [ ] Tutte le flag/password trovate sono visibili e citano la loro origine.
- [ ] Terminale web funzionante, confinato al progetto.
- [ ] Pulsante **Elimina** e **history** funzionanti.
- [ ] Tool AperiSolve presenti; ZIP AES crackabile con wordlist.
- [ ] `GET /api/docs` espone progetti, file, **tool singoli**, crack, wordlist.
- [ ] Test E2E verdi sulle fixture; `docker compose up` avvia tutto.

## 7. Open Questions
- Nome definitivo dell'app (placeholder: **StegoForge**).
- Frontend: Vue SPA (proposto) o Jinja+HTMX (niente build)?
- Base: immagine AperiSolve (proposto) o base Debian nostra?
- Retention: mai automatica (proposto) o `RETENTION_DAYS`?
