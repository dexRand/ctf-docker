# Piano: audit e refactor (2026-10-20)

> Nasce da un audit completo del codice: backend core, analyzer, SPA e infrastruttura.
> **Vincolo nuovo: tutto deve essere controllabile da API.** Niente logica solo-UI:
> la SPA consuma soltanto endpoint `/api/v1/...` documentati in `docs/API.md`.
>
> **Visione:** (1) un'**IA** può pilotare **tutta la suite** via API quando serve;
> (2) un **autosolver** risolve da solo le challenge facili; (3) si lavora **stile
> progetto: una CTF = un progetto**, con dentro le sue challenge.
> **Rete: per ora tutto solo su localhost** (`127.0.0.1`).
> **Pronto all'avvio:** `docker compose up` (o `./ctf up`), e si è subito operativi per una CTF
> senza passi manuali: niente token da cercare nei log, niente voucher, niente `.env` da creare a mano.
>
> **Gate obbligatorio dopo ogni fase:** `docker compose config -q`,
> `app/tests/run_unit.sh` (164/164) e `./ctf test` (regressione fixture, challenge
> reali, verify_flags). Nessuna fase può peggiorare il numero di challenge risolte.

## Baseline (verificata oggi)
- `docker compose config -q` passa.
- pytest **164/164**. Serviva ricostruire l'immagine: quella locale aveva 13 giorni
  e non conteneva `alembic`.
- `tools/dork/test_dork.py` **26/26**.
- `./ctf test`: vedi `tasks/todo.md` (sezione "Refactor 2026-10").

---

## Fase 0: sicurezza e bug confermati (fix piccoli, ciascuno con un test)

| # | Dove | Problema | Fix |
|---|---|---|---|
| S1 | `api/tools.py:43` | **Path traversal confermato**: `/tooljobs/%2e%2e/files/stegsuite.db` scarica il DB | validare `job` (regex) e confrontare `base` con `TOOLJOBS_DIR`. Lo stesso per `pid` in `storage.project_dir` e nel terminale WS |
| S2 | `analyzers/git.py:56` | Un `.git/config` ostile esegue comandi (fsmonitor, diff.external, textconv) | `-c core.fsmonitor= --no-ext-diff --no-textconv`, `GIT_CONFIG_NOSYSTEM=1`, eliminare `.git/config` e `.git/hooks` dal workdir |
| S3 | `frontend/src/md.js` | XSS: link `javascript:` e attributi non escapati nel report (`v-html`) | escape di `"` e `'`, solo `http(s):` e `/`, `rel=noopener` |
| S4 | `compose.yaml` | Servizi su `0.0.0.0` (Homepage con docker.sock, ZAP, mitmproxy, Wireshark, SpiderFoot, Sage, CyberChef, IT-Tools, dork) | **tutto su `127.0.0.1`** (richiesta: per ora solo localhost); variabile `BIND_ADDR` in `.env` per il futuro |
| B1 | `orchestrator.py:269,303` | `_hunt` cancella password/note che sono sottostringa di una flag, così il file torna "bloccato" | filtrare `kind == "flag"` |
| B2 | `cracking.py:212,294,385` | Path `/tmp` fissi: due crack concorrenti si sovrascrivono | `tempfile.mkdtemp()` per chiamata, con cleanup |
| B3 | `cracking.py:266,322,337` | Il budget dell'auto-crack non vale dentro il singolo tool (timeout 3600 s) | timeout = `_remaining(deadline)` |
| B4 | `orchestrator.py:464,572` vs `:749` | `order_index`/`rel_path` collidono dopo un crack, e `shutil.move` sovrascrive file | allocare l'ordine dal DB (o path unico per id) |
| B5 | `api/projects.py:101` | Cancellare un progetto in corsa lascia il thread vivo e `JOBS` sporco | cancellare il job prima, `finally: JOBS.pop` |
| B6 | `api/cracking_api.py:52` | Il worker del crack non gestisce le eccezioni: la UI resta su "running" | try/except + evento di errore, lock su `CRACK_JOBS` |
| B7 | `analyzers/image.py:133` | La lambda di fallback OCR ha la firma sbagliata (TypeError) | `lambda _p, **_: ""` |
| B8 | `analyzers/png.py:44` | IndexError su zTXt senza NUL | dentro il `try` |
| B9 | `analyzers/sstv.py:21` | `import numpy` top-level: se manca, cade tutto il registry | import lazy |
| B10 | `analyzers/steg.py:39` | steghide chiede la password su qualsiasi errore | solo se "passphrase" è nell'output |
| B11 | `frontend Project.vue:464` | `out()` restituisce `undefined` al primo fetch: report e log perdono l'output | restituire il valore |
| B12 | `frontend Project.vue:959` | Cambiando progetto restano il WS e il terminale vecchi, e c'è una race in `load()` | riconnessione su `props.id`, `:key` sul Terminal, contatore di richiesta |
| B13 | `main.py:48` + SPA | Con `API_KEY` attiva `<img>`/download/docs danno 401, e la UI non può inserire la chiave | accettare la chiave anche via cookie o `?key=`, campo nella UI |
| B14 | `tools/scan.py`, `real_challenges.py`, `ctf` | Porta 19014 cablata, nessuna API key; il timeout del poll esce con 0 | `STEGSUITE`/`STEGSUITE_API_KEY` esportati da `ctf`, exit ≠0 su timeout |
| B15 | `app/Dockerfile` | `dpkg -i … && apt-get -f install` fragile, rockyou `|| echo WARN` silenzioso | `apt-get install -y ./x.deb`, fallire se manca rockyou |

## Fase 1: API-first (tutto controllabile da API)
Oggi report, log completi, transcript e percorso della flag sono calcolati **solo nel
frontend** (`Project.vue` `buildReport` :619, `buildFullLogs` :738,
`buildTranscript` :793, `chainOf`/`routeNodes`/`evidenceFor`).
1. Nuovo modulo backend `report.py` con endpoint:
   - `GET /api/v1/projects/{pid}/report?format=md|json&lang=it|en`
   - `GET /api/v1/projects/{pid}/logs` (log completi, `text/plain`)
   - `GET /api/v1/projects/{pid}/transcript` (XML)
   - il percorso della flag incluso in `GET .../findings` (campo `route`)
2. Endpoint mancanti:
   - `POST /api/v1/projects/{pid}/files/{fid}/run` (rilancia uno o più tool su un nodo)
   - `GET /api/v1/projects/{pid}/tree`
   - stato "paused" reale
   - `GET /api/v1/tools` con metadati (categoria, estensioni)
3. La SPA chiama questi endpoint e il codice duplicato lato client viene eliminato.
4. `docs/API.md` aggiornato. Test pytest per ogni endpoint nuovo.

## Fase 1b: CTF come progetto, autosolver, IA
1. **Modello dati CTF → Challenge → File**: nuova entità `Ctf` (nome, formato flag,
   URL, note); il `Project` attuale diventa la *challenge* (FK `ctf_id`, categoria,
   stato `solved`/`unsolved`, flag inviata). Migrazione Alembic `0003`, compatibile
   con i progetti esistenti (CTF "Default").
   API: `/api/v1/ctfs`, `/api/v1/ctfs/{id}/challenges`, import multiplo (zip/cartella
   con una sottocartella per challenge, come `./ctf pull`).
2. **Autosolver**: `POST /api/v1/ctfs/{id}/autosolve` lancia la pipeline su tutte le
   challenge non risolte (code limitate, budget per challenge). Ogni flag trovata
   con il formato della CTF segna la challenge `solved?`, con conferma manuale o via API.
   Dashboard CTF con stato per challenge.
3. **Gateway per l'IA (tutta la suite)**:
   - **server MCP** (`mcp/`, container nel profilo `ai`, solo localhost) che espone
     come tool: StegSuite (CTF, upload, analizza, findings, report, crack), sandbox
     **`rev`** (exec di comandi via API invece del solo ttyd), CyberChef (ricette via
     API), ZAP (API nativa), stato dei servizi.
   - stessa superficie anche come REST, documentata in `docs/API.md`; per
     `./ctf scan` e altri script resta compatibile.
   - guard-rail: tutto su `127.0.0.1`, API key, sandbox `rev` senza internet.
4. **Zero-config all'avvio**:
   - `./ctf up` crea `.env` da `.env.example` se manca, poi aspetta gli healthcheck e stampa gli URL.
   - SageMath senza token (solo localhost), mitmproxy/ZAP senza password locali.
   - Hashtopolis con un agent/voucher già pronto, oppure fuori dal default.
   - Wordlist e immagini già pronte; StegSuite con una CTF "Default" creata.
   - Il server MCP parte con lo stack, così l'IA lo usa subito.
5. Test: una CTF di prova con le challenge reali di `real_challenges.py`; autosolve ≥ i risultati attuali.

## Fase 2: backend modulare (rimuovere le duplicazioni)
1. **`analyzers/util.py`**: le funzioni copiate in più moduli:
   - `printable_ratio` (6+ copie)
   - `bits_to_bytes(msb=True)` (7 copie; verificare l'LSB di `audio.py:14`)
   - `b64_pad_decode`
   - `MAGICS` (tabella unica dei magic byte)
   - `safe_name`
   - `read_head(path, n)`
   - `read_wav` (4 copie)
   - `to_wav` (3 copie)
   - `open_image(max_pixels)`
   - `TEXT_EXT`/`IMG_EXT`/`AV_EXT`/`ARCHIVE_EXT` (definite una sola volta, condivise con orchestrator e cracking)
2. **`base.py`**:
   - `ToolContext.artifact(path)`, che uniforma il campo `name`
   - `ToolContext.siblings(max_bytes)`
   - `ToolContext.run_bytes()`
   - kill del process group sui timeout (`start_new_session` + `killpg`)
   - `SubprocessAnalyzer` con fallback e cap dell'output: assorbe `PdfIdAnalyzer` e i 3 hex
3. **Split di `orchestrator.py` (881 righe)**:
   - `flaghunt/patterns.py`
   - `flaghunt/hunter.py` (`FlagSink` in memoria, condiviso con `dedupe_findings`)
   - `planner.py`
   - `jobs.py`
   - `pipeline.py`
   - `crackflow.py` (`apply_crack_result` usato **sia** da orchestrator **sia** da `cracking_api`)
   - `maintenance.py`
4. `cracking.py`:
   - un solo runner subprocess (quello di `base`)
   - `list_wordlists`/`resolve_wordlists` uniti, con cache del conteggio righe per mtime
   - zip2hashcat eseguito una sola volta per file
   - wordlist passata per path, senza copiarla
5. Prefissi flag in un solo posto: anche `vision.py` usa `FLAG_PATTERN` utente.
6. Convenzioni:
   - categoria `steg` (non `stego`)
   - `display_order` unici
   - stato "nessun risultato" uniforme = `skipped`
7. Dead code da togliere:
   - `storage.file_node_path`, `hashes_of`
   - `Project.settings_json` (o usarlo per le impostazioni del progetto: decidere)
   - `Job.paused`/`thread`
   - `steg._first`, `elf._DT_JMPREL`
   - import inutilizzati
   - `on_event` → `lifespan`
   - `app/backend/static/index.html` (placeholder)

## Fase 3: efficienza
- `_hunt`: precarica i findings una volta per job, cap sui match b64.
- GIF: OCR `thorough=False` solo sui frame distinti.
- SSTV: niente doppia lettura, decimazione prima della FFT.
- Letture complete → letture limitate: `elf`, `whitespace`, `png`, `repair`, `decode`, `morse`.
- `pngpixels`/`audio`/`morse`: numpy al posto dei loop Python, niente `pop(0)`.
- pcap: unire i 7 passaggi di tshark dove possibile.
- DB: `COUNT … GROUP BY` in `list_projects`, delete bulk, niente N+1 in `locked_files`.
- WS:
  - eventi incrementali invece di `load()` completo ogni 600 ms
  - executor dedicato
  - kill del process group del terminale
- `Home.vue`: statistiche in parallelo.
- Retention anche per `tooljobs/` e `/tmp` (wordlist gunzip, crack).

## Fase 4: frontend modulare
- Split di `Project.vue` (1385 righe):
  - composable: `useProjectData` (WS con reconnect), `usePaneResize`, `useClipboard`
  - componenti: `FileTree`, `RunCard`, `FilePreview`, `FindingsPanel`, `LogsPanel`, `GraphPanel`, `TextModal`, `PwdChip`
- Mappa unica dei colori di stato. `fmtSize` unico. Wrapper `api` con `toastOnError`.
- Leak: `refreshTimer`, timeout di GraphView, `revokeObjectURL`.
- Chiavi i18n e icone inutilizzate da rimuovere; `localStorage` in try/catch.

## Fase 5: infrastruttura e documentazione
- `compose.yaml`:
  - anchor `x-common` (restart, logging, network)
  - `cpus` ovunque
  - healthcheck (StegSuite, MySQL con `service_healthy`)
  - tag delle immagini pinnati
- Porte davvero solo da `.env`:
  - `{{HOMEPAGE_VAR_*}}` in `services.yaml`
  - variabili Hashtopolis e AllowedHosts derivate
- `ctf`:
  - helper unico per i profili
  - `urls`/`open` completi (Hashtopolis, proxy, OSINT…)
  - `port()` robusta
  - OSINT incluso in `down`/`status`
- `.dockerignore`: aggiungere node_modules, dist, wordlists, docs, tasks, .opencode, .github.
- `rev/Dockerfile`: un solo layer `apt`, sha256 per Ghidra e jadx.
- Documentazione coerente: numero di tool generato da `GET /api/v1/tools` (oggi 41/48/52/55
  nei vari file), README "no custom builds" e "Ghidra escluso" sbagliati, RAM, sandbox `rev` PE/APK,
  riferimenti ad AperiSolve/triage obsoleti in SPEC.md/plan.md/.gitignore.
- `tools/photo-geolocate/`: integrarlo in `ctf` e nella documentazione, oppure rimuoverlo.
- CI:
  - `test_dork.py`, shellcheck, check `-f osint/compose.yaml`
  - build di `rev`/`zap`
  - e2e con un health loop che fallisce davvero
  - script di coerenza compose ↔ services.yaml ↔ README

## Ordine di esecuzione proposto
Fase 0 → 2 → 1 → 1b → 3 → 4 → 5. Il motivo: la Fase 2 crea i moduli dove vanno a vivere gli
endpoint della Fase 1. Un commit per punto, con test e gate a fine fase.
