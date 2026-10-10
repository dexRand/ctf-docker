# Todo: CTF Toolbox

## Phase 1 — Scaffolding repo ✅
- [x] Task 1: `git init` + remote `origin` + `.gitignore` + `AGENTS.md`
- [x] Task 2: `.env.example` con porte `19000+`
- [x] Task 3: `compose.yaml` core (Homepage, AperiSolve, CyberChef, mitmproxy, IT-Tools)

### Checkpoint: Core ✅
- [x] `docker compose config -q` OK
- [x] `./ctf up` → servizi core up e raggiungibili (200)
- [x] Revisione umana (set tool + porte 19000+)

## Phase 2 — Dashboard ✅
- [x] Task 4: `config/homepage/settings.yaml` + `widgets.yaml`
- [x] Task 5: `config/homepage/services.yaml` (tutti i tool, ordinati, descritti)

## Phase 3 — Tool pesanti (profili) ✅
- [x] Task 6: ZAP webswing — profilo `web` → http://localhost:19005/zap (200)
- [x] Task 7: SpiderFoot — profilo `recon` → http://localhost:19007/spiderfoot/ (200, healthy)
- [x] Task 8: Wireshark — profilo `forensics` → http://localhost:19008 (200)
- [x] Task 9: SageMath Jupyter — profilo `crypto` → http://localhost:19010 (200, token nei log)

## Phase 4 — UX + doc ✅
- [x] Task 10: wrapper `./ctf`
- [x] Task 10b: `./ctf urls` (URL dei servizi, porte da `.env`) e `./ctf open <servizio>`
- [x] Task 11: `README.md` (EN, principale) + `README.it.md` (IT) + `LICENSE`

## Phase 5 — Deep triage ✅
- [x] Immagine `triage` (AperiSolve + stegseek/john/fcrackzip/pdfcrack)
- [x] Ricorsione parallela: 7z / binwalk -e / foremost
- [x] Analisi per file: strings, exiftool, zsteg, steghide
- [x] Flag hunt con pattern (strict su binari, generico solo su testo)
- [x] Wordlist piccola → grande, password riusata, menù interattivo sui file bloccati
- [x] Report `report.md` + `report.json` in `./data/`, consultabili in FileBrowser Quantum (19012, noauth)
- [x] Test: zip cifrato + steghide + PNG con payload (2 flag, 2 password)
- [x] Test su `challenge.png` (PNG 1×1 con zip AES): carving e lock corretti

## Phase 6 — GUI web + wordlist ✅
- [x] `webapp.py` (Flask/gunicorn) con modalità **Auto** e **Check**
- [x] Upload multiplo, log live, risultati (flag/password/estratti), report
- [x] In Check: albero file + elementi bloccati con scelta wordlist per item
- [x] Porta 19013 (solo localhost) + card nella dashboard
- [x] Wordlist più usate nel repo (500-worst, probable-1575, 10k, darkweb10k, rockyou-75)
- [x] rockyou completa (14M) inclusa nell'immagine in `/opt/wordlists`
- [x] Test end-to-end: Auto 3 flag/2 pwd, Check con scelta wordlist OK, CLI OK
- [x] Fix: binwalk estraeva nella cwd (`/data`) e non accanto al file → estrazione ricorsiva non trovata
- [x] ZIP AES: `fcrackzip` (ZipCrypto) + `hashcat` via `zip2hashcat` vendored (MIT) → testato su zip AES-256

## Backlog
- [x] Profilo `crack`: **Hashtopolis** (frontend + backend + MySQL) in compose
      (porte 19015/19016, profilo `crack`); avvio `./ctf up crack`. Gli **agent**
      si registrano dalla UI (voucher) — non ne avviamo uno di default.
- [x] **Rimosso AperiSolve** (sostituito da StegSuite): tolti i servizi
      `web`/`worker`/`cron`/`initdb`/`postgres`/`redis`/`rqdashboard`, i volumi e
      le env. La base immagine di StegSuite/triage resta pinnata (toolset).
- [x] **Homepage**: grafica sistemata — tema **hacker** (verde neon su nero,
      monospace, scanline CRT) + `statusStyle: dot`, icone **mdi**
      monocromatiche verdi, card uniformi (stessa altezza per riga), gruppi a
      colonne, bookmark CTF utili (via Reddit/YouTube), gruppo AperiSolve rimosso.
- [x] **Rimosso anche il vecchio Triage** (CLI + GUI su 19013; StegSuite lo
      sostituisce). FileBrowser resta come browser di `./data`; la cartella
      `third_party/` (zip2hashcat) resta in root perché la usa StegSuite.
- [x] **Docker integration di Homepage** (socket read-only): widget *Sistema*
      (CPU/RAM/disk/uptime) + stato/CPU-RAM per container; documentato nei README.
- [x] **Profilo `audio`: Whisper-WebUI** (Gradio) per la **trascrizione audio con
      timestamp** (SRT/VTT) — utile quando la flag è **detta a voce**. Immagine
      upstream `jhj0517/whisper-webui` (porta **19017**), default CPU-friendly
      (`small`, `float32`) via `config/whisper/`, output in `./data/whisper/outputs`
      (visibili in FileBrowser).
- [x] **Analyzer `office`**: scompatta documenti Office/OpenDocument
      (`.pptm/.docm/.docx/.xlsx/odt…`) e decodifica il **base64 separato da
      spazi** → risolve *MacroHard WeakEdge* (reali **12/12**, regressione
      **24/24**, tool totali **42**).
- [x] **Dashboard**: tema **hacker** (verde neon su nero, monospace, scanline CRT),
      icone uniformi monocromatiche, card di pari altezza e **favicon `>_`**
      (sovrascritti i default di Homepage). Immagini aggiornate (`filebrowser`,
      `wireshark`).
- [x] **Analyzer `wav-levels`**: rileva WAV con campioni **quantizzati a pochi
      livelli** e li mappa a cifre **hex** → decodifica i byte. Risolve *Surfing the
      Waves* (reali **33/33**, regressione **25/25**, tool **48**).
- [x] **GIF: frame analizzati come figli** (pipeline completa) + flag hunt su view
      **senza spazi** (flag su più righe) → risolve *Corrupted flag*.
- [x] **Analyzer `lsb-carve`**: file nascosto nei piani LSB + password da file
      "fratello" → risolve *Gab-Chan* (tool **48**).
- [x] **Challenge OliCyber/ITS + Olimpiadi + SOFTWARE**: 18 reali da mirror
      pubblico (`training.olicyber.it` richiede login) → reali **31/31**.
- [x] **Analyzer `git`**: repo git dentro uno zip → storia/refs/reflog/oggetti →
      risolve *gitgud* (tool **47**).
- [x] **Analisi ELF**: **passiva** in StegSuite (analyzer `elf`/`readelf`/`objdump`:
      struttura, **checksec** RELRO/Canary/NX/PIE/Fortify, disassemblaggio) +
      **attiva** nel container **`rev`** (profilo `rev`, :19018): sandbox isolato
      (rete interna senza internet, `cap_drop: ALL`) con gdb/strace/ltrace/pwntools/
      qemu-user + **Ghidra headless** da **terminale web** (ttyd). Tool StegSuite **45**.

### Da fare (prossima sessione)
- [ ] **Area OSINT condivisa** (`osint/`): fatta la base (override compose + README
      contratto + `example_client.py` + `CODEOWNERS`); il collega aggiunge i suoi
      servizi su `ctfnet` e chiama le API per nome servizio.
- [x] **Frame GIF → analizzati come figli** (pipeline completa, tetto `MAX_NODES`)
      + flag hunt su view **senza spazi** → risolve *Corrupted flag*.
- [ ] **`./ctf dork`** / tool **dorking** (richiesta utente): generatore di query
      Google/GitHub/Shodan da un target. *(valutare scope OSINT.)*

### ZAP: add-on "potenti" (profilo `web`) ✅
Installati in un'unica passata in **`zap/Dockerfile`** (`FROM ghcr.io/zaproxy/zaproxy`
pinnata per digest, poi `zap.sh -cmd -addoninstall …`): **ascanrulesAlpha/Beta**,
**pscanrulesAlpha/Beta**, **accessControl**, **custompayloads**, **directorylistv2_3**,
**fuzzdb**, **grpc**, **httpsInfo**, **jython**, **sse**, **ptk**. Altri add-on della
lista (`domxss`, `sequence`, `authhelper`, `fuzz`, `graphql`, `soap`, `exim`,
`requester`, `database`, `insights`, `scanpolicies`) sono **già inclusi** nella
stable. Verificato: 13/13 presenti (`-addonlist`) + webswing risponde su
`http://localhost:19005/zap` (HTTP 302). `tech` non è un ID del marketplace
(fingerprint coperto da `httpsInfo`/wappalyzer).

### OSINT — delegato (fuori scope di questa repo)
> OSINT è gestito da un collega con una **webapp separata**: qui **non** aggiungiamo
> un profilo `osint`, né Prism-platform / Web-Check / GeoSpy. **SpiderFoot**
> (profilo `recon`) resta com'è, senza espansioni OSINT.
>
> Riferimenti, solo per memoria (non da implementare qui): Prism-platform,
> `lissy93/web-check` (`ghcr.io/lissy93/web-check`), GeoSpy / Pim Su.

### Checkpoint: Complete ✅
- [x] Ogni servizio risponde a runtime (9/9 → HTTP 200)
- [x] Dashboard mostra tutti i tool con descrizione e stato
- [x] README allineato (EN principale + IT)
