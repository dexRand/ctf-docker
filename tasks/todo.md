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
- [ ] Profilo `crack`: Hashtopolis (frontend + backend + agent + DB)
- [ ] (Opz.) Docker integration di Homepage via socket read-only per stats container

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
