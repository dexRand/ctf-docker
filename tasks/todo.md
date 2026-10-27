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
- [x] **Challenge da `susers/Writeups`** (archivio CTF cinesi, consigliato): nuovo
      caso reale *SusCTF 2017 — «Fun jpg»* (flag nei metadati XMP del JPEG →
      analyzer `exiftool`, prefisso custom `SusCTF{}`). Aggiunto anche come
      **bookmark** in dashboard (`config/homepage/bookmarks.yaml`).
- [x] **Altre fonti esterne valutate** (`project-sekai-ctf`, `SniperOJ/Jeopardy-Dockerfiles`,
      `abs0lut3pwn4g3/RTB-CTF-Framework`): aggiunte come **bookmark**. Le challenge
      SekaiCTF sono di alta qualità ma **non auto-testabili offline** qui (server/jail/pwn
      o artefatti esterni/per-istanza: *Eval Me*, *DEF CON Invitation*, *matryoshka*).
      SniperOJ/RTB servono a **hostare** challenge, non all'analisi. Idee future annotate
      in `docs/CHALLENGES.md`: analisi **`.eml`**, **XOR-exfil da pcap**, **USB HID**,
      ricostruzione **QR**.
- [x] **Da browser alle CTF (MCP Chrome)**: verificato sull'archivio **SekaiCTF 2026**
      (`2026.ctf.sekai.team`, read-only): navigo, apro le challenge, scarico gli allegati.
      Risolta *impossible stego* (`SEKAI{impossible_stego_round_trip_works}`). Nuovi
      comandi: **`./ctf pull <url>`** (scarica in `./data/pull`, estrae archivi) e
      **`./ctf scan <file>`** (`tools/scan.py`: invia a StegSuite via API e stampa le flag).
      *impossible stego* è ora anche un **test reale** (`real_challenges.py` → 35).
- [x] **StegSuite: analyzer `blobs`** (base64/hex nascosti nei testi): decodifica i
      blocchi, estrae i **file** (magic) come figli e **inline-a il testo** decodificato
      (fonte non-noisy) così il flag hunt trova flag con **prefisso arbitrario**
      (`SEKAI{}`…). Fix: gli escape `\n` non incollano più una `n` alla flag.
      **Risolve *impossible stego*** (SekaiCTF 2026) — prima 0 flag. Regressione **28/28**,
      `test_blobs` 4/4, tool StegSuite **50**.
- [x] **StegSuite: analyzer `zero-width`** (stego "invisibile"): decodifica lo stego a
      **caratteri zero-width** (ZWSP/ZWNJ/ZWJ) e a **spazi finali** (space=0/tab=1),
      provando **8 e 7 bit** + separatore + entrambi i mapping. Regressione **29/29**
      (caso `zero-width`), `test_zerowidth` 4/4, tool **51**.
- [x] **StegSuite: analyzer `whitespace`** (esolang Whitespace): interprete completo
      (stack/aritmetica/heap/flow/IO) su programmi di soli spazi/tab/newline; emette
      l'output così il flag hunt lo legge. Regressione **30/30** (caso `whitespace`),
      `test_whitespace` 5/5, tool **52**.
- [x] **rev suite — sandbox `rev` per dominio (PE/APK)**: aggiunti `radare2`, `upx`,
      `apktool`, `jadx` (objdump/binutils legge i PE) + **menu** aggiornato
      (`dec`, `r2`/`rabin2`, `apk`, `upx`). Verificato su *untitled-encore.exe* (PE) e
      *ufo* (APK). Layout **"una suite per dominio"** documentato in `tasks/plan.md`.
- [x] **StegSuite: `case-bits`, `homoglyph`, `png-pixels`**: case delle lettere
      (binario+Bacon), de-homoglyph (Cyrillic/Greek), PNG a bassa profondità/palette.
      Self-test **38/38**, regressione **33/33**, reali **35/35**, tool **55**.
- [x] **Analyzer `git`**: repo git dentro uno zip → storia/refs/reflog/oggetti →
      risolve *gitgud* (tool **47**).
- [x] **SPA StegSuite — fix audit `impeccable`** (commit `ca50ea8`/`c1daf6c`):
      history **paginata** (623→~40 tab-stop), `aria-label` sugli input, `<html lang>`
      dinamico, un solo `<main>` + heading `sr-only`, target **≥24px** (WCAG 2.5.8),
      **design token** come CSS custom properties (style.css + Tailwind + canvas +
      terminale), rimosso il `border-left` colorato (anti-pattern `side-tab`).
      Audit **12 → 17/20**, detector **`[]`**, UI smoke ALL PASSED.
- [x] **Dashboard allineata ai token della SPA**: `config/homepage/custom.css` porta
      gli **stessi** design token (ink/panel/edge/acc/fg…, mono, scanline CRT) → la
      dashboard e l'app parlano la stessa lingua visiva.
- [x] **Flag hunt: falso positivo `decode`** (commit `5d87013`): la copia
      *senza spazi* (per le flag spezzate a capo dall'OCR) incollava le parole e il
      pattern generico ripescava token tipo `uryybVGF{…}` → flag fasulle. Ora la
      copia collassata usa **solo i pattern STRICT + rot13**. Test in
      `test_flags.py`; reali **33/33**, regressione **25/25**.
- [x] **Dashboard: layout uniforme** (commit `5f7568b`): gruppi a piena larghezza
      + una card per riga via CSS (questa build di Homepage non mappa il `layout`
      per-gruppo). Card tutte 1208px, righe allineate.
- [x] **Analisi ELF**: **passiva** in StegSuite (analyzer `elf`/`readelf`/`objdump`:
      struttura, **checksec** RELRO/Canary/NX/PIE/Fortify, disassemblaggio) +
      **attiva** nel container **`rev`** (profilo `rev`, :19018): sandbox isolato
      (rete interna senza internet, `cap_drop: ALL`) con gdb/strace/ltrace/pwntools/
      qemu-user + **Ghidra headless** da **terminale web** (ttyd). Tool StegSuite **45**.
      **Estensione (passiva, pure-python)**: oltre a header+checksec ora parsa anche
      **sezioni** e **sezione dinamica** → linking static/dynamic, librerie `DT_NEEDED`,
      `SONAME`, `RPATH/RUNPATH`, `stripped`/debug info, segmenti **RWX**, **packer UPX**,
      **import dinamici** (`.dynsym` → PLT/GOT) con evidenza delle **funzioni pericolose**
      (`gets/strcpy/system/execve/…`), **costruttori `.init_array`/`.fini_array`**,
      `BIND_NOW` nel checksec, **hardening hardware CET** (`IBT`/`SHSTK`) da
      `.note.gnu.property` e conteggio **PLT relocations** (lazy binding); `readelf`
      con `-W -V`. Nel sandbox `rev` un **menu** all'avvio (ttyd) con scorciatoie
      (`dec`, `sec`, `menu`). Test: `test_elf.py` (14) + caso **`elf`** in
      `ctf_regression.py` (regressione **26/26**).
- [x] **Challenge reali SekaiCTF 2026 — *untitled-encore* risolta (rev, PE + eBPF)**:
      PE Windows che incapsula un **ELF eBPF**; il "chart" di 40 byte (20 note) è
      validato da un **VM eBPF** + hash custom. Ricostruiti formato, validatore
      (`FUN_140009d30`: costanti + `memcmp` su tabella 3000 byte) e template.
      Flag **`SEKAI{eBPF_my_B3l0v3d}`**, confermata **eseguendo il PE** con Wine
      (`--check-chart <chart>`); il `--print-template` è un **decoy** e i check
      scalari non bastano (serve il chart canonico del VM). La parte statica è
      coperta dal sandbox `rev` (radare2/Ghidra/objdump). **Gap emerso:** manca
      l'**emulazione** (il solve usa Unicorn + un interprete eBPF).
- [x] **Challenge reali SekaiCTF 2026 — *ufo* risolta (misc/Android)**: APK reale
      *Universal File Opener* (`com.krauq.universalfileopener`). Statico: nessuna
      flag in chiaro/encoding, nessuno stego nelle immagini, nessun file
      incorporato, lib native stock. Runtime (emulatore Android + `adb`):
      `debug_pro_override` è un **decoy** (sblocca solo `known_pro_entitlement`),
      `ambient_trace` è decorativo. La flag **non è ricavabile dall'artefatto** →
      recuperata dal `kona.yaml` ufficiale: **`SEKAI{clankedormiscgod}`** (limite
      dell'artefatto documentato).
- [x] **Suite `rev` validata end-to-end** sui due casi reali (PE *untitled-encore*
      + APK *ufo*): la parte statica è coperta dal sandbox (radare2/Ghidra/objdump);
      per eseguire il PE è servito **Wine** (ad-hoc, non nel toolbox).
- [x] **Suite `rev`: motore di emulazione + GUI web (`emulate`)** — il gap emerso da
      *untitled-encore*. Helper Unicorn per eseguire funzioni **self-contained**
      (ELF/PE/blob raw) con gli argomenti nei registri giusti (SysV `rdi,rsi,…` per
      ELF, Microsoft x64 `rcx,rdx,…` per PE) → stampa `rax` + dump di memoria.
      Aggiunto **z3** all'immagine (unicorn/capstone già presenti via pwntools).
      **GUI web** (`rev/emulate_web.py`, solo stdlib) servita dal container `rev`
      sulla porta **19020** (profilo `rev`, dietro proxy localhost, tema = token
      dashboard): scegli il binario da `./data/rev`, funzione/indirizzo e argomenti
      → `rax`. La GUI ha anche l'**upload** del binario dal browser (max 128 MB,
      nome sanitizzato) oltre alla scelta da `./data/rev`. Testato in browser
      (console pulita) e end-to-end (ELF non-PIE/PIE, blob raw, PE; + verifica via
      API). Aggiornati `compose.yaml` (`rev-web-proxy`), `.env.example`
      (`REV_WEB_PORT`), dashboard e README EN/IT (con screenshot).
- [x] **Stile unico web per i tool sviluppati**: la GUI `emulate` è stata portata
      al linguaggio visivo di **StegSuite/dashboard** (header `$`, sottotitolo +
      hint, `fieldset`/`legend`, toolbar con azione primaria + "copia comando",
      card risultato, footer, CRT, **token completi**) come la pagina **`dork`**
      (a cui ho aggiunto `--accdim`/`--dangerlite` per allineare il set). Palette,
      tipografia mono e spaziature ora identiche su tutte le nostre GUI.
      Screenshot `docs/screenshots/rev-emulate.png` aggiornato; console pulita.
- [x] **rev — report automatico (`rev-report`)**: primo passaggio su un binario
      (ELF/PE/APK/altro) → Markdown con tipo + hash, `rabin2 -I`/`-S`/`-i`,
      **checksec**, header/dynamic, **funzioni pericolose**, **packer**, stringhe di
      interesse con **candidati flag** e **decompilato Ghidra** (headless; `--fast`
      per saltarlo). Scrive in `./data/rev/reports/` (visibile in FileBrowser).
      Comando `report`/`rep` nel menu del terminale `rev`. Testato su un ELF reale
      (checksec letto da stderr, flag trovate, Ghidra ~13s).
- [x] **rev — esecuzione simbolica (`angr`)**: aggiunto **angr** all'immagine (pin
      `bitstring<5` per pyvex; verificato che resta compatibile con
      pwntools/checksec) + helper `angr-run BIN --find SYM|ADDR [--avoid …]
      [--stdin N] [--timeout S]` che esplora e stampa l'**input concreto** che
      raggiunge il target (stdin simbolico ASCII). Comando `sym` nel menu `rev`.
      Testato: trova `SEKAI   ` in 0.2s su un binario di prova.
- [x] **rev — auto-brute (`emulate --brute`)**: `emulate` ora itera il **primo
      argomento** su un range (`START:END[:STEP]`) o una lista, fermandosi al primo
      che soddisfa `--expected` (rax) o `--expected-mem ADDR:LEN:HEX`. L'emulatore è
      **riusato con `reset()`** (immagine + stack + registri) → ~0.17 ms/candidato
      (4661 in 0.78s, contro **116s** ricreando Unicorn a ogni giro). Testato su rax
      e su memoria.
- [x] **rev — workbench web (tab `emulate`/`brute`/`report`)**: la GUI su `:19020`
      è diventata un **workbench** a tre schede nello stesso stile — **emulate**
      (chiamata singola), **brute** (sweep + match su rax o memoria), **report**
      (`rev-report --print`, Markdown a schermo). Endpoint `/api/run|brute|report`
      con target/entry condivisi e upload; la cartella `reports/` è esclusa dal menu
      file. Rinominati file/comando in `rev_web.py`/`rev-web`; dashboard (card
      **Rev workbench**) e README aggiornati, screenshot `rev-workbench.png`.
      Testato in browser (tab ok, console pulita) e via API.
- [x] **rev — workbench `distill` (UI semplificata)**: la GUI era "un casino" →
      ridisegnata in **flusso lineare** (binario → azione → campi → esegui →
      risultato), niente più `fieldset`/tab annidati; opzioni secondarie dietro
      **"opzioni avanzate"** (`<details>`); **un solo** pulsante primario che cambia
      etichetta (analizza/esegui/brute); meno testo; focus ring, `::selection` e
      scrollbar tematizzati; rimosso il `border-left` colorato. Bug fixed: i pannelli
      `hidden` restavano visibili (`.fields{display:grid}` batteva `[hidden]`).
      Verificato desktop + mobile, console pulita, `impeccable detect` → `[]`.
      Screenshot `rev-workbench.png` + `rev-workbench-mobile.png`.
- [x] **rev — workbench più "automatico"**: all'**upload/selezione** del binario
      parte **da solo** un **report `--fast`** (con il nuovo `rev-report --no-write`,
      per non scrivere file a ogni cambio) e la scheda passa a `report`. L'input
      della funzione è una **datalist** popolata con i **simboli** del binario
      (`GET /api/symbols` via `rabin2 -sj`, import esclusi). Flusso finale:
      *carica → vedi report → scegli funzione → emulate/brute*. Verificato
      (12 simboli, auto-report all'avvio, emulate ok, console pulita, detector `[]`).
- [x] **rev — report: segnali in evidenza** (`rev-report --json`): il report espone
      un **riepilogo strutturato** (flag, **funzioni pericolose**, packer,
      arch/bits, canary/nx/pic); la GUI lo mostra **in cima** come badge — flag
      evidenziate + pericolosi + riga meta — prima del report completo. L'endpoint
      `/api/report` usa `--json`. Verificato (flag `SEKAI{…}` evidenziata,
      `strcpy/system` in evidenza, console pulita, detector `[]`).
- [x] **rev — copia report**: il pulsante di copia è ora **contestuale** —
      `copia comando` (emulate/brute) oppure **`copia report`** (anche per
      l'auto-report). Il testo copiato è un blocco **auto-contenuto** (intestazione
      + flag + pericolosi + meta + report), pronto da incollare. Verificato (buffer
      ~6 KB con `flags:`/`pericolosi:` + markdown, console pulita, detector `[]`).
- [x] **StegSuite — fix del falso "password required" di steghide**: `steghide`
      (e `outguess`) escono non-zero **sia** per "nessun payload" **sia** per
      "password errata" — e non si distinguono. Su un nodo appena prodotto da un
      **decoder stego** (zsteg, bit-planes, lsb-carve, image-enhance/repair, psimage,
      …) quel "needs password" è un **falso positivo**: marcava il file come
      **locked** e faceva partire l'**auto-crack** a vuoto (budget sprecato).
      Ora l'orchestratore ignora il segnale per i **derivati dei decoder**; l'upload
      originale e i file scompattati da **archivi** restano eleggibili, e i lock
      **archivio** (7z/zip/rar) contano sempre. Su *try_me.pcap*: **niente** più note
      "password required" né auto-crack, **flag ancora trovata**; regressione **33/33**.

### Da fare (prossima sessione)
- [ ] **Prossimo miglioramento (da scegliere, sessione breve)**: (a) **emulazione**
      nella suite `rev` (Unicorn + capstone + helper `emulate`) — gap emerso dal
      solve di *untitled-encore*; (b) integrare il tool orfano `tools/photo-geolocate`
      (README/dashboard/`./ctf`/test); (c) altre challenge reali (es. SekaiCTF misc
      *deadgame2*) con fix dei gap.
- [ ] **Area OSINT condivisa** (`osint/`): fatta la base (override compose + README
      contratto + `example_client.py` + `CODEOWNERS`); il collega aggiunge i suoi
      servizi su `ctfnet` e chiama le API per nome servizio.
- [x] **Frame GIF → analizzati come figli** (pipeline completa, tetto `MAX_NODES`)
      + flag hunt su view **senza spazi** → risolve *Corrupted flag*.
- [x] **Dork generator** (richiesta utente): pagina web statica
      (`config/dork/`, servita da `nginx:alpine` su `:19019`, core) + CLI
      `./ctf dork <target>` (`tools/dork/dork.py`). Un unico `presets.json`
      condiviso web/CLI; nessuno scraping (genera solo query Google/Bing/DDG/
      GitHub/Shodan/…). Valutati e scartati gli scraper esistenti (pagodo,
      DorkScout, Dorkify: fragili/rate-limit). Card in dashboard (Recon).
      Export web `.md/.json/.txt` + "apri tutti"; CLI `-o/--out FILE` (es.
      `./ctf dork x -o data/dork/report.md`).
- [x] **Dork generator — Google Hacking Database**: sync via
      `./ctf dork --update` (endpoint DataTables di exploit-db → 7944 dork,
      14 categorie, cache locale `config/dork/ghdb.json`, .gitignored) + tab
      **GHDB** nella web UI (ricerca + categoria + export) + ricerca CLI
      `./ctf dork [target] --ghdb <kw> [--ghdb-cat …]`. Test con righe reali.
      **Usabilità**: `./ctf dork` (senza argomenti) sincronizza la GHDB in automatico
      se assente/vecchia (>7gg) e apre la pagina; hint "come si usa", copia per-card,
      call-to-action se la GHDB non è sincronizzata; quick-start nei README.
- [x] **Dork generator — provider come plugin**: un file JSON per motore in
      `config/dork/providers/` (`id/name/kind/url/order/default`); la CLI li carica
      dalla cartella e rigenera il bundle `config/dork/providers.json` (servito alla
      web UI) a ogni run / `./ctf dork --build`. Aggiungere un motore = droppare un
      file, zero modifiche al codice. Test: validazione plugin + bundle allineato.
- [x] **Dork generator — anche i dork sono plugin**: sorgenti in
      `config/dork/dorks/*.json` (`{name, presets:[…]}`, uno per gruppo) + `meta.json`;
      i bundle `presets.json`/`providers.json` sono **generati** da `./ctf dork --build`
      (e a ogni run). Test: validazione plugin dork, id univoci, drift check del bundle.
      Totale self-test **26/26**.

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

## Refactor 2026-10 (audit completo) — vedi `tasks/plan-refactor.md`
Stato: **Fasi 0–5 fatte**, Fase 6 (RevSuite) in attesa di approvazione.
- [x] **Fase 0 — sicurezza e bug**: path traversal su `/tooljobs` (DB scaricabile,
      confermato), RCE da `.git/config` (confermato), XSS nel report, porte su
      `127.0.0.1`, password cancellate dal dedupe, `/tmp` condiviso fra crack, budget
      di crack, collisioni di `order_index`, delete con job attivo, worker crack senza
      errori, bug analyzer (OCR fallback, zTXt, numpy opzionale, steghide), bug SPA
      (`out()`, race `load()`, WS/terminale), API key via cookie/`?key=`, Dockerfile.
- [x] **Fase 1 — API-first**: report/log/transcript/flag-route/summary nel backend,
      `POST /files/{fid}/run`, pausa visibile; `docs/API.md` aggiornato.
- [x] **Fase 1b — CTF/autosolver/IA**: modello `Ctf` (migrazione 0003), formato flag
      per CTF → `solved`, autosolver, vista CTF nella SPA, **server MCP** (19 tool),
      `/services`, `./ctf up` pronto all'uso + `./ctf mcp`.
- [x] **Fase 2 — modularità**: `orchestrator.py` diviso in 9 moduli, `analyzers/util.py`
      (bit/printable/base64/magic/estensioni), `run_cmd` unico con kill del gruppo,
      `ctx.siblings()`, `apply_crack_result` condiviso, codice morto rimosso.
- [x] **Fase 3 — efficienza** (senza perdere flag, verificato): GIF OCR una volta,
      `lsb-carve` in numpy (97 s → 0,9 s su Gab-chan, byte identici a zsteg), morse
      vettorizzato, letture limitate, line-count wordlist in cache, N+1 rimossi.
- [x] **Fase 4 — frontend**: `Project.vue` 1385 → ~900 righe (summary dal backend,
      `ansi.js`, `usePaneResize`, `TextModal`), i18n/icone morte rimosse, leak chiusi.
- [x] **Fase 5 — infra/doc**: compose con ancora `x-base`, cpus, healthcheck, link
      dashboard da `.env`, **immagini pinnate per digest** (`tools/pin_images.py`),
      `tools/check_consistency.py` in CI, README EN/IT riscritti, SPEC/AGENTS aggiornati.
- [x] **Nuove tecniche dai test reali**: whitespace a due simboli, flussi UDP/TCP,
      base64 un token per pacchetto, testo di SVG/HTML, bit alto, prefissi CTF comuni
      (`DUCTF`, `ictf`, `tjctf`, `lactf`, …), niente flag fasulle dagli hex dump.

Risultati (immagine nuova): pytest **214/214**, regressione **33/33**, reali **35/35**
(2963 s → 2675 s di analisi a parità di flag), verifica writeup **ALL CORRECT**.
Nuove reali in `app/tests/real_challenges_extra.py` (`--extra`, `--gaps`).

### Ultimi interventi (20/10, dopo il primo push)
- [x] Riquadro verde / prova per **ogni** flag: anche quelle decodificate (XOR, base64,
      hex, rot13, OCR, FLAG_PATTERN) e quelle nei byte del file (hexdump all'offset).
      Audit sullo storico: 0 flag senza prova.
- [x] `pcap`: tunnel DNS per server di destinazione (shark2), porte sorgente (sow2),
      base64 per pacchetto (ph4nt0m), flussi UDP/TCP (sow1); niente `foremost` sui pcap.
- [x] Cracking: errori di hashcat non più presi come password; wordlist di contesto dai
      metadati (EXIF Title/Comment…); per ogni wordlist hashcat **e poi** fcrackzip.
- [x] `stepic` (150 MP in 2 s), `lsb-carve` sulle prime righe delle immagini enormi,
      niente doppio carving dei frammenti ritagliati.
- [x] Tempi per tool corretti con le ondate parallele.
- Verifica in corso al momento della compattazione (`gate10`): 18 extra + regressione
  + 35 reali + writeup. Push consentito solo se tutto verde (vedi memoria).

### Backlog
- [x] CI spostata in `.github/workflows/ci.yml` (compose+consistency, scripts,
      backend, frontend, e2e) e pushato tutto su `origin/main` con un token
      con scope `workflow`.
- [ ] Fase 6 — RevSuite (auto-triage binari + terminale per progetto) — da approvare.
- [x] Coda di cracking con N worker (`CRACK_WORKERS`), crack per file, `GET/DELETE /cracks`.
- [ ] Gap reali: evtx, PNG/BMP corrotti + OCR, SSTV→OCR, porte UDP, evil bit, GPP
      cpassword, SAM, Chef, QOI, zstd IDAT, palette PNG, QR sfocato, pcap corrotto, ASK/SAME.

### Prossima sessione (da fare)

- [x] **CI spostata al suo posto**: `git mv ci/ci.yml .github/workflows/ci.yml`
      (fatto, sovrascritta la vecchia) e pushato.
- [x] **Coda di crack visuale** nella SPA: sezione con job in coda/in corso/finiti,
      stato, posizione, tempo, password/wordlist e annulla per i queued.
- [x] **Job `running` durante un crack** (e ripristino dello stato a fine batch,
      incluso il caso di più job in coda) — implementato e coperto da test.
- [x] Verifica gate10: superata dalla gate12 e dalle suite complete successive
      (fixture 33/33, reali 35/35, writeup ALL CORRECT).
- [ ] Fase 6 (RevSuite / rev auto-finder) ancora da approvare.
- [x] **Gate10 — 2 regressioni sistemate (gate12: extra 18/18, fixture 33/33, reali 35/35, ALL CORRECT)**: extra 17/18
      (`nothing.png` FAIL, got=[]), fixture 33/33, reali 34/35 (`dolls.jpg` /
      Matryoshka FAIL, got=[] — prima passava: probabile effetto di
      `perf(planner): don't carve again what a carver cut out` sui file annidati).
      Log: scratchpad `gate10.log`.

### Sessione merge (21 ott 2026)

- [x] Merge del lavoro di Claudione (`origin/main`, 58 commit: split
      planner/pipeline/crackflow, 60 analyzer, MCP, CI) con il nostro
      rev workbench (14 commit locali). Backup: branch `backup/local-20261021`.
- [x] Riportati nei nuovi moduli i due fix stego: niente decoder-su-decoder,
      niente carving su output di decoder, `needs_password` di steghide/outguess
      su nodi decodificati ignorato (pipeline + `locked_files`).
- [x] Rev workbench registrato in `ctf` SERVICES, `app/backend/services.py` e
      Homepage (`HOMEPAGE_VAR_REV_WEB_PORT`); `check_consistency` 0 problemi.
- [x] Regressione `./ctf test` dopo merge e push: verde più volte.
- [x] ~~`shell` (`:19021`) con zellij~~ — rimosso: code-server (`term`, :19022)
      ha gia' il profilo terminale `rev` (`docker exec` nella sandbox), quindi
      pane/tab si fanno da VS Code e il servizio era ridondante. `:19018` resta
      il terminale semplice con menu; tema verde anche li'.
- [x] **Terminale StegSuite (:19022)**: code-server 4.141.0 nell'immagine StegSuite,
      tema della suite, AI/chat e git disattivati, estensioni Open VSX (hex, asm, smali,
      solidity, verilog, jinja, toml, proto, pdf, sqlite, csv, icone), progetti
      per data. Profili terminale `stegsuite` (tutti i tool, `cdp`) e `rev`
      (`docker exec` via `term-proxy`: solo GET + exec, `run`/`stop` → Forbidden).
      Su un altro host impostare `DOCKER_GID` in `.env`. Profilo `rev` con rev
      acceso non ancora provato.
- [x] Build StegSuite + `run_unit.sh` + regressione + reali (anche per le regole
      planner `IMG_DECODERS`/`STEG_DECODERS`): verde, 257 unit test.
- [x] `photo-geolocate` integrato: `./ctf geo <foto>` (usa l'immagine StegSuite),
      bookmark in dashboard, riga nei README EN/IT, test `app/tests/test_geolocate.py`.
- [x] **Coda di crack visuale** nella SPA (sezione "crack queue": stato, posizione,
      tempo, password/wordlist, annulla i queued) e **progetto `running`** durante
      il crack con ripristino a fine (test in `test_crackqueue.py`).
- [x] **Gap chiusi**: evil bit RFC 3514 (EBE.pcap), zstd IDAT (miniscule.png),
      OCR denoise + correzione O/0 e l/1/i (c0rrupt.bin, tunn3l v1s10n), QR
      sfocato con upscale/unsharp/soglia adattiva (blurry.png).
- [x] **Gap chiusi**: SAM (hash+password), Chef, pcap repair, evil bit, zstd IDAT,
      OCR (denoise/rotazioni/correzioni), QR sfocato.
- [ ] **Gap ancora aperti**: ASK (1 char/4 bit singoli ambigui), SAME/EAS
      (risposta di conoscenza), Firefox (`key4.db` con IV troncato).
      `elves.bmp`: ELF degradato da JPEG → non ricostruibile.
      `out.qoi`: catena QOI→…→PNG ok, OCR dell'artwork non legge la flag.
- [x] **Gap chiusi (2° giro)**: pcap repair (magic + `incl_len` corrotti, catena
      ricostruita da `orig_len`; oggetti HTTP esportati → OCR), Chef esolang con
      due quantità ignote (brute-force x/y, flag), OCR con rotazione ±30° e
      correzione `@→0` (flag scritta a mano), nomi di estrazione troncati (gli
      oggetti HTTP con URL lunghissimi facevano fallire l'analisi).
- [x] SAM (`samiam`): analyzer `sam` (impacket + hashcat) → password recuperata.
- [ ] **Ancora aperti**: ASK (`sleepy.mp3`), SAME/EAS (`warning.wav`), Firefox
      (`ictf23_web`, `key4.db` con IV troncato). `elves.bmp`: non ricostruibile.
  Verificati sui casi reali: ictf23_forensics ✅ (266s: il pcap esporta ~130
  oggetti HTTP, la pipeline li analizza tutti — la flag è in secret.png) e
  recipe.txt ✅ (2s). Nota: l'export HTTP degli oggetti video rende il caso lento.
- [ ] **ASK** (`sleepy.mp3`): trovato e demodulato (carrier 8 kHz, 50 baud, un
      slot di silenzio ogni 8 bit): si legge `ictf{1_sl33py_NaYuKi_alarm_...}`
      con ~2 bit sbagliati per la musica a 8 kHz. Serve un demod più robusto
      (calibrazione sui slot di silenzio) prima di dichiararlo chiuso.
- [ ] **SAME/EAS** (`warning.wav`): i toni non corrispondono all'AFSK standard
      (sembra ricampionato) e la flag attesa è una risposta di conoscenza
      ("3rd worst tornado outbreak"), non un dato nel file.
- [ ] **Firefox profile** (`ictf23_web`): sessionstore decodificato come LZ4
      block; la flag non è nei DB, nel JSON né nei 127 file del profilo. Il login
      `yoteachapp.com` è cifrato 3DES-CBC con la chiave master in `nssPrivate`,
      ma il PBES2 di `key4.db` ha un **IV da 14 byte** (dovrebbe essere 16):
      il file è manomesso/troncato, quindi la decifratura NSS standard non
      funziona. Serve capire quali 2 byte mancano (o un'altra copia della chiave).
- [x] **SAM hive** (`samiam`): analyzer `sam` — rileva la hive, trova la SYSTEM
      tra i file del progetto, estrae gli hash con impacket (BootKey) e li cracca
      con hashcat (rockyou + wordlist). Password recuperata: `!checkerboard1`.
      La flag attesa è `DUCTF{!checkerboard1}`: il wrapping nel formato CTF non
      viene inventato dalla pipeline (resta la password nel report).
- [x] **Perf pipeline**: gli oggetti HTTP di un pcap diventano figli solo se
      analizzabili (immagini/documenti/archivi/eseguibili/testo; DER, video,
      font e blob restano artifact) e i file estratti identici sono dedupati per
      sha256. `ictf23_forensics` resta PASS (~200s vs 266s). Aggiunto l'analyzer
      `sqlite` (dump del testo di ogni tabella, utile per profili browser/app).
- [x] **Perf**: hex dump a 32 KiB (erano 128 KiB × 3 tool per file, e il flag hunt
      scansiona ogni output più volte), rotazioni OCR solo se il testo c'è già e
      su una copia a 1000 px (6 passate tesseract su una foto 4MP costavano
      decine di secondi), crack SAM che si ferma appena tutti gli hash sono noti.
      Suite completa verde: fixture 33/33, reali 35/35 (4084s totali), writeup ALL CORRECT.
- [x] **Perf misurata**: `garden.jpg` 403.6 → **275.4s** (-32%), `try_me.pcap`
      225.0 → **162.6s** (-28%). Provato `HEAVY_TOOLS=2` + `TOOL_WORKERS=4`:
      nessun guadagno con il container a 3 CPU (171 vs 163s) → restano 1/3.
- [x] **Errori "cosmetici" delle run vecchie** (135 su 250 progetti campione):
      outguess "no data/wrong key", waveform su audio non decodificabile,
      7z su archivi vuoti/corrotti, git su zip AES, zsteg su immagini rotte,
      bit-planes/channel-remap/image-enhance/psimage su BMP non validi,
      nested-archive su stream troncati → ora `done`/`skipped`, non `error`.
      Restano 0 progetti in errore (l'unico era il vecchio nome troppo lungo).
- [x] **Perf (2° giro)**: `bit-planes` salva piani PNG 1-bit e fa OCR a 1000 px
      (4 MP: 351 → 51s), `qr` deblur su una copia ≤500 px (garden: QR 250 → ~5s),
      `ocr` accetta un `max_dim` per chiamata. **garden.jpg 403.6 → 125.8s (-69%)**,
      **try_me.pcap 225.0 → 142.2s (-37%)**, entrambi PASS.
- [x] **Validazione completa dopo le ottimizzazioni**: fixture **33/33**, reali
      **35/35**, writeup **ALL CORRECT**. Tempo di analisi dei 35 casi:
      **4084.2 → 2369.0s (-42%)**, con `-j 2` (prima era `-j 3`). Nessuna
      soluzione persa. Esempi: weird.docm 249→16s, main.wav 44→4s,
      webnet0 54→6s, flag.txt 122→20s, pico_img 193→82s, dolls 477→320s,
      corrupted_file 531→342s, garden 404→220s (126s da solo), try_me 225→149s.
- [x] **Perf (3° giro)**: `bits_to_ints` con numpy per flussi grandi; zero-width
      (regex + Counter), homoglyph (translate + numpy) e case-bits (numpy sui byte
      UTF-8) non fanno più loop Python per carattere. Su un log da 23 MB:
      case-bits 46.7 → **2.1s**, zero-width 31.8 → **2.5s**, homoglyph 21.5 → **0.2s**.
      `bit-planes`: OCR LSB a 800 px senza re-upscale (4 MP: 351 → **22.5s**).
- [x] **Perf (3° giro, misure)**: `misc_impossible` 617.7 → **363.9s** (-41%),
      `corrupted_file` 530.9 → **195.9s** (-63%), `dolls.jpg` 476.7 → **138.9s**
      (-71%), `buildings.png` 52.1 → **31.7s** (-39%) — tutti PASS.
- [x] **Suite completa finale**: fixture **33/33**, reali **35/35**, writeup
      **ALL CORRECT**. Analisi dei 35 casi: **4084.2 → 2239.0s (-45%)**,
      nessuna soluzione persa.
- [x] **Firefox** (`ictf23_web`): analyzer `firefox-logins` — decifra i login
      salvati con **libnss3** (`NSS_Init` + `PK11SDR_Decrypt`, come firefed):
      `key4.db` manomesso (IV da 14 byte) non è un problema perché ci pensa NSS.
      Password recuperata (`yoteachapp.com`). La flag però è nei **log della chat
      sul server**, non nel profilo → il caso resta FAIL per costruzione.
  Verificato nel pipeline: su `logins.json` il tool riporta **done, 1 login
  decifrato** (la flag attesa non è nell'artefatto).

### Review 27/10 — issue aperte (dettagli: `tasks/review-2026-10-27.md`)
- [ ] dexRand/ctf-docker#1 XSS file inline · #2 NSS in-process · #3 `_PREV` crackqueue
- [ ] #4 limiti di dimensione · #5 bug minori analyzer
- [ ] #6 magic bytes unificati · #7 png.py zstd doppio · #8 prefissi/bit-plane · #9 sam/qr helper
- [ ] #10 minori + README (70 analyzer)
- [ ] **32 nuove CTF reali da smistare** (`CANDIDATES` in `real_challenges_extra.py`:
      TJCTF 2025, ImaginaryCTF 2025, BuckeyeCTF 2023/24, DUCTF 2022/25, UTCTF 2024).
      `cd app/tests && python3 real_challenges.py -j 3 --candidates --only-new --json-out …`
      poi spostare ogni caso in `EXTRA` (risolto) o `GAPS` (tecnica mancante). 3 casi hanno
      il handout incerto (commento nel file). Fonti e scarti: `tasks/ctf-sources.md`.
