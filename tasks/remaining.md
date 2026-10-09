# Remaining work — StegSuite

> Documento di ripresa. **Stato (2026-10-09): sezioni A–G e P15–P27 chiusi**;
> resta fuori scope solo OSINT (delegato). Qui sotto la storia e i limiti noti.

## Come riprendere
```bash
cd <repo>                               # es. /home/r/__Github/CTF
./ctf up                                # core (Homepage, CyberChef, mitmproxy, IT-Tools, StegSuite, FileBrowser)
./ctf up web                            # + ZAP (con add-on extra)   [recon|crypto|forensics|crack]
./ctf urls                              # URL di tutti i servizi
./ctf test                              # regressione 24/24 + reali 12/12 + verify ALL CORRECT
./ctf ui-smoke                          # smoke test della SPA (Chromium headless in Docker)
docker compose config -q                # valida il compose
```
CI: `.github/workflows/ci.yml` (compose, backend+pytest, frontend build; job `e2e`
on-demand). Il token serve con scope **`workflow`**.

## Fatto di recente ✅
- **P27 MacroHard WeakEdge risolta (analyzer `office`)**: nuovo tool **`office`**
  che scompatta i documenti **Office/OpenDocument** (`.pptm/.docm/.docx/.xlsx/.odt…`)
  e decodifica il **base64 anche separato da spazi** (o un carattere per riga) — è
  il caso di *MacroHard WeakEdge* (`ppt/slideMasters/hidden`). Aggiunta ai test
  reali (→ **12/12**) + caso fixture `office` (→ regressione **24/24**); tool
  totali **42**.
- **P26 Very very very Hidden risolta (Invoke-PSImage)**: nuovo analyzer
  **`psimage`** — estrae il payload a **1 byte per pixel dai 4 bit bassi dei canali
  B/G** (`(B&0x0F)<<4 | G&0x0F`), la tecnica di **Invoke-PSImage**. Il flag hunt ora
  prova anche lo **XOR di due stringhe** di pari lunghezza nel testo: la "mappa"
  PowerShell diventa la flag. Verificato end-to-end su `evil_duck.png` e sull'intero
  `try_me.pcap` → `picoCTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}`. Aggiunta ai
  test reali (→ **11/11**) + caso fixture `psimage` (→ regressione **23/23**);
  tool totali **41**.
- **P25 challenge difficili (sezione G) chiusa**: aggiunta **St3g0** ai test reali.
  Verificati *tunn3l*, *c0rrupt* e *Very very very Hidden* (quest'ultima poi chiusa
  in P26):
  - **perf**: l'analisi di immagini grandi era dominata da centinaia di OCR
    (bit-planes/image-enhance chiamavano `ocr_image` "thorough" su decine di
    varianti) → ora le immagini derivate usano un OCR **leggero** e i bit-plane
    scansionano solo l'LSB. `tunn3l` in auto: **>440s → 81s** (regressione 23/23
    invariata). *(era il "collateral" del follow-up auto-crack.)*
  - **decisioni/limiti**: *tunn3l* near-miss OCR (`1`→`i`) e *c0rrupt* flag visiva
    non OCR-abile. Correzione OCR `1↔i/l` **accettata come limite** (rischiosa).
- **P24 performance + formati flag custom**: **auto-crack** in Auto ora usa solo le
  wordlist ≤ `AUTO_CRACK_MAX_MB` (default 1 MB, quindi **esclude rockyou da
  140 MB**) con budget per progetto `AUTO_CRACK_BUDGET_S` (default 120s, applicato
  anche a pdf/stegseek) → un falso "locked" (JPEG senza payload steghide) non
  blocca più l'analisi (garden.jpg: auto-crack **3s**). **OCR**: le immagini più
  grandi di `OCR_MAX_DIM` (default 2200) vengono ridimensionate prima di tesseract
  (garden.jpg auto 122s → **92s**). **Flag**: regex opzionale **`FLAG_PATTERN`**
  (es. `DUCTF\{[^}]+\}`, anche senza graffe) applicata a **tutte** le sorgenti,
  incluse quelle rumorose dove il pattern generico è disattivato.
- **P23 fix UI grafo**: due problemi. (1) l'**hit-test del canvas di force-graph**
  sbagliava nodo (un click vicino a un nodo ne attivava uno lontano) → molti nodi
  "non cliccabili": ora il click è gestito da noi e seleziona il **nodo più vicino**
  (dot+etichetta, ignorando i drag). (2) `selectFile` non "rivelava" il file a
  sinistra (niente scroll/espansione; su mobile non cambiava pannello): ora
  **espande antenati e gruppi**, **azzera il filtro**, fa **scrollIntoView** e su
  mobile passa al pannello `files`. Verificato con Chromium headless (12/12 nodi
  cliccabili, timeline→sinistra ok, mobile→`files`, 0 errori console).
- **P22 cracking + bugfix**: sezione **F** completata — **upload wordlist**
  (persistite in `/data/wordlists`) con scelta per-item **persistente** in GUI;
  **hashcat rules/mask + budget CPU** (`HASHCAT_RULES`, `CRACK_BUDGET_S`, opzioni
  per-richiesta) e **bkcrack** (ZipCrypto known-plaintext, binario precompilato
  v1.8.1; verificato end-to-end: crack → decifra → estrae). **Bugfix**:
  `openstego` passava sempre `-p ""`, che lo mandava in *help* e **non estraeva
  mai** (ora `-p` solo se c'è una password, output conciso; regressione
  `openstego` → **22/22**); `bkcrack -k` richiede le 3 chiavi come argomenti
  separati. **Fix stato**: un progetto interrotto da un riavvio **con una flag
  già trovata** ora è `done` (non più `error`); i progetti **storici** in
  `error` con una flag vengono riparati a `done` all'avvio — `reconcile_orphans`.
- **P21 packaging (sezione E)**: **screenshot** reali nel README EN/IT
  (`docs/screenshots/`: home, progetto risolto, mobile) catturati con Chromium
  headless. Nuovi comandi **`./ctf urls`** (URL di tutti i servizi, porte da
  `.env`) e **`./ctf open <servizio>`**. Decisione registrata sulla **base
  image** (si tiene AperiSolve pinnata per digest).
- **P20 test/qualità (sezione D)**: **OCR italiano** (`tesseract-ocr-ita` +
  `OCR_LANGS`, default `eng` sugli host senza il pack, `eng+ita` nel container,
  fallback automatico). **Fixture reali** committate (`app/tests/fixtures/webnet0/`,
  pcap+chiave ~15 KB) con nuovo caso di regressione **`tls-pcap`** → **21/21**.
  **Smoke test della UI** con Chromium headless in Docker (`app/tests/ui_smoke.mjs`
  + `./ctf ui-smoke`: home, vista progetto, switcher mobile a 375px, zero errori
  in console). Nuovo test unit per le lingue OCR. **Riconfermato**: `real_challenges`
  9/9 e `verify_flags` ALL CORRECT dopo l'OCR (fallback ita).
- **P19 GUI: progress + toast + upload + copy-all + responsive**: l'orchestratore
  emette `total` negli eventi `file`/`progress`, così la vista progetto mostra
  una **barra di progresso** live (file corrente + percentuale). Nuovo store
  **toast** globale (`toast.js` + `components/Toasts.vue`) per errori e successi
  (crack trovato, copie, delete, svuota history). **Upload con progress** via XHR
  (`api.uploadFile`). Bottone **copia tutte le flag** nel pannello findings +
  export report `.md` (già presente). **Layout mobile**: sotto i 900px la vista
  progetto mostra un pannello alla volta (files/detail/panel) con selettore;
  separatori nascosti, modali `min(…, 100vw-…)`, header/footer che vanno a capo.
- **P18 ops: Alembic + retention**: le migrazioni dello schema ora sono gestite
  da **Alembic** (`app/backend/migrations/`: revisione `0001` baseline
  autogenerata + `0002` `finding.context`). `init_db()` esegue `upgrade head` e
  **stampa** i database creati prima di Alembic (`_legacy_revision` riconosce se
  `context` esiste) — `_migrate()` manuale rimosso. Aggiunta la **retention**
  opzionale (`RETENTION_DAYS`, 0 = mai): all'avvio elimina i progetti più
  vecchi (righe DB + filesystem, `backend/retention.py`); dedup della
  cancellazione in `db.delete_project_rows`, riusata dall'API. `pytest` **88**.
- **P17 analyzer: TLS su pcap (`WebNet0/1`) + rot13/url inline**: l'analyzer
  `pcap` ora **decifra TLS** quando trova una chiave privata (o un keylog
  `CLIENT_RANDOM`) accanto al capture: `tls.keys_list`/`tls.keylog_file` di
  tshark, sezione "TLS decrypted" (header inclusi) e `--export-objects` sugli
  oggetti decifrati (WebNet1 → `vulture.jpg` → flag nei metadati, via ricorsione).
  Verificato: **WebNet0** `picoCTF{nongshim.shrimp.crackers}` e **WebNet1**
  `picoCTF{honey.roasted.peanuts}` (reali **9/9**). Nella flag hunt: vista
  **percent-decoded** e ricerca dei **twin rot13** dei prefissi noti anche sulle
  sorgenti rumorose. `pytest` **82**.
- **P16 analyzer: decoder SSTV (`sstv`)**: nuovo analyzer audio che demodula una
  trasmissione **SSTV** senza dipendenze esterne (band-pass + Hilbert →
  frequenza istantanea → sync pulse 1200 Hz → riconoscimento **modo dallo
  spacing** dei sync → ricostruzione RGB). Supporta **Scottie S1/S2**; il
  `message.wav` reale di *m00nwalk* decodifica un frame 320×256 identico a
  quello di QSSTV (verificato). Il frame è salvato come artefatto e OCR-ato
  dritto e capovolto (le immagini SSTV arrivano spesso ruotate). Regressione
  **20/20** (nuovo caso `sstv` con encoder Scottie S1 sintetico), `pytest` **77**.
  Limite noto: il testo di m00nwalk è capovolto e il frame 320×256 rumoroso →
  OCR near-miss (documentato in `docs/CHALLENGES.md`).
- **P15 core: `nested-archive` + job resiliente**: nuovo analyzer che apre in
  **un solo passaggio** le catene di archivi annidati (*like1000*: 1000 tar con
  un `filler.txt` per livello) seguendo il membro archivio più grande e
  restituendo solo il file finale (che viene poi analizzato normalmente). Con
  `ToolResult.consumed` l'orchestratore salta gli estrattori rimanenti sul nodo
  → niente ricorsione profonda né tool pesanti per livello. **Bugfix di
  robustezza** scoperto in E2E: un'eccezione in un analyzer (`ocr` su un PNG
  troncato → `OSError: Truncated File Read`) uccideva il thread del job lasciando
  il progetto bloccato in `running`; ora l'orchestratore cattura l'eccezione
  (run `error`) **e** ha una rete di sicurezza che marca il job `error`, inoltre
  `ocr_image` decodifica con guardia. Regressione **19/19** (nuovo caso
  `nested-archive`), `pytest` **73**.
- **P14 CI + falsi positivi + OCR canali + test**: CI reso verde — dipendenze
  backend **pinnate** alle versioni verificate nell'immagine e **`httpx`** in
  `requirements.txt` (il CI prendeva uno starlette nuovo che pretende `httpx2` e
  non installava il client HTTP per `TestClient`). Nuovo `test_crack_locked.py`
  (locked/crack 409/`record_crack_run`/`mark_unlocked`/timestamp) e
  `test_api_tools` robusto se il binario `strings` manca. Il pattern generico
  `<word>{...}` è **saltato su sorgenti rumorose** (`strings`/hex/pcap): niente
  più flag spazzatura (`MxeV{...}`, `9K{...}`). **OCR per canale/banda**:
  se la passata grayscale non trova flag note, prova R/G/B su banda alta/bassa
  (bounded, 6 chiamate) per testo a basso contrasto (tunn3l: canale R legge
  `picoCTF{quit3_a_v13w_2020}`).
- **P13 GUI: transcript XML (context-engineering) + full logs**: il **transcript**
  segue le linee guida Anthropic (*effective context engineering* / prompting):
  **tutto in `<transcript>`** con tag XML (`<challenge>`, `<findings>`,
  `<flag_path>`, `<timeline>`, `<files>`, `<runs>` con `<commands>`/`<output>` in
  CDATA, `<event_log>`, `<still_locked>`) e il **`<task>` in fondo** (dati lunghi
  sopra, query sotto → +qualità); output curati (comandi sempre, output troncato,
  più spazio ai run del percorso flag). Nel tab **Logs** il riquadro sotto ha ora
  due viste: **runs** e **full logs** (eventi + tutti i run con output) con
  **copia in un click**.
- **P12 GUI: transcript per agente + copia log**: bottone **transcript** nella
  barra azioni → modale con **copy/.md** di un transcript completo (findings,
  route ASCII, timeline, albero file con hash, **tutti i run con comandi+output**,
  event log), pensato per essere incollato in un'AI se il tool non chiude la
  challenge; nel tab **Logs** un bottone **copia log**.
- **P11 GUI: graph interattiva (force-graph) + crack con log + click sincronizzato**:
  la tab **graph** usa ora **`force-graph`** (MIT): simulazione a forze con
  **zoom/pan/scroll**, **drag dei nodi**, label scalate e `fit`; i nodi del
  percorso flag e le flag sono verdi, i bloccati/craccati ambra. **Cliccare un
  nodo (o uno step della timeline) seleziona quel file a sinistra**, così i
  dettagli restano in un solo posto (niente pannello duplicato). Il **crack ora
  registra un `ToolRun`** (`tool=crack`) con i comandi reali (hashcat/zip2hashcat,
  `7z`, stegseek…) e l'esito, quindi compare in overview/logs/graph (prima non
  lasciava traccia). Un solo crack-run per file, aggiornato tra i round.
- **P10 GUI: tab Graph + crack visibile in overview**: nuova tab **graph** nel
  pannello destro con l'**albero dei tool** che hanno prodotto ogni file (nodi
  colorati: verde = percorso flag), la **timeline** ordinata di come è stata
  trovata la flag e, cliccando un nodo, i **dettagli**: comando/output del run che
  l'ha prodotto, esito del crack e **file risultanti**. In overview/extracted un
  file craccato non mostra più `[pw]`: la run diventa **`cracked`** con il
  risultato (`🔑 robot (via 10k-most-common.txt)`), nell'albero un `🔑`.
- **P9 GUI: layout a 3 colonne rifatto + resizer affidabili + log con storico**:
  pannello destro **ancorato a destra** (tree a larghezza fissa a sinistra, centro
  `flex-1 min-w-0`, pannello destro `shrink-0`); **separator** unificati (`.sep`,
  5px, hover accento) con drag **delta-based** (niente più salti/combattimenti) e
  clamp sul centro; **accessibili** (`role="separator"`, `aria-orientation`,
  frecce da tastiera); **dimensioni persistite** in `localStorage`. La tab
  **Logs** ora pre-carica gli **eventi storici** da `/events` (con timestamp), non
  solo lo stream live; xterm si riadatta via **ResizeObserver** quando la tab
  diventa visibile. E2E su `challenge.png`: auto-crack `robot` su `46.zip` →
  flag `ITS{stego_z1p_appended}`; `/locked` mostra solo il file non craccato;
  crack manuale 409 sul già craccato, ammesso sull'ancora bloccato.
- **P8 GUI: pannello destro a tab + stato crack + timestamp**: findings, terminale
  e logs spostati in una **colonna destra a tab** (rimossa la barra in basso); i
  **logs** sono splittati in verticale (live sopra, run/comandi sotto, handle
  draggabile); un file **già craccato non è più "locked"** — `/locked` e la
  dashboard escludono i file con un Finding `password`, e `mark_unlocked` azzera
  `needs_password` dopo un crack auto o manuale; il **crack manuale resta
  possibile solo sui file ancora bloccati** (409 su file già craccato);
  **timestamp** sui run (`started_at`/`finished_at` ora esposti dall'API e
  mostrati nei log) e sugli eventi live (`ts` del bus).
- **P7 GUI: palette neutra + pannelli resizable + log comandi + dashboard utile**:
  superfici **neutre dark** (`ink/panel/edge`) con verdi solo come accent;
  terminale con **palette ANSI Linux-console/Debian** (nero, 16 colori classici)
  e PS1 *debian user*; **handle di drag** per albero/colonne, altezza terminale e
  larghezza log; pannello log con tab **live / comandi** (tutti i run,
  newest-first, output espandibile con i comandi eseguiti); **dashboard** con
  strip attivi/risolti/flag/bloccati, **solve rate %**, pannello warn "in stallo —
  serve una password (crack)" cliccabile sui progetti, badge `▣N` sui bloccati in
  history, analytics limitata agli ultimi 20 progetti; logo `$_`; `tree` in
  immagine; fix report "…" (tt + try/catch alla build).
- **P6 GUI overhaul + i18n**: look "terminal" end-to-end (tema fosforo scuro,
  mono, prompt); default **inglese** con switch **EN/IT** anytime (persistito in
  `localStorage`, tutto i18n via `src/i18n.js`); **report** scaricabile con
  **selettore lingua** indipendente dalla UI; flag con catena solver, password
  con **`via <wordlist>`** (attribuzione dal backend), route ASCII, live log,
  history stile `ls -la`. Build frontend multi-stage invariata (`vite build`).
- **P5 image repair**: `image-repair` (BMP: header standard se offset/DIB
  corrotti + altezza ricalcolata dai dati; JPEG: EOI mancante). Risolve
  *tunn3l v1s10n* reale; unit test puri + regressione E2E #17.
- **Cracking con attribuzione wordlist**: il craccatore procede **per wordlist**
  (smallest→largest) e il Finding password espone **quale lista ha craccato**
  (`context`, es. `10k-most-common.txt`); E2E #18 la asserisce.
- **P1 pulizia**: dedup **rot13** (`VGF{..}` vs `ITS{..}`, preferisce il prefisso
  noto), frammenti (`CTF{..}` dentro `picoCTF{..}`), varianti con spazi e note
  `password required` duplicate (anche all'avvio sui progetti vecchi). GUI:
  **filtro** nell'albero, **copia-flag 1-click**.
- **P2 analyzer**: `png-repair` (firma/chunk/CRC → PNG valido), `qr` (`zbarimg`),
  `wav-lsb` (bit LSB dei campioni), `pcap` (`tshark`: protocolli, campi HTTP/DNS,
  export oggetti). `MAX_DEPTH` configurabile.
- **P3 sicurezza/ops**: `API_KEY` (env `STEGSUITE_API_KEY`) su API **e** WebSocket
  (header o `?key=`; GUI via `localStorage`), **cap upload** (`MAX_UPLOAD`, 413),
  **semaforo tool pesanti** (`HEAVY_TOOLS`).
- **P4 packaging**: `package-lock.json` + `npm ci` in Dockerfile e CI.
- **GUI**: terminale e **live log affiancati in basso**; colonna destra a tutta
  altezza; icone SVG; albero comprimibile raggruppato per tool e **colorato**
  (verde=percorso flag, bianco=adiacente, grigio=morta); report flag-centrico.
- **Robustezza**: tipo da `file` per il piano (estensione che mente), SQLite
  **WAL + busy_timeout** + commit per-tool (niente `database is locked`), orfani
  `running` → `error` al restart, fuzzy solo su OCR/vision, body flag validato.
- **Test/Docs**: regressione **24/24**, reali **12/12**, `verify_flags` **ALL
  CORRECT**, `pytest` **107**, UI smoke (`./ctf ui-smoke`), `docs/CHALLENGES.md`.

## Prossima sessione (in ordine)

### A. Analyzer (P2) — ✅ completata
- [x] **JPEG/BMP height repair** — *tunn3l v1s10n*: `image-repair` ripristina
  header BMP standard (offset 54, DIB 40) quando i campi sono corrotti (`ba d0…`)
  e ricalcola l'altezza dai dati; JPEG: riattacca EOI mancante. Verificato sulla
  challenge reale (1134×850, flag via OCR/vision) + caso regressione #17.
- [x] **DNS tunneling** (*ExtractionD'ADNs*): nell'analyzer `pcap`, le euristiche
  base-domain / posizione-etichetta ricompongono i chunk (dedup, ordine pacchetti)
  e provano base32/base64 con gate di printable; flag poi presa dalla flag hunt.
  Unit (7) + regressione E2E #18 (pcap DNS sintetico).
3. [x] **TLS/pcap con chiave** (*WebNet0/1*): l'analyzer `pcap` rileva un file
   con `PRIVATE KEY` (o un keylog `CLIENT_RANDOM`) accanto al pcap e passa a
   tshark `tls.keys_list` / `tls.keylog_file`; estrae l'HTTP decifrato
   (header custom come `Pico-Flag`) e fa `--export-objects` (WebNet1: la flag è
   nei metadati del JPEG scaricato). Verificato su entrambe le challenge reali.
4. [x] **SSTV** (*m00nwalk*): analyzer `sstv` senza dipendenze esterne — demod
   FM (band-pass + Hilbert) → sync pulse → riconoscimento modo dallo spacing →
   ricostruzione RGB. Supporta **Scottie S1/S2**, verificato sul `message.wav`
   reale (frame identico a QSSTV); OCR testo capovolto/rumoroso = limite noto.
5. [x] **Fast-path archivi annidati** (*like1000*): analyzer `nested-archive`
   segue in-process catene tar/zip/gz/bz2/xz ignorando i sidecar non-archivio
   (`filler.txt`), in un solo run, e restituisce solo il payload finale come
   figlio → niente più dipendenza da `MAX_DEPTH` né tool pesanti per livello.
   Verificato su **like1000 reale** (1000 tar → `flag.png`).
6. [x] **rot13/url inline** nella flag hunt: oltre a b64/hex inline, ora la
   flag hunt prova una vista **percent-decoded** (flag `%7B…%7D`) e cerca i
   **twin rot13** dei prefissi noti (`VGF{…}` → `ITS{…}`) anche sulle sorgenti
   rumorose dove il pattern generico è disattivato.

### B. Sicurezza / Ops (P3) — ✅ completata
7. [x] **Rate limiting** sulle API: token bucket per IP, opt-in
   (`RATE_LIMIT_RPM`/`RATE_LIMIT_BURST`), health mai throttlato, `Retry-After`.
8. [x] **Alembic** per le migrazioni: `app/backend/migrations/` (revisioni
   `0001` baseline, `0002` `finding.context`); `init_db()` fa `upgrade head` e
   **stampa** i DB pre-Alembic (`_legacy_revision`). `_migrate()` rimosso.
9. [x] **Retention** opzionale: `RETENTION_DAYS` (0 = mai) elimina i progetti
   più vecchi all'avvio, DB + filesystem (`backend/retention.py`).

### C. GUI (rifiniture P1 residue) — ✅ completata
10. [x] **Barra di progresso** per file: l'orchestratore emette `total` (oltre a
    `processed`) negli eventi `file`/`progress`; la vista progetto mostra una
    barra live (file corrente + %). **Toast** globali (`toast.js` +
    `components/Toasts.vue`) per errori/successi (crack, copie, delete).
    **Upload con progress** via XHR (`api.uploadFile`).
11. [x] **Copia tutte le flag** (bottone nel pannello findings) + export report
    `.md` (già presente, per-file e progettuale).
12. [x] **Layout responsive/mobile**: sotto i 900px la vista progetto mostra un
    pannello alla volta (files/detail/panel) con selettore; separatori nascosti,
    modali e header adattati a 320px.

### D. Test & qualita (P0 residuo) — ✅ completata
13. [x] **pytest** ampliato: migrazioni/retention, nested-archive, sstv, guardia
    OCR, url/rot13, discovery chiave TLS; più uno **smoke test della UI** con un
    browser headless (`app/tests/ui_smoke.mjs` + `./ctf ui-smoke`).
14. [x] **Fixture reali** committate: `app/tests/fixtures/webnet0/` (pcap+chiave,
    ~15 KB) + caso di regressione `tls-pcap` (decifra TLS e legge la flag).
15. [x] **OCR italiano**: `tesseract-ocr-ita` nell'immagine; `OCR_LANGS`
    (`eng+ita` nel container, fallback `eng` se il pack manca).

### E. Packaging (P4) — ✅ completata
16. [x] **Screenshot** nel README (EN/IT): `docs/screenshots/` (home, progetto
    risolto, mobile) catturati con Chromium headless.
17. [x] **`./ctf`**: comandi `urls` (URL di tutti i servizi, porte da `.env`) e
    `open <servizio>` (apre dashboard/StegSuite/docs/reports nel browser).
18. [x] **Base image**: si mantiene l'immagine **AperiSolve pinnata per digest**
    (MIT): ci dà tutto il toolset stego e resta riproducibile. Una base propria
    non aggiunge valore oggi (manutenzione in più); si rivaluta solo se cambia il
    toolset. Nessun cambio.

### F. Cracking — ✅ completata
19. [x] **Upload wordlist** (`POST /api/v1/wordlists`, salvata in `/data/wordlists`
    persistente) + bottone in GUI; **scelta per-item persistente** del file
    bloccato (localStorage per progetto+file).
20. [x] **`bkcrack`** (ZipCrypto known-plaintext, binario precompilato v1.8.1
    nell'immagine; attacco via payload `bkcrack` della crack API → decifra ed
    estrae) + **rules/mask + budget CPU** per hashcat (`HASHCAT_RULES`,
    `CRACK_BUDGET_S`, e per-richiesta `rules`/`mask`/`budget_s`).

### G. Challenge difficili (verifica con soluzione) — chiusa (limiti documentati)
- [x] **St3g0** (2022, `pico.flag.png`) → **PASS** `picoCTF{7h3r3_15_n0_5p00n_96ae0ac1}`.
  Aggiunta a `CASES` di `app/tests/real_challenges.py` (B22) e a `docs/CHALLENGES.md`.
- [x] **tunn3l v1s10n** (2021, `tunn3l_v1s10n`) → `image-repair` OK; `ocr` legge
  `picoCTF{quit3_a_v13w_2020}` (near-miss `1`→`i`, il vero è `...qu1t3...`).
  Decodifica corretta, solo un char OCR. **Decisione: accettato come limite**
  (niente sostituzioni `1↔i` rischiose). Bonus perf: analisi da >440s a **~81s**.
- [x] **like1000** (2019, `1000.tar`) → **PASS strutturale**: `nested-archive`
  apre i 1000 tar in un colpo e raggiunge `flag.png`; OCR near-miss `0/O`, `5/S`.
- [x] **m00nwalk** (2019, `message.wav`) → **decodifica OK** (`sstv`, Scottie S1,
  frame identico a QSSTV); OCR near-miss: testo capovolto in un frame rumoroso.
- [x] **c0rrupt** (2019, `mystery`) → PNG riparato (visibile a un umano:
  `picoCTF{c0rrupt10n_1847995}`) ma l'OCR non lo legge (rumore rosso). **Limite
  accettato.**
- [x] **Very very very Hidden** (2021, `try_me.pcap`) → **RISOLTA**: il `pcap`
  esporta `evil_duck.png`, che usa **Invoke-PSImage** (1 byte/pixel nei 4 LSB di
  B/G); l'analyzer `psimage` estrae la "mappa" PowerShell e lo **XOR delle due
  stringhe** produce la flag → test reale.
- [x] Correzione OCR `1↔i/l`, `0↔o`, `5↔s`: **decisione = accettarla come limite**
  (troppo rischiosa: corromperebbe flag reali). Chi si trova vicino al flag lo
  legge dal contesto/report.

## Gap challenge noti
Vedi `docs/CHALLENGES.md` → "Altri casi provati": **c0rrupt** (PNG repair
presente, flag visiva non OCR-abile), **Surfing the Waves** (WAV: mapping
custom), **tunn3l v1s10n** e **like1000** (risolte strutturalmente, resta il
near-miss OCR).

## Limiti noti
- Flag **visive** via OCR (buono, non perfetto; alcune immagini rumorose non
  vengono lette, es. `c0rrupt`).
- AES su **CPU** ~17k H/s → rockyou intera ≈ 14 min (no GPU).
- `picoctf.net` non risolve da qui → mirror GitHub (HHousen/PicoCTF-*).
- Flag **per-istanza** su alcune challenge: verificare artifact-per-artifact
  (`verify_flags.py`), non confrontare writeup diversi.

## File chiave
```
app/backend/main.py            # app factory + startup (reconcile + dedupe + retention)
app/backend/migrations/        # Alembic (env.py + revisioni 0001/0002)
app/backend/retention.py       # cancellazione progetti oltre RETENTION_DAYS
app/backend/api/*.py           # router: system, projects, analysis, tools, cracking, ws
app/backend/orchestrator.py    # ricorsione + auto-crack + flag hunt + semaforo
app/backend/cracking.py        # hashcat/stegseek/pdfcrack/fcrackzip
app/backend/analyzers/*.py     # 42 tool (un file, auto-registered)
app/frontend/                  # GUI Vue 3 (+ package-lock.json)
app/frontend/src/toast.js      # store toast globale
app/frontend/src/components/Toasts.vue  # rendering toast
app/tests/ctf_regression.py    # 24/24 (incl. image-repair, dns-tunnel, nested-archive, sstv, tls-pcap, openstego, psimage, office)
app/tests/real_challenges.py   # 12/12 picoCTF (incl. WebNet0/1: pcap+TLS key; Very very very Hidden, MacroHard WeakEdge)
app/tests/verify_flags.py      # verifica per-istanza (ALL CORRECT)
app/tests/ui_smoke.mjs         # smoke test UI (Playwright/Chromium) + ui_smoke.sh
app/tests/fixtures/            # challenge.png + webnet0/{capture.pcap, picopico.key}
app/tests/*.py                 # unit pytest (107)
docs/ADDING-A-TOOL.md, docs/API.md, docs/CHALLENGES.md
.github/workflows/ci.yml       # CI
compose.yaml                   # servizio stegsuite (19014)
```
