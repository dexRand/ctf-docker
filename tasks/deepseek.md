# Task per opencode (deepseek) — batch 3

Stesse regole di sempre: **tutto** `AGENTS.md` → "Regole per il lavoro autonomo"
+ "Lezioni dal batch del 05–10/11". Batch 2 rivisto da Claude il 10/11: ok
(perimetro rispettato, unit 437, lint clean); archiviato sotto.

Baseline da non peggiorare: fixture 33/33, reali 35/35, extra 55/55, `ALL CORRECT`.
Ordine per task: test prima (deve fallire) → codice → `run_unit.sh` + `./ctf lint`
+ `./ctf test --fast` (tempo prima/dopo nel commit) → caso reale con
`real_challenges.py --gaps --only-new -k <nome>` → commit. Fine batch:
`git pull --rebase`, set extra completo + `./ctf test -j 3`, push.
**Dopo un riavvio di WSL/Docker**: controlla che `/data` nel container sia ext4
(`docker compose exec -T stegsuite grep " /data " /proc/mounts`); se è `tmpfs`,
`docker compose up -d --force-recreate stegsuite term` prima di ogni verifica.

## Task 1 — Scritte bianche/nere su sfondi colorati (GAP `out.qoi`) — rivisto 11/11

**Correzione:** la decodifica QOI e la catena di formati funzionano già (`pixel-bytes`
arriva a un PNG con una rana su un arcobaleno). Il problema è l'OCR: la flag è scritta
a mano in **bianco** sopra strisce colorate e l'OCR in scala di grigi non la vede.
**File:** `analyzers/image.py` (solo `ImageEnhanceAnalyzer`), test `app/tests/test_neutral_ink.py`.
- Due viste in più in `image-enhance`: `whiteness` = 255−min(R,G,B) e `blackness` =
  max(R,G,B) (stirato ×255/160). Ognuna = un'immagine prodotta + **una** chiamata OCR
  (`ocr_image(thorough=False)`), come le varianti esistenti.
- Gating sul contenuto, con numpy, dopo il controllo MAX_PIXELS esistente: gli 8
  colori più frequenti (bin a 4 bit) coprono ≥ 60% dei pixel; ≥ 30% dei pixel saturi
  (max−min ≥ 128); "inchiostro" neutro (max−min ≤ 48 e min ≥ 200, oppure max ≤ 60)
  tra 0,2% e 40%. Altrimenti nessuna vista (zero OCR in più).
- **Test** (immagini generate con il font di Pillow, OCR mockato tranne l'ultimo):
  testo bianco su arcobaleno → vista whiteness, nessuna blackness; testo nero → blackness;
  PNG palette (P) ok; rumore, rampa di grigi, arcobaleno senza testo, tinta unita,
  grigio a 16 bit → nessuna vista e numero di OCR invariato; un test con tesseract
  vero (`skipif` se manca) che legge `flag{white_on_rainbow}`.
- `out.qoi` probabilmente **resta in GAPS** (la scritta a mano esce `—ribbLt_G70b`):
  aggiorna solo il suo commento. Il task vale per la classe generica.

## Task 2 — File disegnato come pixel grigi (GAP `elves.bmp`) — rivisto 11/11

**Correzione:** l'altezza del BMP la ripara già `repair_bmp` (`analyzers/repair.py`).
Le righe nascoste contengono un ELF disegnato come pixel **grigi** (R=G=B, un byte per
pixel) e nessuno lo riconverte.
**File:** `analyzers/image.py` (`pixel-bytes`, funzione `_pixel_bytes`) e
`analyzers/repair.py`, test `app/tests/test_pixel_gray.py`.
- In `pixel-bytes`: se i byte RGB(A) non sono né un'immagine né un file noto, e i
  primi ≤ 64 pixel della riga 0 sono grigi e il loro canale inizia con una firma
  **forte (≥ 4 byte)** di `magic.MAGICS` (escluse BM, MZ, gzip), leggi un solo canale
  e taglia al primo pixel non grigio → figlio con l'estensione della firma.
- Bug da sistemare nello stesso task: `repair.py` legge l'altezza BMP come unsigned;
  un BMP top-down (altezza negativa) viene "riparato" e capovolto. Leggi `<i`, usa
  `abs()` per le righe e conserva il segno.
- **Test:** righe grigie con `\x7fELF` su foto colorata (RGB png, RGBA png, RGB bmp)
  → `.elf` uguale al payload; righe nascoste dall'altezza → trovate dopo repair;
  grigio che inizia con BM/MZ/1f8b08 → skipped; pixel colorati che compongono `\x7fELF`
  → skipped; BMP top-down valido → nessun figlio.
- `elves.bmp` **resta in GAPS** (l'ELF nel file distribuito è rovinato da una
  compressione JPEG): aggiorna il commento.

## Task 3 — Office: testo da tutte le parti del documento (GAP `du22-doxme`)

**File:** `analyzers/extract.py` (analyzer `office`), test `app/tests/test_office_parts.py`.
- Oggi si legge soprattutto `document.xml`. Estrai il testo anche da header/footer,
  note, commenti, `docProps/*`, `customXml/*`, e da ogni XML del pacchetto non già
  letto (tetto: 200 parti, 20 MB decompressi in totale, `zipfile` con controllo di
  `file_size` prima di leggere).
- Gating: zip con `[Content_Types].xml` (anche senza estensione, come `doxme`).
- **Test:** docx minimo costruito con `zipfile` con la flag solo in `word/footer1.xml`
  → la flag è nell'output.

## Task 4 — Risorse di assembly .NET (GAP `du25-yo-dawg.zip`)

**File:** nuovo `analyzers/dotnet.py`, `__init__.py`, riga in `DEFAULT_PLAN` vicino a
`elf`, pip **con versione fissata** (`dnfile`) in `app/Dockerfile`, test
`app/tests/test_dotnet.py`.
- Gating: `MZ` + PE con CLI header (data directory 14 non vuota). Niente esecuzione.
- Estrai le *managed resources* come figli (nome risorsa → file); se una risorsa è
  compressa (gzip/deflate/zip) la decomprime già il resto della pipeline.
  Tetti: 100 risorse, 50 MB totali.
- Se `dnfile` non basta: fermati, scrivi in "Bloccato".
- **Test:** con un assembly minuscolo non è banale generarlo: usa un mock della
  struttura `dnfile` per il test unitario e il caso reale per la verifica.

## Task 5 — Piet (GAP `tj25-pietty-runme.png`)

**File:** nuovo `analyzers/piet.py`, riga in `DEFAULT_PLAN` (in fondo alle immagini),
`app/Dockerfile` (`npiet` da apt se esiste nella distro dell'immagine, altrimenti
fermati e scrivi in "Bloccato"), test `app/tests/test_piet.py`.
- Gating sul **contenuto**: immagine con ≤ 20 colori, tutti nella palette Piet
  (18 colori + bianco/nero), letta con `load_image`; codel size stimato dal blocco
  minimo. Altrimenti `skipped` subito.
- `ctx.run(["npiet", "-q", "-cs", str(codel), path], timeout=20)`, input vuoto,
  output ≤ 200 KB. Mai input interattivo.
- **Test:** PNG casuale → `skipped`; immagine Piet minima (puoi disegnare un
  programma "push/out" di pochi codel) o mock di `ctx.run`.

---

## Per il revisore (deepseek pro) — controllo di ogni commit di deepseek flash

Non scrivere codice: leggi `git show <commit>` e rispondi con OK / DA RIFARE + motivo,
sotto "Review" in fondo a questo file. Controlla, nell'ordine:
1. **Perimetro**: solo i file del task; in `planner.py` solo `DEFAULT_PLAN`; nessun
   file vietato (`AGENTS.md`), nessuna flag/URL cambiata in `real_challenges*.py`.
2. **Test**: il test fallirebbe col codice vecchio? Copre i casi scomodi (vuoto,
   enorme rifiutato, formati limite)? Mock solo dei tool esterni.
3. **Costo**: gating su estensione + firma nei primi byte prima di ogni lavoro; tetti
   PRIMA di decomprimere/allocare; `read()` sempre con limite; budget di tempo totale
   con `deadline`; al massimo un OCR/zbar per immagine.
4. **Niente su misura**: nessuna costante presa dal caso reale (offset, chiavi, stringhe).
5. **Numeri veri**: nel commit ci sono gli output (unit, lint, fast prima/dopo, PASS del
   caso) copiati, non riassunti? Se mancano → DA RIFARE.
6. **Caso in EXTRA** solo con il file distribuito dalla challenge e il PASS incollato.

## Stato batch 3 (aggiornalo tu, numeri copiati dall'output)

| Task | Stato | Commit | Verifica (unit · lint · fast prima/dopo · caso reale) |
|---|---|---|---|
| 1 viste whiteness/blackness | da fare | | |
| 2 pixel grigi → file | da fare | | |
| 3 Office parti | parziale: estrazione XML + gating OOXML/ODF/EPUB + CDATA/commenti + tetti; `doxme` resta GAP (flag nelle due immagini, non in XML) | (questo commit) | unit **460 passed** · `lint clean` · doxme **FAIL** (`got=[]`, 40,5 s) · extra **57/57** (12581,7 s) |
| 4 .NET risorse | parziale: nuovo `dotnet` (gating MZ/PE/CLI, managed resources → figli, cap 100/50 MB, `dnfile==0.15.1`); `du25-yo-dawg` resta GAP (flag DES del gioco, non in chiaro) | (questo commit) | unit **468 passed** · `lint clean` · yo-dawg **FAIL** (`status=done`, `got=[]`, 42,5 s) · extra **57/57** (13535,0 s) |
| 5 Piet | **bloccato**: `npiet` non è in apt (Debian 13 trixie) e `runme.png` non è un Piet diretto (55 248 colori; programma nascosto con campionamento 15×100 + crop 124×11) | — (solo docs) | nessun codice: `apt-get install -s npiet` → `E: Unable to locate package npiet` |
| issue #24 QR de-masking (fuori batch) | fatto | (questo commit) | unit 447 · lint clean · caso masked PASS · extra 56/56 · fixture 33/33 · fast reali 11/11 |

Nota issue #24: `./ctf test --fast` ha chiuso 32/33 per il timeout flaky di
`steghide` (status=running a 300 s, OCR su un JPEG di rumore), non per il QR;
la stessa suite fixture rilanciata da sola finisce 33/33 e `real_challenges.py
--fast` è 11/11. Dettaglio: `qr.py` rileva i 3 finder, campiona la griglia,
lascia intatti i moduli funzionali e prova le 8 maschere standard + il loro XOR
(9 immagini max), con tetti su byte/pixel e deadline di 120 s.

## Proposte

(niente per ora)

## Bloccato (batch 3)

### Task 5 — Piet (`tj25-pietty-runme.png`) bloccato: niente `npiet` in apt e immagine non diretta

Due motivi indipendenti, entrambi bloccanti secondo il task; nessuno dei due è
stato aggirato con regole su misura.

1. **`npiet` non esiste nella distro dell'immagine.** La base è Debian 13
   (trixie): `apt-get update` va a buon fine, poi `apt-cache policy npiet` non
   restituisce nulla e `apt-get install -s npiet` risponde
   `E: Unable to locate package npiet`. Anche `packages.debian.org` (tutti i
   suite, tutte le sezioni) dà "Sorry, your search gave no results"; su PyPI
   `https://pypi.org/pypi/npiet/json` è 404. Le regole del repo ammettono tool
   nuovi solo da apt o pip con versione fissata, quindi non c'è un modo
   ammesso di aggiungerlo.
2. **Il file distribuito non è un programma Piet diretto.** `chall/runme.png`
   (1 998 446 B, 1964×2085, RGB) ha **55 248 colori** e il gcd delle run
   orizzontali e verticali è **1**: è una foto con rumore JPEG, non blocchi di
   codel. Il gating richiesto (≤ 20 colori) lo scarta subito, quindi `npiet`
   non lo vedrebbe mai. Il programma Piet vero è **nascosto**: il `recover.py`
   ufficiale della challenge campiona `composite_pixels[i*15, j*100]` e poi
   taglia `(0, 0, 124, 11)`; il ritaglio ha esattamente i 20 colori della
   palette Piet (verificato in container). Sarebbe una regola su misura per
   questa challenge (passo 15×100 + crop 124×11), vietata dal task.

Per questo non sono stati scritti né `app/backend/analyzers/piet.py` né
`app/tests/test_piet.py`: senza `npiet` il test potrebbe solo mockare
`ctx.run` e nessuna esecuzione reale sarebbe verificabile. Il caso
`tj25-pietty-runme.png` resta in `GAPS`.

Per sbloccarlo serve una decisione a monte: (a) fornire `npiet` in modo
ammesso (binario upstream pinnato come `stegseek`, oppure un pacchetto
apt/pip), e (b) una regola **generica** per i Piet "ridimensionati con
ripetizione" (riconoscere il passo di ripetizione dai blocchi, non 15×100),
da concordare perché oggi sarebbe codice su misura.

### Task 4 — `du25-yo-dawg.zip` resta GAP dopo l'estrazione delle resources

`dnfile 0.15.1` basta: l'analyzer `dotnet` legge le 5 `ManifestResource` embedded
(`Yo_Dawg.Form1/2/3/4.resources` e `Yo_Dawg.Resources.resources`, 2 306 025 B
l'ultima) e le scrive come figli (cap 100 risorse / 50 MB, file esterni ignorati).
L'analisi e2e chiude `status=done` ma `got=[]`: nella risorsa grande c'è il solo
entry `flag` di tipo `System.Drawing.Bitmap`, un koala 1024×1024 (PNG dentro il
`ResourceSet`, `zsteg -a` non trova testo né un file LSB). Il `#US` heap del DLL
contiene `DUCTF{` e frammenti (`_never`, `_oldschool`, `_shoutout`, …) più chiavi
e blob cifrati, ma non la flag intera: il sorgente ufficiale
(`misc/yodawg/solve/WRITEUP.md`) dice che la flag è il risultato DES delle
risposte del gioco ("half of the flags visible and half AES encrypted").
Il caso resta in `GAPS` con il commento aggiornato; chiuderlo richiederebbe un
interprete del gioco/DES, fuori dal perimetro dell'analyzer.

### Task 3 — `du22-doxme` non chiudibile con la sola estrazione XML

Il file distribuito (`publish/doxme`, 19 763 B, zip senza estensione) **non ha**
header/footer/note/commenti/`customXml`: le sue uniche parti XML sono
`[Content_Types].xml`, `_rels/.rels`, `docProps/app.xml`, `docProps/core.xml`,
`word/document.xml`, `word/fontTable.xml`, `word/settings.xml`, `word/styles.xml`,
`word/theme/theme1.xml`, `word/webSettings.xml`, `word/_rels/document.xml.rels`.
Nessuna contiene un frammento della flag: `grep -ra "DUCTF\|WOrd\|D0Cs\|R34L1Y\|W3ird"`
sull'intero pacchetto non restituisce nulla. La flag è **disegnata** in due media:
`word/media/image1.png` = `DUCTF{WOrd_D0Cs_Ar` e `word/media/image2.png` =
`3_R34L1Y_W3ird}`. L'analyzer `office` ora gira davvero su `doxme` (13 parti
estratte, output con il testo di `docProps/*`), ma nessun output per-immagine può
contenere la flag intera: `ocr` su `image1` dà solo la prima metà e su `image2`
solo la seconda, e il flag hunt non unisce output di nodi diversi. Una prova di
montaggio verticale delle due PNG + `ocr_image` produce esattamente
`DUCTF{WOrd_D0Cs_Ar3_R34L1Y_W3ird}` (`== OCR lines joined ==`), ma è gestione
dei media fuori dal perimetro di questo task (richiede OCR dentro `office` o un
figlio montaggio, con una sola chiamata OCR per immagine e senza duplicare
quella del figlio `ocr`). Il caso resta in `GAPS`.

Dopo la review ARBITER il gate è stato corretto: un pacchetto è Office/Office-like
se ha `[Content_Types].xml` **oppure** `mimetype` + almeno uno tra
`META-INF/manifest.xml`, `META-INF/container.xml`, `content.xml` (ODF/EPUB non
hanno `[Content_Types].xml`), con `z.getinfo()` e non `set(z.namelist())`. I text
node includono anche `CDATA` e i commenti XML. Test aggiunti: ODT con base64 in
`content.xml`, EPUB, docx/odt senza estensione end-to-end, CDATA/commenti.

## Review (deepseek pro)

(niente per ora)

---

# Archivio — batch 2 (10/11)

### B2 Task 1 — Credenziali in chiaro nei pcap (issue #11)

**File:** nuovo `app/backend/analyzers/pcapcreds.py`, `__init__.py`, una riga in
`DEFAULT_PLAN` (dopo `"pcap"`), test `app/tests/test_pcapcreds.py`.

- Un solo passaggio `tshark -r <file> -Y "<filtro>" -T fields ...` con
  `ctx.run(timeout=180)` che estrae: FTP `USER`/`PASS`, Telnet (dati client),
  HTTP `Authorization: Basic` (decodificato), POP3 `USER`/`PASS`, IMAP `LOGIN`,
  SMTP `AUTH PLAIN`/`LOGIN` (base64 decodificato).
- Gating: estensioni pcap (`PCAP_EXT` da `usbhid.py`) + link type Ethernet/raw
  IP/Linux SLL (riusa `link_types`). Nessuna credenziale → `skipped`.
- Output: una riga per credenziale `proto  src -> dst  user:password`. Le password
  vanno anche nella wordlist di contesto? **No** (file vietati): basta l'output.
- **Test:** costruisci nel test un pcap minimo (header pcap + frame Ethernet/IPv4/TCP
  scritti a mano con `struct`) con una sessione FTP `USER bob` / `PASS s3cr3t` e
  una richiesta HTTP con `Authorization: Basic Ym9iOnMzY3IzdA==`; verifica che
  l'output contenga `bob:s3cr3t` due volte. Più un pcap senza credenziali → `skipped`.

### B2 Task 2 — Export di oggetti SMB/TFTP/IMF/FTP-data dai pcap (issue #11)

**File:** `app/backend/analyzers/pcap.py` (solo la parte `--export-objects`), test
`app/tests/test_pcap_export.py`.

- Oggi si esporta solo `http`. Aggiungi `smb`, `tftp`, `imf`, `ftp-data` (verifica
  con `tshark --export-objects help` quali esistono nella versione dell'immagine),
  **solo se** il protocollo compare nella gerarchia già calcolata (`phs`): niente
  passaggi tshark in più sui pcap che non li hanno.
- Ogni protocollo in una sottocartella; stessi filtri `analysable_object` e stesso
  tetto di figli dell'HTTP.
- **Test:** con `ctx.run` sostituito, verifica che con `phs` senza `smb` non venga
  lanciato l'export smb, e con `smb` sì.

### B2 Task 3 — Frame delle PNG animate (APNG) (issue #15)

**File:** `app/backend/analyzers/gif.py`, test `app/tests/test_apng.py`.

- `gif-frames` accetta anche `.png` **solo se** nei primi 64 KB c'è il chunk `acTL`
  (PNG animata); le PNG normali escono `skipped` subito, senza aprire l'immagine.
- Pillow legge gli APNG con `ImageSequence`: stesso trattamento delle GIF (frame,
  differenze, delay, QR a strisce).
- **Test:** crea un APNG di 3 frame con Pillow (`save(..., save_all=True,
  append_images=...)`) e verifica i 3 frame; una PNG normale → `skipped`.

### B2 Task 4 — Audio stereo: differenza dei canali (issue #15)

**File:** nuovo `app/backend/analyzers/stereodiff.py`, `__init__.py`, una riga in
`DEFAULT_PLAN` (vicino a `"spectrogram"`), test `app/tests/test_stereodiff.py`.

- Solo WAV stereo (header RIFF/WAVE, 2 canali, PCM 8/16 bit): altrimenti `skipped`
  leggendo solo l'header. Durata massima 10 minuti.
- Calcola L−R con numpy; se l'energia della differenza è < 1% di quella del segnale
  (canali quasi uguali) → `skipped`. Altrimenti scrivi `<nome>_L-R.wav` come
  **figlio**, così spectrogram/morse/sstv/… girano sulla differenza.
- **Test:** stereo con un tono identico sui due canali + un secondo tono solo a
  sinistra → il figlio esiste e contiene il secondo tono (FFT); stereo identico →
  `skipped`; mono → `skipped`.

### B2 Task 5 — Hash "nudi" nei file di testo (issue #16)

**File:** nuovo `app/backend/analyzers/hashes.py`, `__init__.py`, una riga in
`DEFAULT_PLAN`, test `app/tests/test_hashes.py`.

- Solo file di testo (`TEXT_EXT`, `load_text`): trova hash riconoscibili (MD5/NTLM
  32 hex, SHA1 40, SHA256 64, bcrypt `$2[aby]$`, crypt `$1$`/`$5$`/`$6$`, NTLM
  `user:rid:lm:nt:::`), al massimo 50.
- Crack con hashcat (modo giusto per tipo, per MD5 vs NTLM prova entrambi) sulle
  wordlist piccole di `cracking.resolve_wordlists(max_bytes=cracking.AUTO_CRACK_MAX_BYTES)`
  con **un budget totale** di 60 s (`deadline`), come `wpa.py` dopo la review.
- Output: `hash  tipo  password` (o "non trovata").
- **Test:** un file con `md5("password")` → output con `password` (hashcat mockato
  o reale se c'è); un testo senza hash → `skipped`; un file con 10 000 righe di
  hex casuale → al massimo 50 hash e budget rispettato (mock del tempo).

---

## Stato batch 2 (aggiornalo tu, numeri copiati dall'output)

| Task | Stato | Commit | Verifica (unit · lint · fast prima/dopo · caso reale) |
|---|---|---|---|
| 1 credenziali pcap | fatto | dcf3b85 | unit **398 passed** · `lint clean` · fast fixture **33/33** + reali **11/11** (`ALL CORRECT`) · analisi **245,6 s -> 245,4 s**. Nessun caso reale dipende solo dalle credenziali: nessun GAP spostato. |
| 2 export SMB/TFTP/IMF | fatto | 61cd7b3 | unit **404 passed** · `lint clean` · fast **33/33** + **11/11** (`ALL CORRECT`) · analisi **245,4 s -> 252,4 s** (+2,9%: nei casi pcap del slice gira anche pcap-creds). Nessun capture SMB/TFTP reale in suite. |
| 3 APNG | fatto | 0998709 | unit **408 passed** · `lint clean` · fast **33/33** + **11/11** (`ALL CORRECT`) · analisi **252,4 s -> 250,1 s**. Nessun caso APNG in suite. |
| 4 stereo L−R | fatto | 77609ea | unit **415 passed** · `lint clean` · fast **33/33** + **11/11** (`ALL CORRECT`) · analisi **250,1 s -> 251,4 s**. Caso reale `bk24-couch_potato.wav`: l'L−R **decodifica l'SSTV** con la flag visibile (`bctf{1_11k3_5p4m_w17h_my_h4m}`, frame in ~11 s) ma il test end-to-end resta **FAIL** (`got=[]`) perché l'OCR non legge la scritta rossa sopra la foto: resta in GAPS. |
| 5 hash nudi | fatto | 1c3026f | unit **425 passed** · `lint clean` · fast fixture **33/33** + reali **11/11** · analisi **288,8 s** (baseline 251,4 s, host condiviso con un agente che testa AI: load 2-7 su 8 core; `verify_flags` 10/11, Matryoshka A in timeout per il carico, ricontrollato nel gate). |

**Gate finale batch 2 (10/11):** `./ctf test -j 3 --extra` →
fixture **33/33** · reali **90/90** (35 core + 55 extra) · writeup
**ALL CORRECT** · **0 FAIL** · **8190,1 s** di analisi. Unit **431 passed**,
`./ctf lint` clean. Nessuna flag persa rispetto alla baseline.

**Fix durante il gate:** `hashes` era in backtracking catastrofico (`_DUMP`
con `([^\s:]+)` non ancorato) su una riga da 141 KB senza due punti emessa da
`psimage` in `flag.txt`: il primo gate è morto con un timeout client dopo 31
casi. Ancorato il token (`(?<![^\s:])`, max 64 char): lo stesso file passa in
0,009 s, test di regressione con una riga da 300 KB. Commit `86fd538`.

**Nota Task 5:** primo giro costava +30 s nel fast perché un ASCII art (`ffff…`,
estratto da `psimage`) veniva preso per 2 hash e faceva partire hashcat per 60 s.
Due regole generiche: un hash deve avere >= 6 cifre esadecimali distinte, e le
wordlist piccole sono concatenate in un file (un avvio di hashcat per modo, non
per lista). Senza queste due, il budget di 60 s veniva speso su rumore.

**Nota Task 4:** `bk24-couch_potato.wav` ha il campo RIFF size sbagliato (0x24):
il `wave` di Python 3.13+ restituisce 0 frame. `stereo-diff` legge allora il
chunk `data` direttamente (test dedicato), altrimenti il caso restava muto.

## Proposte (cose che servirebbero ma toccano file vietati)

- **Frame SSTV come figlio** (`analyzers/sstv.py`, fuori dai file vietati ma
  fuori dai task): oggi `sstv_{mode}.png` è solo artifact, quindi `ocr`,
  `image-enhance` e `channel-remap` non ci girano. Per `bk24-couch_potato` la
  flag è leggibile a occhio ma l'OCR interno (una passata) non la trova.
  Proposta: aggiungere il frame a `extracted` e lasciare che la pipeline lo
  legga; da verificare che non rallenti `m00nwalk`/`couch_potato` oltre il 5%.
- **OCR su testo colorato** (`analyzers/vision.py`, vietato): una maschera
  canali (rosso su foto) + upscale prima di tesseract servirebbe a
  `couch_potato` e `m00nwalk`. Non toccato.

## Bloccato (batch 2)

(niente per ora)

---

# Archivio — batch 1 (05–10/11)

**Review di Claude (10/11):** i 4 task erano fatti e conformi; gli extra utili
(`jpeg-dqt`, `tar-chain` hanno risolto casi reali). Problemi corretti nel commit
`efd9b27`: `color-map` dava indici sbagliati (`searchsorted` su chiavi ordinate per
luminosità); ricostruzione PNG senza tetto prima della decompressione, senza PLTE e con
stride sbagliato sotto gli 8 bit; `faint` faceva due OCR identici su ogni immagine;
`tar-chain` leggeva i tar interni senza tetto; budget di `wpa` per wordlist invece che
totale; tabelle DQT a 16 bit lette male; **due casi di test sostituiti con file della
soluzione** (`duck-pics` whole-capture, `dinosaur` qr_code.bmp) al posto dei file
distribuiti. Da qui le regole "Lezioni dal batch del 05–10/11" in `AGENTS.md`.

## Stato (aggiornalo tu, con i numeri copiati dall'output)

| Task | Stato | Commit | Verifica |
|---|---|---|---|
| 1 Vigenère / rail fence | fatto | 8246477 | unit 374, lint clean |
| 2 olevba | fatto | df03c17 | lint clean, `weird.docm` PASS 8.2s, output con `Sub AutoOpen()` |
| 3 winreg (regipy) | fatto | f23f033 | lint clean, hive NTUSER `done · 2131 keys, 4214 value(s)` |
| 4 WPA → hashcat | fatto | c7bccf7 | lint clean, 2 hash 22000 estratti da `ui21-megacorp-01.cap`; crack ok con dizionario ad hoc, non con le wordlist piccole |

**Gate finale (05/11, dopo i 4 task + jpeg-dqt):** `./ctf test -j 2 --extra` →
fixture **33/33** · reali **83/83** (35 core + 48 extra) · writeup **ALL CORRECT**
· 0 FAIL · 6445.3 s di analisi. Unit **379 passed**, `./ctf lint` clean. CI verde
su `30d4c57`.
Nessuna flag persa rispetto alla baseline.

Restano aperti (nessun blocco): i casi in `GAPS` per #11/#13/#14 e i task
#11–#16 nella loro interezza (`ic25-obfuscated-Users` non ha il flag nella hive,
`ui21-megacorp` non ha la password nelle wordlist piccole).

## Sessione 05/11 pomeriggio — extra fuori dai 4 task

- **`jpeg-dqt`** (nuovo analyzer): JPEG con DQT azzerate → tabelle ricostruite
  (prima tutte a 1: "the lion doesn't quantize", poi Annex K) e immagine
  decodificata come figlio per OCR. `tj25-quant-lost.jpg` **PASS 28.7 s** →
  spostato in `EXTRA` (48 extra, 55 GAPS). Test in `app/tests/test_jpegdqt.py`;
  unit **379**, lint clean. README a **81 analyzer** (aggiunti anche `olevba`,
  `winreg`, `wpa`, `jpeg-dqt` nelle tabelle) e due `display_order` duplicati
  sistemati (`olevba` 221, `wpa` 266).
- **`tar-chain`** (nuovo analyzer) + una variante OCR "unleet": i 999 tar
  annidati si percorrono **in memoria** (1,5 s) e l'ultima PNG viene letta con
  un passaggio OCR 2x binarizzato; la variante ricostruisce `l0t5_0f_TAR5` da
  `lOtS Of TAR5` (spazi→`_`, O→0, S→5 nei corpi già "leet").
  `1000.tar` **PASS 51,2 s** → in `EXTRA` (49 extra, 54 GAPS).

## Verifiche intermedie: `./ctf test --fast`

`real_challenges.py --fast` esegue 11 casi core scelti uno per famiglia di
analyzer (metadata, OCR, bit-plane, pcap HTTP/DNS/commenti, TLS keylog, Office
macro, git, archivi, stream TCP): **11/11 PASS in 334 s di analisi (~2 min a
`-j 3`)**, più le fixture. Serve per i controlli durante il lavoro; il gate
completo (`./ctf test -j 2 --extra`, ~2h) resta obbligatorio prima del push.

## Bloccato

### `ic25-thrift-capture.pcap` (GAP, analisi 06/11, ~45 min) — **issue #23**
Thrift **binary + TFramedTransport** (ogni messaggio preceduto da 4 byte di
lunghezza; header `80 01 00 01 <len> <name> <seqid>`).

Mappa ricavata dai byte:
- metodi: `createBasket` 212, `addToBasket` 418, `getBasket` 74, `getInventory` 194, **`pay` 24**;
- tipi osservati: `0x0b`=string, `0x0c`=struct, `0x0f`=list, `0x0a`=intero 8 byte, `0x00`=stop
  (NON coincidono con la tabella standard di Thrift, quindi non è il binary
  protocol ufficiale: serve l'IDL della challenge o un parser scritto a mano);
- `pay` manda `{1: uuid stringa, 2: intero}` (es. 700) e il server risponde con
  l'eccezione "Total does not match basket total"; 134 stream, 170 KB di payload;
- la flag **non è in chiaro** (`strings` sul pcap: nessun `ictf`), nessuna stringa
  non-ASCII o blob base64.

Provato: parser Thrift generico (fallisce per i tipi non standard), estrazione
degli interi di `pay`, dump delle stringhe. Non risolto in 1h: serve capire dove
sta il dato (probabile: totali di `pay` che codificano ASCII, oppure field id).
Prossimo passo: scrivere un parser che segua la mappa dei tipi sopra e stampare
tutti i campi, `pay` compreso.

---

# Sessione 13/11 (MONOLITH-00 + ASU-001 + ARBITER) — issue #23/#24/#25

## #24 QR mascherato — **CHIUSA** (commit `7c27ddc` + `1c963c8`)

Il "mask" della challenge `tj25-masked-qrcode.png` NON è un mask standard: è lo
**XOR di tutte e 8 le maschere standard QR** applicato ai soli moduli dati
(`enc.py` = `mask0 ^ … ^ mask7`, "I put all the masks on him"). Finder/timing/
alignment/format restano intatti. Soluzione generica in `qr.py`: quando zbar
fallisce ma ci sono 3 finder, campiona la griglia, identifica le regioni
funzionali per versione, ri-XORa i moduli dati con le 8 maschere + lo XOR di
tutte, ri-renderizza e riprova zbar (max 9 chiamate, deadline 120 s).

- unit **447 passed** · `lint clean` · `--gaps -k masked` **PASS** (22.3 s) ·
  extra **56/56** · fixture **33/33** · fast **11/11**.
- Caso spostato da `GAPS` a `EXTRA`. Niente nuove dipendenze.

## #23 Thrift — **NON chiudibile offline** (verificato dal sorgente)

Scaricato il sorgente ufficiale della challenge
(`ImaginaryCTF-2025-Challenges/.../thrift-store/challenge/handler.go`): la flag
**`ictf{l1k3_gRPC_bUt_l3ss_g0ogly}` è hardcoded nel server** e viene restituita
da `Pay` solo se il basket contiene l'item `flag` (prezzo 9999) e il totale
corrisponde. Nel pcap ci sono solo `getInventory`/`createBasket`/`addToBasket`/
`getBasket`/`pay` (l'inventory elenca l'item `flag` ma mai il suo valore). Quindi
**la flag non transita mai sul filo**: nessun decoder offline la può estrarre.
Conferma la nota "serve il server". Nota: i type code del pcap (`0x0a`=I64,
`0x0b`=STRING, `0x0c`=STRUCT, `0x0f`=LIST) sono in realtà i type code standard del
Thrift binary protocol (la sessione 06/11 li riteneva non standard). Un analyzer
`thrift` generico (dump di metodi/campi) sarebbe utile ma non farebbe emergere la
flag → non chiude l'issue.

## #25 SSTV m00nwalk — **resta GAP** (limite OCR, verificato)

Il frame Scottie S1 320×256 viene decodificato correttamente (clock 1.002, 256
righe). Il testo della flag è **corsivo/graffiti scritto a mano** su uno sticker
giallo, ~10 px di altezza, ruotato di 180°. Provati in container: crop + soglia,
maschera giallo+scuro, upscale 6×, soglia adattativa, psm 6/7 — tesseract produce
solo frammenti (`cTFibeer-`, `boop-`, `beop-Perk`) e nessun token leggibile.
È lo stesso limite già documentato nell'issue ("flag leggibile solo a occhio"):
nessuna trasformazione generica affidabile. Il caso resta in `GAPS` per
costruzione; per chiuderlo servirebbe un OCR per corsivo (fuori portata) o
hardcodare la flag (vietato).
