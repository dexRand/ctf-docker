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
| 3 Office parti | da fare | | |
| 4 .NET risorse | da fare | | |
| 5 Piet | da fare | | |
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

(niente per ora)

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
