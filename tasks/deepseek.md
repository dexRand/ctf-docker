# Task per opencode (deepseek) — batch 2

Prima di iniziare rileggi **tutto** `AGENTS.md` → "Regole per il lavoro autonomo",
compresa la parte **"Lezioni dal batch del 05–10/11"**: sono le regole aggiunte dopo
la review del batch 1 (vedi in fondo cosa era andato storto).

Baseline da non peggiorare: quella scritta nell'ultimo commit `docs(tasks)` di Claude
(numeri di `real_challenges.py --extra` e `./ctf test -j 3`). Una FAIL nuova = niente push.

Ordine di lavoro per ogni task:
1. scrivi prima il test (deve fallire), poi il codice;
2. `run_unit.sh` + `./ctf lint` + `./ctf test --fast` (tempo prima/dopo nel commit);
3. il caso reale del task, se c'è;
4. commit `Refs #N`/`Fixes #N` + commento sull'issue.
Alla fine del batch: set extra completo + `./ctf test -j 3`, poi push su `main`.

---

## Task 1 — Credenziali in chiaro nei pcap (issue #11)

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

## Task 2 — Export di oggetti SMB/TFTP/IMF/FTP-data dai pcap (issue #11)

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

## Task 3 — Frame delle PNG animate (APNG) (issue #15)

**File:** `app/backend/analyzers/gif.py`, test `app/tests/test_apng.py`.

- `gif-frames` accetta anche `.png` **solo se** nei primi 64 KB c'è il chunk `acTL`
  (PNG animata); le PNG normali escono `skipped` subito, senza aprire l'immagine.
- Pillow legge gli APNG con `ImageSequence`: stesso trattamento delle GIF (frame,
  differenze, delay, QR a strisce).
- **Test:** crea un APNG di 3 frame con Pillow (`save(..., save_all=True,
  append_images=...)`) e verifica i 3 frame; una PNG normale → `skipped`.

## Task 4 — Audio stereo: differenza dei canali (issue #15)

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

## Task 5 — Hash "nudi" nei file di testo (issue #16)

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
| 1 credenziali pcap | da fare | | |
| 2 export SMB/TFTP/IMF | da fare | | |
| 3 APNG | da fare | | |
| 4 stereo L−R | da fare | | |
| 5 hash nudi | da fare | | |

## Proposte (cose che servirebbero ma toccano file vietati)

(niente per ora)

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
