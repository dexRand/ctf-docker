# Remaining work — StegSuite

> Documento di ripresa. Aggiornato al commit `1757f83`.
> Metti ✅ quando fatto, sposta in "Done" in fondo.

## Stato attuale (fatto)

StegSuite è **funzionante e integrata**:

- Backend **FastAPI** + **SQLite**: progetti (CRUD/upload/delete), file, tool-run,
  artefatti, findings, eventi; **API per il singolo tool** (`POST /api/v1/tools/{tool}`),
  OpenAPI su `/api/docs`. Codice in `app/backend/`.
- **~30 analyzer** (`app/backend/analyzers/`): file, exiftool, identify, ffprobe,
  pdfinfo, strings, pdftotext, pdfid, binwalk-scan, **decode** (mini-Ciphey),
  **morse-text**, **ocr**, zsteg, **png-chunks**, steghide, outguess, jsteg,
  openstego, bit-planes (+OCR), channel-remap, **image-enhance**, **gif-frames**
  (split+diff+delay+OCR), morse (audio), dtmf, spectrogram, waveform, 7z,
  binwalk-extract, foremost, pngcheck, hexyl/xxd/hexdump.
- **Orchestrazione ricorsiva ordinata** (`orchestrator.py`): Auto = analizza +
  **auto-crack** + ri-analizza; Check = si ferma e chiede.
- **Cracking** (`cracking.py`): hashcat (ZipCrypto+AES via `zip2hashcat`),
  stegseek, pdfcrack, fcrackzip fallback; wordlist piccola→grande (repo + rockyou).
- **Live**: WebSocket eventi + **terminale PTY** (`/ws/projects/{id}/terminal`).
- **GUI Vue 3** + Vite + Tailwind + xterm.js (`app/frontend/`): Home (upload,
  Auto/Check, history), Project (albero file, output tool, artefatti, preview,
  findings, blocco "bloccati" con scelta wordlist, log live, terminale,
  start/pause/resume/cancel/delete).
- **Compose**: servizio `stegsuite` (porta **19014**, localhost) + card dashboard.
- **Regressione** `app/tests/ctf_regression.py`: **13/13** (incl. `challenge.png`
  reale risolto in autonomia: pwd `robot` → `ITS{stego_z1p_appended}`).

## Ultima modifica NON ancora verificata (fai questa per prima)

- `app/backend/orchestrator.py` è **modificato ma non committato né buildato**:
  aggiunge la ricerca **base64/hex inline negli output** (serve per la challenge
  picoCTF *information*: la flag è base64 nel campo EXIF `License`).
- Al resume:
  ```bash
  cd "/home/r/__Github/CTF"
  python -m py_compile app/backend/orchestrator.py
  docker compose build stegsuite && docker compose up -d --force-recreate stegsuite
  python3 /tmp/opencode/real_test.py     # se esiste; altrimenti ricrealo (vedi sotto)
  ```
- `real_test.py` (host) testa 5 challenge reali picoCTF scaricate in
  `/tmp/opencode/real/` (potrebbero non esserci più dopo un reboot → riscaricale):
  | file | flag attesa | tecnica |
  |---|---|---|
  | pico_img.png | `picoCTF{s0_m3ta_43f253bb}` | exiftool |
  | cat.jpg | `picoCTF{the_m3tadata_1s_modified}` | base64 in EXIF |
  | dolls.jpg | `picoCTF{336cf6d51c9d9774fd37196c1d7320ff}` | zip annidati |
  | buildings.png | `picoCTF{h1d1ng_1n_th3_b1t5}` | LSB (zsteg) |
  | garden.jpg | `picoCTF{more_than_m33ts_the_3y35a97d3bB}` | strings/xxd |
  Fonti: `raw.githubusercontent.com/HHousen/PicoCTF-2019|2021/...` (picoctf.net è
  bloccato da qui, usare i mirror GitHub).
- Poi: se qualcuno fallisce, fixare e **aggiungere i file come fixture** in
  `app/tests/fixtures/` + caso in `ctf_regression.py`.

## TODO

### 1. Test reali & regressione
- [ ] Verificare le 5 challenge picoCTF sopra e fixare i gap.
- [ ] Committare le fixture reali (in `app/tests/fixtures/`) + casi regressione.
- [ ] Portare la suite a girare comodamente (script `./ctf test` o Makefile) e,
      opzionale, in **CI** (GitHub Actions) con l'immagine.
- [ ] Test unit backend (`pytest`): analyzer, orchestrator, API (TestClient).

### 2. Riduzione rumore flag
- [ ] La catena `decode` genera duplicati rot13 (`VGF{...}`). Filtrare le flag che
      sono trasformazioni (rot13/b64) di un'altra flag già trovata.
- [ ] Deduplicare le `note "password required"` (oggi si ripetono a ogni passata).

### 3. GUI (rifiniture Phase 7)
- [ ] Rendering **ANSI** dell'output (`hexyl` a colori) invece del testo grezzo.
- [ ] Viewer immagini con **zoom** + confronto side-by-side (bit-plane, frame,
      highlights, `compare`-style).
- [ ] Filtri/ricerca nell'albero file; raggruppamento dei tool per categoria;
      collapse/expand.
- [ ] Barra di progresso per file; feedback pause/cancel; toast/errori visibili.
- [ ] Copia-flag con un click; marcare/annotare i finding; export del report.
- [ ] Upload con progress + dropzone più curata; layout responsive.
- [ ] "Keep"/"Delete" più espliciti + selezione multipla in history.

### 4. Analyzer da aggiungere (per coprire "tutto")
- [ ] **pcap/DNS tunneling** (ExtractionD'ADNs): estrae i sottodomini, concatena,
      base32/base64 → flag. Richiede `tshark` (verificare in immagine).
- [ ] **TLS/pcap con chiave** (WebNet): `tshark -o tls.keylog_file` / RSA key.
- [ ] **SSTV** audio (picoCTF m00nwalk): decoder SSTV (slowrx/qsstv o Python).
- [ ] **QR/barcode** decode (`zbar-tools`).
- [ ] **PNG repair** (`pcrt`) per "c0rrupt".
- [ ] **JPEG height/width repair** per "tunn3l v1s10n".
- [ ] **WAV LSB / campioni** (audio stego) oltre a spectrogram/morse.
- [ ] **exiftool thumbnail** extraction + `identify -verbose` histogram.
- [ ] **rot13/url inline** nella flag hunt (come fatto per b64/hex).
- [ ] OCR lingua **italiana** (`tesseract-ocr-ita`) per challenge IT.
- [ ] Depth di ricorsione configurabile da UI/API (oggi fisso 3).

### 5. Cracking avanzato
- [ ] UI per gestire le wordlist (upload/selezione) e salvare la scelta per item.
- [ ] `bkcrack` per ZipCrypto known-plaintext.
- [ ] Attacchi con **rules/mask** e budget di tempo configurabile.
- [ ] Valutare **john jumbo** (zip2john/office2john reali) o Hashcat GPU.

### 6. Robustezza / Ops / Sicurezza
- [ ] Migrazioni DB (oggi solo `create_all`): introdurre Alembic se lo schema cambia.
- [ ] Capi di dimensione upload, streaming, limiti risorse e timeout per tool.
- [ ] Concorrenza: semaforo globale per i tool pesanti; più progetti in parallelo.
- [ ] Auth/`X-API-Key` documentato + rate limiting; terminale protetto; bind solo
      localhost (già).
- [ ] Retention opzionale (`RETENTION_DAYS`) — oggi disattivata per scelta utente.

### 7. Packaging / Docs
- [ ] `package-lock.json` del frontend (oggi `npm install` senza lock) per build
      riproducibili.
- [ ] Screenshot + sezione API con esempi (`curl`) nel README.
- [ ] Valutare **base image propria** (ora è pinnata per digest all'immagine
      AperiSolve, MIT): costruirla da Debian per indipendenza totale.
- [ ] `./ctf` : comando comodo per aprire StegSuite / docs.

### 8. Limiti noti (documentare)
- Flag **visive** risolte via OCR (buono ma imperfetto; c'è il fuzzy matcher).
- AES su **CPU** ~17k H/s: rockyou intera ≈ 14 min (nessuna GPU).
- `picoctf.net` non risolve da questa macchina: usare mirror GitHub.
- Challenge che richiedono **ricerca dell'originale online** (Stegartifice2) non
  sono automatizzabili.

## File chiave
```
app/backend/main.py            # API + WS + static SPA
app/backend/orchestrator.py    # ricorsione + auto-crack + flag hunt  (MODIFICATO)
app/backend/cracking.py        # hashcat/stegseek/pdfcrack/fcrackzip
app/backend/analyzers/*.py     # ~30 tool
app/frontend/                  # GUI Vue 3
app/tests/ctf_regression.py    # suite 13/13
app/tests/fixtures/            # challenge.png reale
compose.yaml                   # servizio stegsuite (19014)
config/homepage/services.yaml  # card dashboard
SPEC-steg.md, tasks/plan-steg.md, tasks/todo-steg.md
```

## Done
- (nessuno ancora) — sposta qui le voci completate.
