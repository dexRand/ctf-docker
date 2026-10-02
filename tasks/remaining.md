# Remaining work — StegSuite

> Documento di ripresa. Aggiornato dopo il refactor modulare + fix flag/GUI.
> Metti ✅ quando fatto.

## Come riprendere
```bash
cd "/home/r/__Github/CTF"
docker compose up -d stegsuite                 # GUI/API su http://localhost:19014
# regression (nel container):
docker cp app/tests/ctf_regression.py ctf-stegsuite-1:/tmp/ctf_regression.py
docker cp app/tests/fixtures ctf-stegsuite-1:/tmp/fixtures
docker exec -e FIXTURES_DIR=/tmp/fixtures ctf-stegsuite-1 /opt/stegsuite/venv/bin/python /tmp/ctf_regression.py
# challenge reali (host, si scarica i file da sola):
python3 app/tests/real_challenges.py
```

## Fatto di recente ✅
- **Caccia flag** ripulita: pattern strict vs generico; il generico NON gira sui
  tool di vision né sui byte grezzi; validazione della flag (una sola `{}`, no
  `|`, body alfanumerico) → spariscono i falsi positivi OCR (`zz{z{...`).
- **UTF-16 / byte alterni**: recupera flag in file UTF-16 con lunghezza dispari
  (es. `flag.txt` di *Matryoshka doll*).
- **Scansione dei byte grezzi** del file (oltre agli output dei tool).
- **Depth ricorsione = 6** (archivi annidati).
- **Immagini grandi**: `bit-planes`/`image-enhance` gated (4 MP) e OCR solo dei
  piani LSB (bit 0/1) → niente più "running" infinito su foto grandi.
- **Refactor modulare**: route divise in `app/backend/api/` (system, projects,
  analysis, tools, cracking_api, ws); `main.py` è solo la app factory.
- **Terminale**: **bash colorato** (PS1 con colori, `TERM=xterm-256color`) e `ls`
  con `dircolors` (cartelle blu, eseguibili verdi, symlink ciano).
- **GUI**: click sul tool → output (con rendering **ANSI**/colori), immagini
  **ingrandibili** (lightbox), tasto **Report** (progetto e file); **icona SVG**
  al posto delle emoji; **albero file comprimibile** raggruppato per tool di
  estrazione (con freccette) e **colorato**: verde = percorso flag, bianco =
  adiacente, grigio = via morta.
- **Report pulito**: solo il **percorso della flag** (albero ASCII con lo step
  che ha prodotto ogni file), passaggi rilevanti, comandi usati; niente più
  rumore di file/tool che non portano alla flag (restano esplorabili in GUI).
- **Orfani dopo restart**: i progetti rimasti `running` vengono marcati `error`
  all'avvio (niente più spinner infinito).
- **Estrazioni**: ogni file figlio registra **quale tool** l'ha prodotto
  (`origin=extracted:<tool>:<parent>`); niente più artefatti "missing on disk".
- **Docs**: `docs/ADDING-A-TOOL.md`, `docs/API.md`, `docs/CHALLENGES.md`
  (flag + comandi manuali verificati).
- **Test**: regressione **13/13**, challenge reali picoCTF **7/7**
  (So Meta, information, Matryoshka doll, What Lies Within, Glory of the Garden,
  extensions, Weird File).
- **Fix robustezza**: tipo rilevato da `file` usato per il piano (estensione che
  mente), WAL + busy_timeout SQLite e commit per-tool (niente più
  `database is locked`), dedup flag per spazi/frammenti, fuzzy solo su OCR/vision.

## TODO

### 1. Test & CI
- [x] 5 challenge reali picoCTF verdi (script auto-contenuto).
- [ ] Committare le fixture reali (opzionale, pesano ~4 MB) + casi regressione.
- [ ] Script `./ctf test` (o Makefile) che lancia regressione + reali.
- [ ] **CI** GitHub Actions (build immagine + regressione).
- [ ] Test unit `pytest` (analyzer, orchestrator, API con TestClient).

### 2. Rumore/precisione
- [x] Falsi positivi OCR/generic eliminati.
- [ ] Deduplicare i finding **rot13** (`VGF{...}`) rispetto alla flag originale.
- [ ] Deduplicare le note "password required" ripetute tra le passate.
- [ ] OCR lingua **italiana** (`tesseract-ocr-ita`).

### 3. GUI (rifiniture)
- [x] Click sul tool → output/ANSI; report per file; immagini ingrandibili;
      terminale colorato.
- [x] Tema scuro / “bellezza”
- [x] Albero file collapse/expand + raggruppamento per tool di estrazione +
      colori semantici (percorso/adiacente/morto).
- [ ] Filtri/ricerca nell'albero file.
- [ ] Barra di progresso per file; toast/errori; copia-flag 1-click; export report `.md`.
- [ ] Upload con progress; layout responsive/mobile.

### 4. Analyzer da aggiungere
- [ ] **pcap/DNS tunneling** (ExtractionD'ADNs): `tshark` → sottodomini → base32.
- [ ] **TLS/pcap con chiave** (WebNet).
- [ ] **SSTV** audio (m00nwalk) — decoder SSTV.
- [ ] **QR/barcode** (`zbar-tools`).
- [ ] **PNG repair** (`pcrt`) — c0rrupt.
- [ ] **JPEG height repair** — tunn3l v1s10n.
- [ ] **WAV LSB / campioni**.
- [ ] **rot13/url inline** nella flag hunt (già b64/hex).
- [ ] Depth di ricorsione configurabile da UI/API.

### 5. Cracking
- [ ] UI gestione wordlist (upload/scelta), salvataggio scelta per item.
- [ ] `bkcrack` (ZipCrypto known-plaintext); rules/mask + budget.
- [ ] Valutare john jumbo / Hashcat GPU.

### 6. Robustezza / Ops
- [ ] Migrazioni DB (Alembic) se cambia lo schema.
- [ ] Cap upload/limiti risorse per tool; semaforo tool pesanti.
- [ ] Auth `X-API-Key` documentato + rate limiting; terminale protetto.
- [ ] Retention opzionale (`RETENTION_DAYS`) — oggi disattivata per scelta utente.

### 7. Packaging
- [ ] `package-lock.json` frontend per build riproducibili.
- [ ] Screenshot + esempi nel README.
- [ ] Valutare base image propria (ora pinnata per digest a AperiSolve, MIT).
- [ ] Comando `./ctf` per aprire StegSuite/docs.

## Limiti noti
- Flag **visive** via OCR (buono, con fuzzy matcher; non perfetto).
- AES su **CPU** ~17k H/s → rockyou intera ≈ 14 min (no GPU).
- `picoctf.net` non risolve da qui → usare mirror GitHub (HHousen/PicoCTF-*).
- Challenge che richiedono ricerca dell'originale online non automatizzabili.

## File chiave
```
app/backend/main.py            # app factory (include i router)
app/backend/api/*.py           # router: system, projects, analysis, tools, cracking, ws
app/backend/orchestrator.py    # ricorsione + auto-crack + flag hunt
app/backend/cracking.py        # hashcat/stegseek/pdfcrack/fcrackzip
app/backend/analyzers/*.py     # ~30 tool (un file, auto-registered)
app/frontend/                  # GUI Vue 3
app/tests/ctf_regression.py    # 13/13
app/tests/real_challenges.py   # 7/7 picoCTF
docs/ADDING-A-TOOL.md, docs/API.md, docs/CHALLENGES.md
compose.yaml                   # servizio stegsuite (19014)
```
