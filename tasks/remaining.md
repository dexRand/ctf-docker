# Remaining work — StegSuite

> Documento di ripresa. Aggiornato dopo P1 (pulizia/GUI), P2 (analyzer),
> P3 (sicurezza/ops), P4 (packaging). Metti `[x]` quando fatto.

## Come riprendere
```bash
cd "/home/romeo/Progetti/ctf-docker"
docker compose up -d stegsuite          # GUI/API su http://localhost:19014
./ctf test                              # 17/17 + 7/7 + verifica risposte
# oppure i singoli passi:
#   regressione (nel container): copia app/tests/ctf_regression.py in /tmp e lancia
#   challenge reali (host):      python3 app/tests/real_challenges.py
#   verifica per-istanza:        python3 app/tests/verify_flags.py
docker compose config -q                # valida il compose
```
CI: `gh`/Actions → workflow `.github/workflows/ci.yml` (compose, backend+pytest,
frontend build; job `e2e` on-demand). Il token serve con scope **`workflow`**.

## Fatto di recente ✅
- **P5 image repair**: `image-repair` (BMP: header standard se offset/DIB
  corrotti + altezza ricalcolata dai dati; JPEG: EOI mancante). Risolve
  *tunn3l v1s10n* reale; unit test puri + regressione E2E #17.
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
- **Test/Docs**: regressione **17/17**, reali **7/7**, `verify_flags` **ALL
  CORRECT** (istanza per istanza), `pytest` 9, `docs/CHALLENGES.md`.

## Prossima sessione (in ordine)

### A. Analyzer da completare (P2)
- [x] **JPEG/BMP height repair** — *tunn3l v1s10n*: `image-repair` ripristina
  header BMP standard (offset 54, DIB 40) quando i campi sono corrotti (`ba d0…`)
  e ricalcola l'altezza dai dati; JPEG: riattacca EOI mancante. Verificato sulla
  challenge reale (1134×850, flag via OCR/vision) + caso regressione #17.
- [x] **DNS tunneling** (*ExtractionD'ADNs*): nell'analyzer `pcap`, le euristiche
  base-domain / posizione-etichetta ricompongono i chunk (dedup, ordine pacchetti)
  e provano base32/base64 con gate di printable; flag poi presa dalla flag hunt.
  Unit (7) + regressione E2E #18 (pcap DNS sintetico).
3. [ ] **TLS/pcap con chiave** (*WebNet*): `tshark -o tls.keylog_file=...` o
   `sslkeylogfile` per decifrare; poi campi HTTP.
4. [ ] **SSTV** (*m00nwalk*): serve un decoder (es. `qsstv`/`pysstv`); valutare
   dipendenza o decoder minimo in Python.
5. [ ] **Fast-path archivi annidati** (*like1000*): con `MAX_DEPTH` alto è lento
   (tool pesanti per livello) → loop tar/zip mirato senza ricreare N nodi.
6. [ ] **rot13/url inline** nella flag hunt (oltre b64/hex già fatti).

### B. Sicurezza / Ops (P3)
7. [ ] **Rate limiting** sulle API (token bucket per IP, opt-in).
8. [ ] **Alembic** per le migrazioni (oggi `_migrate()` manuale in `db.py`).
9. [ ] **Retention** opzionale (`RETENTION_DAYS`) — oggi disattivata per scelta.

### C. GUI (rifiniture P1 residue)
10. [ ] **Barra di progresso** per file (evento `progress` già emesso) e
    **toast**/errori; upload con progress.
11. [ ] Copia **tutte** le flag / export report `.md` (il per-file c'è già).
12. [ ] Layout responsive/mobile.

### D. Test & qualita (P0 residuo)
13. [ ] Ampliare `pytest`: analyzer, orchestrator, API con **TestClient**.
14. [ ] Committare le fixture reali (opzionale, ~4 MB) + nuovi casi regressione.
15. [ ] OCR lingua **italiana** (`tesseract-ocr-ita`).

### E. Packaging (P4)
16. [ ] **Screenshot** + esempi nel README.
17. [ ] Comando `./ctf` per aprire StegSuite/docs (URL rapidi).
18. [ ] Valutare base image propria (ora pinnata per digest a AperiSolve, MIT).

### F. Cracking
19. [ ] UI wordlist (upload/scelta, salvataggio per item).
20. [ ] `bkcrack` (ZipCrypto known-plaintext); rules/mask + budget CPU.

## Gap challenge noti
Vedi `docs/CHALLENGES.md` → "Altri casi provati": **c0rrupt** (PNG repair
presente, flag visiva non OCR-abile), **like1000**, **MacroHard WeakEdge**,
**Surfing the Waves** (WAV: mapping custom), **Very very very Hidden** (pcap+tool).

## Limiti noti
- Flag **visive** via OCR (buono, non perfetto; alcune immagini rumorose non
  vengono lette, es. `c0rrupt`).
- AES su **CPU** ~17k H/s → rockyou intera ≈ 14 min (no GPU).
- `picoctf.net` non risolve da qui → mirror GitHub (HHousen/PicoCTF-*).
- Flag **per-istanza** su alcune challenge: verificare artifact-per-artifact
  (`verify_flags.py`), non confrontare writeup diversi.

## File chiave
```
app/backend/main.py            # app factory + startup (reconcile + dedupe)
app/backend/api/*.py           # router: system, projects, analysis, tools, cracking, ws
app/backend/orchestrator.py    # ricorsione + auto-crack + flag hunt + semaforo
app/backend/cracking.py        # hashcat/stegseek/pdfcrack/fcrackzip
app/backend/analyzers/*.py     # 38 tool (un file, auto-registered)
app/frontend/                  # GUI Vue 3 (+ package-lock.json)
app/tests/ctf_regression.py    # 17/17 (incl. image-repair: BMP corrotto)
app/tests/real_challenges.py   # 7/7 picoCTF
app/tests/verify_flags.py      # verifica per-istanza (ALL CORRECT)
app/tests/test_flags.py        # unit (9)
app/tests/test_repair.py       # unit repair JPEG/BMP (7)
docs/ADDING-A-TOOL.md, docs/API.md, docs/CHALLENGES.md
.github/workflows/ci.yml       # CI
compose.yaml                   # servizio stegsuite (19014)
```
