# Todo — StegoForge (app)

> Backlog vivo StegSuite: **`tasks/remaining.md`** (stato attuale + prossimi passi).
> Qui sotto la storia delle fasi completate.

## Phase 1 — Backend core ✅
- [x] T1.1 Scaffolding backend + config (FastAPI)
- [x] T1.2 Modelli SQLite (Project/FileNode/ToolRun/Finding/Event)
- [x] T1.3 API progetti (CRUD + upload + delete)
- [x] T1.4 Storage su disco (uploads/files/work) + hashing
- [x] T1.5 SPA statica placeholder + /health
### Checkpoint A ✅
- [x] CRUD progetti verificato via curl (create/get/list/content/delete)

## Phase 2 — Analyzer + API tool singoli ✅
- [x] T2.1 Registry + runner subprocess
- [x] T2.2 Tool metadati/testo (file, exiftool, identify, ffprobe, pdfinfo, strings, pdftotext, pdfid, binwalk-scan)
- [x] T2.3 Tool estrazione (binwalk-extract, foremost, 7z, pngcheck)
- [x] T2.4 Tool steg (zsteg, steghide, outguess, jsteg, openstego, bit-planes, channel-remap) + audio (spectrogram, waveform)
- [x] T2.4b Tool hex: xxd, hexdump, hexyl (colorato)
- [x] T2.5 GET /tools (25 tool) + POST /tools/{tool} stateless + download artefatti
### Checkpoint B ✅
- [x] Tool eseguibili via API; binwalk-extract/7z/steghide/bit-planes verificati

## Phase 3 — Orchestrazione + findings ✅
- [x] T3.1 Orchestratore sequenziale ordinato (BFS per ordine di scoperta)
- [x] T3.2 Ricorsione su artefatti (figli come FileNode, depth max 3)
- [x] T3.3 Flag-hunt + locked detection (Finding kind=note "password required")
- [x] T3.4 start/pause/resume/cancel + findings/runs/events
### Checkpoint C ✅
- [x] Su challenge.png+stego.jpg: albero 16 nodi su 3 livelli, findings corretti

## Phase 4 — Cracking + wordlist ✅
- [x] T4.1 Port stegseek/fcrackzip/hashcat/pdfcrack (+ zip2hashcat)
- [x] T4.2 Wordlist piccola→grande + ripple sui figli sbloccati
- [x] T4.3 GET /wordlists + GET /locked + POST /crack
### Checkpoint D ✅
- [x] Zip AES crackato via API (secret123) + flag estratta
- [x] steghide crackato via API (ctf) + flag estratta
- [x] Fix vendored zip2hashcat: mancava il ciphertext nel campo dati → hashcat
      ora verifica i candidati (prima 0 recuperi anche con password nota)

## Phase 5 — Live & log ✅
- [x] T5.1 Bus eventi (thread-safe) + WS /ws/projects/{id}
- [x] T5.2 Persistenza eventi (tabella Event) + emit da orchestrator/cracking
### Checkpoint (verificato)
- [x] 10 eventi live ricevuti via WS durante un'analisi

## Phase 6 — Terminale web ✅
- [x] T6.1 PTY over WS (cwd = progetto) — verificato (echo eseguito)
- [x] T6.2 Resize (TIOCSWINSZ) + chiusura pulita

## Vision & audio (extra, per challenge "da vedere/ascoltare") ✅
- [x] `gif-frames`: split frame + diff (evidenzia i frame più diversi) + decodifica
      dei delay (bit→ASCII) + OCR per frame
- [x] `ocr`: tesseract con upscaling (legge flag visibili)
- [x] `morse`: decoder Morse dall'inviluppo audio (verificato: "SOS")
- [x] `dtmf`: multimon-ng
- [x] Test reale: **picoCTF 2022 St3g0 risolta in autonomia** (zsteg →
      `picoCTF{7h3r3_15_n0_5p00n_96ae0ac1}`)
- [x] Test vision: GIF con flag in un frame → trovata via OCR (`gif-frames`)
- [x] `nested-archive`: catene di archivi annidati (*like1000*, 1000 tar) aperte
      in un solo passaggio, ignorando i `filler.txt`, fino al payload finale
- [x] `sstv`: decoder SSTV in Python (band-pass + Hilbert + sync + modo da
      spacing), Scottie S1/S2; *m00nwalk* decodificata (frame = QSSTV), OCR near-miss
- [x] `pcap` + TLS: decifra con una chiave privata/keylog fornita accanto al
      capture (`WebNet0/1`) ed esporta gli oggetti decifrati (ricorsione)
- [x] Flag hunt: viste **percent-decoded** e **rot13 twin** dei prefissi noti
      anche sulle sorgenti rumorose (strings/hex/pcap)
- [x] Migrazioni con **Alembic** (`migrations/`, stampa dei DB pre-Alembic) al
      posto di `_migrate()`; **retention** opzionale (`RETENTION_DAYS`)
- [x] Test: fixture reale WebNet0 (pcap+chiave) + regressione `tls-pcap`;
      **OCR italiano** (`tesseract-ocr-ita`, `OCR_LANGS`); smoke test UI con
      Chromium headless (`./ctf ui-smoke`)
- [x] Cracking: upload wordlist (persistite) + scelta per-item persistente;
      hashcat rules/mask + budget CPU; `bkcrack` ZipCrypto known-plaintext
- [x] Bugfix: `openstego` non estraeva mai (`-p ""` → help); progetto interrotto
      con flag già trovata ora `done` (non `error`) all'avvio
- [x] Bugfix UI: click su grafo/timeline ora seleziona e **rivela** il file
      (espande, scroll, su mobile passa al pannello `files`); click sul grafo
      gestito da noi (nodo più vicino) perché l'hit-test di force-graph sbagliava

## Copertura challenge italiane (ITSCyberGame / Olicyber / StarHackademin) ✅
- [x] `png-chunks`: dump tEXt/iTXt/zTXt/eXIf + dati dopo IEND (IsThatA)
- [x] `morse-text`: Morse testuale dal file, con catena di layer (Dashed)
- [x] `decode`: mini-Ciphey (base64/base32/base85/hex/binario/rot13/url +
      `0x30`/`0x31`→binario) e concatenazione multi-livello
- [x] `bit-planes` con **OCR** dei piani (LSB leggibile in autonomia, Stegartifice1)
- [x] `image-enhance`: autocontrast/equalize/invert/highlights/shadows + OCR (BrightSun)
- [x] Flag hunt "fuzzy" per gli errori OCR (`ITSfenhance_11}` → `ITS{enhance_11}`)
- [x] Regressione estesa: **13/13** categorie risolte in Auto
- [x] `challenge.png` reale (PNG 1x1 + zip AES) risolto in autonomia:
      password `robot` (da 10k-most-common/rockyou-75) → `ITS{stego_z1p_appended}`
      (fixture committata in `app/tests/fixtures/`)

## Phase 7 — Frontend SPA ✅ (v1)
- [x] T7.1 Setup Vue 3 + Vite + Tailwind + vue-router
- [x] T7.2 Home/nuova analisi (drag&drop, modalità Auto/Check)
- [x] T7.3 Vista progetto (albero file + tool + anteprime + findings)
- [x] T7.4 Log live + pannello cracking (scelta wordlist)
- [x] T7.5 Terminale xterm.js + Elimina
- [x] T7.6 History (lista progetti + apertura/eliminazione)
- [x] T7.7 Progress bar per-file (evento `total`) + toast + upload con progress
      + copia-tutte-le-flag + layout responsive/mobile (un pannello per vista)
- [x] Build multi-stage nell'immagine (Node → dist servita da FastAPI)
### Checkpoint E ✅
- [x] Flusso completo da browser (SPA servita, 29 tool, St3g0 risolta)

## Phase 8 — Integrazione & doc
- [x] T8.1 Servizio `stegsuite` in compose (19014) + card dashboard
- [x] T8.2 CLI opzionale (triage resta; StegSuite è GUI+API)
- [x] T8.3 README (EN/IT) + attribuzioni
- [x] T8.4 Test E2E continui + commit/push (CI + `./ctf test`)
