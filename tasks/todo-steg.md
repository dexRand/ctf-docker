# Todo — StegoForge (app)

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

## Phase 7 — Frontend SPA
- [ ] T7.1 Setup Vue/Vite/Tailwind
- [ ] T7.2 Home/nuova analisi
- [ ] T7.3 Vista progetto (albero + tool + anteprime + findings)
- [ ] T7.4 Log live + cracking panel
- [ ] T7.5 Terminale + Elimina/Keep
- [ ] T7.6 History
### Checkpoint E
- [ ] Flusso completo da browser

## Phase 8 — Integrazione & doc
- [ ] T8.1 Servizio stego + dashboard
- [ ] T8.2 Parità/CLI opzionale
- [ ] T8.3 README + attribuzioni
- [ ] T8.4 Test E2E + commit/push
