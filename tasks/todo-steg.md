# Todo — StegoForge (app)

## Phase 1 — Backend core ✅
- [x] T1.1 Scaffolding backend + config (FastAPI)
- [x] T1.2 Modelli SQLite (Project/FileNode/ToolRun/Finding/Event)
- [x] T1.3 API progetti (CRUD + upload + delete)
- [x] T1.4 Storage su disco (uploads/files/work) + hashing
- [x] T1.5 SPA statica placeholder + /health
### Checkpoint A ✅
- [x] CRUD progetti verificato via curl (create/get/list/content/delete)

## Phase 2 — Analyzer + API tool singoli
- [ ] T2.1 Registry + runner subprocess
- [ ] T2.2 Tool metadati/testo
- [ ] T2.3 Tool estrazione
- [ ] T2.4 Tool steg + bit-layers/spectrogram
- [ ] T2.5 GET /tools + POST /tools/{tool}
### Checkpoint B
- [ ] Ogni tool eseguibile via API

## Phase 3 — Orchestrazione + findings
- [ ] T3.1 Orchestratore sequenziale ordinato
- [ ] T3.2 Ricorsione su artefatti
- [ ] T3.3 Flag-hunt + locked detection
- [ ] T3.4 start/pause/resume/cancel + tree/findings
### Checkpoint C
- [ ] Albero completo e ordinato su fixture

## Phase 4 — Cracking + wordlist
- [ ] T4.1 Port stegseek/fcrackzip/hashcat/pdfcrack
- [ ] T4.2 Wordlist piccola→grande + ripple
- [ ] T4.3 GET /wordlists + POST /crack
### Checkpoint D
- [ ] Zip AES crackato via API

## Phase 5 — Live & log
- [ ] T5.1 Bus eventi + WS progetto
- [ ] T5.2 Persistenza eventi

## Phase 6 — Terminale web
- [ ] T6.1 PTY over WS (cwd progetto)
- [ ] T6.2 Sicurezza + resize

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
