# Todo: CTF Toolbox

## Phase 1 — Scaffolding repo ✅
- [x] Task 1: `git init` + remote `origin` + `.gitignore` + `AGENTS.md`
- [x] Task 2: `.env.example` con porte `19000+`
- [x] Task 3: `compose.yaml` core (Homepage, AperiSolve, CyberChef, mitmproxy, IT-Tools)

### Checkpoint: Core ✅
- [x] `docker compose config -q` OK
- [x] `./ctf up` → servizi core up e raggiungibili (200)
- [x] Revisione umana (set tool + porte 19000+)

## Phase 2 — Dashboard ✅
- [x] Task 4: `config/homepage/settings.yaml` + `widgets.yaml`
- [x] Task 5: `config/homepage/services.yaml` (tutti i tool, ordinati, descritti)

## Phase 3 — Tool pesanti (profili) ✅
- [x] Task 6: ZAP webswing — profilo `web` → http://localhost:19005/zap (200)
- [x] Task 7: SpiderFoot — profilo `recon` → http://localhost:19007/spiderfoot/ (200, healthy)
- [x] Task 8: Wireshark — profilo `forensics` → http://localhost:19008 (200)
- [x] Task 9: SageMath Jupyter — profilo `crypto` → http://localhost:19010 (200, token nei log)

## Phase 4 — UX + doc ✅
- [x] Task 10: wrapper `./ctf`
- [x] Task 11: `README.md` (EN, principale) + `README.it.md` (IT) + `LICENSE`

## Backlog
- [ ] Profilo `crack`: Hashtopolis (frontend + backend + agent + DB)
- [ ] (Opz.) Docker integration di Homepage via socket read-only per stats container

### Checkpoint: Complete ✅
- [x] Ogni servizio risponde a runtime (9/9 → HTTP 200)
- [x] Dashboard mostra tutti i tool con descrizione e stato
- [x] README allineato (EN principale + IT)
