# AGENTS.md — CTF Toolbox

Repo infrastrutturale: un unico `compose.yaml` che avvia tool CTF con GUI web,
più una dashboard **Homepage** che li elenca ordinati per fase di lavoro.

## Regole fondamentali

- **Docker-first.** Non installare tool sull'host: tutto gira nei container.
- Prima di un task, se esiste una skill adatta invocala con il tool `skill`.
  Le skill stanno in `.opencode/skills/` (vedi `.opencode/ATTRIBUTION.md`, MIT).
- **Porte sempre `19000+`** e modificabili da `.env`. Mai porte < 9000: la
  macchina ospita altri stack (es. `veronabusapp` su 8080/5173).
- Immagini upstream reali e verificate. Unica eccezione: il tool **triage** ha
  un `Dockerfile` in `triage/` che estende l'immagine AperiSolve (aggiunge
  stegseek/john/fcrackzip/pdfcrack). Per il resto niente build custom.
- Aggiorna insieme queste cose quando cambi un servizio:
  `compose.yaml`, `.env.example`, `config/homepage/services.yaml`, `README.md`.

## Comandi

```bash
./ctf up                  # tool core
./ctf up web              # core + profilo web
./ctf up-all              # tutto
./ctf down
./ctf status
./ctf logs <servizio>
docker compose config -q  # valida il compose
```

## Convenzioni

- Niente `container_name` fissi: si usa il prefisso del progetto (`ctf-*`).
- Tool pesanti dietro profili Compose: `web`, `recon`, `crypto`, `forensics`,
  (in backlog) `crack`.
- Nomi dei tool in inglese; descrizioni e documentazione in italiano.
- `restart: unless-stopped`, `mem_limit`/`cpus` e logging `json-file` con rotazione.

## Definition of Done

1. `docker compose config -q` passa senza errori.
2. I servizi toccati partono e rispondono a runtime (`./ctf up` + check URL).
3. Dashboard e `README.md` coerenti con il compose.
4. Nessun segreto committato (`.env` è in `.gitignore`).
5. Stato aggiornato in `tasks/todo.md` e `tasks/plan.md`.
