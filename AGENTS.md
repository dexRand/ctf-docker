# AGENTS.md — CTF Toolbox

Repo infrastrutturale: un unico `compose.yaml` che avvia tool CTF con GUI web,
più una dashboard **Homepage** che li elenca ordinati per fase di lavoro.

## Regole fondamentali

- **Docker-first.** Non installare tool sull'host: tutto gira nei container.
- Prima di un task, se esiste una skill adatta invocala con il tool `skill`.
  Le skill stanno in `.opencode/skills/` (vedi `.opencode/ATTRIBUTION.md`, MIT).
- **Porte sempre `19000+`** e modificabili da `.env`. Mai porte < 9000: la
  macchina ospita altri stack (es. `veronabusapp` su 8080/5173).
- Immagini upstream reali e verificate. Uniche eccezioni (build custom documentati):
  **StegSuite** (`app/Dockerfile`), **ZAP** (`zap/Dockerfile`, add-on extra) e
  **rev** (`rev/Dockerfile`, sandbox ELF: pwntools + ttyd + qemu).
  Per il resto niente build custom.
- Aggiorna insieme queste cose quando cambi un servizio:
  `compose.yaml`, `.env.example`, `config/homepage/services.yaml`, la tabella
  `SERVICES` in `ctf`, `app/backend/services.py`, `README.md` + `README.it.md`.
  `python3 tools/check_consistency.py` controlla che siano allineati (anche in CI).
- **API-first**: ogni funzione di StegSuite deve esistere come endpoint REST
  (e, se utile a un'IA, come tool MCP in `app/backend/mcp_server.py`); la SPA
  consuma solo le API. Documenta in `docs/API.md`.
- **Solo localhost**: le porte si pubblicano su `${BIND_ADDR:-127.0.0.1}`.
- **Niente duplicati**: le funzioni condivise degli analyzer stanno in
  `app/backend/analyzers/util.py` e `base.py` (`run_cmd`, `ctx.siblings`).

## Comandi

```bash
./ctf up                  # tool core
./ctf up web              # core + profilo web
./ctf up-all              # tutto
./ctf down
./ctf status
./ctf logs <servizio>
docker compose config -q  # valida il compose
app/tests/run_unit.sh     # test pytest nell'immagine StegSuite
./ctf test -j 3           # regressione + challenge CTF reali
```

## Convenzioni

- Niente `container_name` fissi: si usa il prefisso del progetto (`ctf-*`).
- Tool pesanti dietro profili Compose: `web`, `recon`, `crypto`, `forensics`,
  `crack`, `audio`, `rev`.
- Nomi dei tool in inglese; descrizioni e documentazione in italiano.
- `restart: unless-stopped`, `mem_limit`/`cpus` e logging `json-file` con rotazione.

## Definition of Done

1. `docker compose config -q` passa senza errori.
2. I servizi toccati partono e rispondono a runtime (`./ctf up` + check URL);
   per StegSuite: `app/tests/run_unit.sh` + `./ctf test -j 3` senza regressioni
   (stesse challenge risolte o di più).
3. Dashboard e `README.md` coerenti con il compose.
4. Nessun segreto committato (`.env` è in `.gitignore`).
5. Stato aggiornato in `tasks/todo.md` e `tasks/plan.md`.
