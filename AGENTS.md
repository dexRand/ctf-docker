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
./ctf lint                # ruff + bandit + vulture + jscpd (duplicati), in container
./ctf test -j 3           # regressione + challenge CTF reali
```

## Convenzioni

- Niente `container_name` fissi: si usa il prefisso del progetto (`ctf-*`).
- Tool pesanti dietro profili Compose: `web`, `recon`, `crypto`, `forensics`,
  `crack`, `audio`, `rev`.
- Nomi dei tool in inglese; descrizioni e documentazione in italiano.
- `restart: unless-stopped`, `mem_limit`/`cpus` e logging `json-file` con rotazione.

## Regole per il lavoro autonomo (opencode / qualsiasi agente)

Valgono sempre; il lavoro da fare è in `tasks/deepseek.md` (un task alla volta).

**Perimetro**
- Un task = un'issue = un analyzer o una funzione. Non toccare altro.
- File **vietati** senza richiesta esplicita dell'utente: `app/backend/planner.py`,
  `pipeline.py`, `flaghunt.py`, `flagpatterns.py`, `tree.py`, `storage.py`,
  `api/fileresp.py`, `ctf`, `compose.yaml`, `.github/`. Se il task sembra richiederli,
  **fermati e scrivilo** in `tasks/deepseek.md` sotto "Bloccato".
- Mai togliere o saltare un'analisi per guadagnare tempo. Più veloce sì, perdere pezzi no.
- Mai cambiare una flag attesa o un URL in `app/tests/real_challenges*.py` per far
  passare un test; un caso si sposta da `GAPS` a `EXTRA` solo se la verifica lo trova.

**Come si scrive un analyzer**
- Copia lo schema di un analyzer simile e recente (`dsstore.py`, `cryptojs.py`,
  `androidboot.py`): classe `Analyzer`, `accepts`, `display_order` libero, `register()`,
  import in `analyzers/__init__.py`, nome in `DEFAULT_PLAN` (unica riga ammessa in `planner.py`).
- Gating: deve uscire `skipped` in pochi millisecondi sui file che non lo riguardano
  (estensione/mime + firma nei primi byte). Niente letture intere per decidere.
- Comandi esterni solo con `ctx.run(...)` / `run_cmd(...)` (lista di argomenti, timeout).
  Mai `shell=True`, mai `subprocess` diretto.
- Tetti: dimensione in ingresso, byte in uscita (`output[:200_000]`), numero di figli.
- Helper già pronti, da riusare (niente copie): `analyzers/util.py` (`load_text`,
  `load_image`, `printable_ratio`, `magic_ext`, `xor_known_prefix`, `bits_to_ints`…),
  `magic.py` (firme), `flagpatterns.FLAG_PREFIXES`, `cracking.resolve_wordlists`.
- Tool nuovi solo da pacchetti apt o pip **con versione fissata** in `app/Dockerfile`.

**Verifica (in quest'ordine, tutto deve passare)**
1. `app/tests/run_unit.sh` — più un test nuovo in `app/tests/test_<analyzer>.py`
   che usa un file minuscolo generato nel test (niente rete).
2. `./ctf lint` → `[ok] lint clean`.
3. `docker compose build stegsuite && docker compose up -d stegsuite term`.
4. Il caso reale del task: `cd app/tests && python3 real_challenges.py --gaps --only-new -k <nome>`.
5. Non regressione: `cd app/tests && python3 real_challenges.py -j 3 --only-new --extra`
   e `./ctf test -j 3` → stessi PASS di prima (oggi: extra 47/47, fixture 33/33,
   reali 35/35, `ALL CORRECT`). **Una sola FAIL nuova = non si pusha.**
- Non modificare file sotto `app/` o `ctf` mentre una verifica è in corso.

**Commit e issue**
- Un commit per task, messaggio in inglese, `Fixes #N` **solo se il task è completo**;
  se è parziale: `Refs #N` e un commento sull'issue con cosa manca.
- In fondo a `tasks/deepseek.md` aggiorna lo "Stato": cosa è fatto, i numeri della
  verifica (copiati dall'output, non a memoria), cosa resta.
- Non dichiarare "fatto" senza l'output dei comandi sopra. Se un comando fallisce,
  scrivilo così com'è.

**Quando fermarsi**
- Due tentativi falliti sullo stesso problema → fermati, scrivi in "Bloccato" cosa hai
  provato e l'errore esatto, passa al task successivo.
- Docker non risponde (`docker info` fallisce) → fermati e chiedi all'utente.

## Definition of Done

1. `docker compose config -q` passa senza errori.
2. I servizi toccati partono e rispondono a runtime (`./ctf up` + check URL);
   per StegSuite: `app/tests/run_unit.sh` + `./ctf test -j 3` senza regressioni
   (stesse challenge risolte o di più) e `./ctf lint` pulito.
3. Dashboard e `README.md` coerenti con il compose.
4. Nessun segreto committato (`.env` è in `.gitignore`).
5. Stato aggiornato in `tasks/todo.md` e `tasks/plan.md`.
