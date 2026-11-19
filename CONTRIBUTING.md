# Contribuire a CTF Toolbox

Questo file è il punto di partenza per chi arriva da fuori: setup, flusso di
lavoro e dove trovare le regole complete. **Le regole vincolanti stanno in
[`AGENTS.md`](AGENTS.md)**: qui sono solo riassunte, non sostituite.

## Prima di iniziare

- **Docker-first**: niente tool installati sull'host, tutto gira nei container.
- **Solo locale**: le porte si pubblicano su `127.0.0.1`, sempre `19000+`
  (modificabili da `.env`). La macchina può ospitare altri stack: mai porte basse.
- **Una issue = un analyzer o una funzione.** Apri (o scegli) una issue prima di
  scrivere codice e non allargare il perimetro: il lavoro fuori tema va in una
  issue separata.

## Setup

```bash
git clone https://github.com/dexRand/ctf-docker.git
cd ctf-docker
./ctf up                      # crea .env, avvia il core e aspetta che sia pronto
./ctf status                  # stato dei container e URL
./ctf test --fast -j 3        # fixture + 11 casi rappresentativi (~5 min)
```

Il primo avvio costruisce l'immagine StegSuite (qualche minuto). I tool pesanti
stanno dietro i profili Compose (`web`, `recon`, `crypto`, `forensics`, `crack`,
`audio`, `rev`): `./ctf up <profilo>`. Il resto in [`README.it.md`](README.it.md).

## Flusso di lavoro

1. **Issue** — descrivi sintomo e risultato atteso; per un analyzer nuovo allega
   un file di input minimo.
2. **Branch** — uno per issue, es. `feat/42-nome-analyzer`, da `main`. Per il
   lavoro in parallelo si usa un worktree per branch (vedi `AGENTS.md`).
3. **TDD** — prima un test che fallisce col codice attuale
   (`app/tests/test_<x>.py`, file minuscolo generato nel test, niente rete), poi
   il codice minimo che lo rende verde. Mock solo per i tool esterni.
4. **Commit** — uno per issue, messaggio in inglese, `Fixes #N` solo se il task è
   completo, altrimenti `Refs #N`. Mai `git stash` in un worktree.
5. **Pull request** — spiega il cambio e incolla l'output delle verifiche
   (copiato, non a memoria).

Nuovo analyzer: parti da [`docs/ADDING-A-TOOL.md`](docs/ADDING-A-TOOL.md).
Nuova funzione di StegSuite: esiste come endpoint REST (e, se utile a un'IA,
come tool MCP), documentata in [`docs/API.md`](docs/API.md).

## Convenzioni

- Nomi di tool, file e comandi in **inglese**; descrizioni e documentazione in
  **italiano**.
- Riusa ciò che esiste (`app/backend/analyzers/util.py`, `base.py`, `magic.py`,
  `flagpatterns.py`): niente copie di helper.
- Comandi esterni solo via `ctx.run(...)` / `run_cmd(...)`; mai `shell=True`,
  mai `subprocess` diretto.
- Tetti sempre: dimensione in ingresso, byte in uscita, numero di figli, timeout.
- **Niente regole su misura per una singola challenge**: una trasformazione entra
  nel codice comune solo se è generica.
- **File vietati senza richiesta esplicita**: `app/backend/planner.py`,
  `pipeline.py`, `flaghunt.py`, `flagpatterns.py`, `tree.py`, `storage.py`,
  `api/fileresp.py`, `ctf`, `compose.yaml`, `.github/`, `analyzers/vision.py`,
  `magic.py`. Se ti servono, chiedilo prima nella issue.
- Non cambiare mai una flag attesa o un URL in `app/tests/real_challenges*.py`
  per far passare un test: un caso si sposta da `GAPS` a `EXTRA` solo se la
  verifica lo trova.

L'elenco completo — perimetro, gating, budget, lezioni dai batch — è in
[`AGENTS.md`](AGENTS.md).

## Come validare

I tre livelli e i comandi esatti sono definiti in `AGENTS.md` (sezione
*Livelli di verifica*). In sintesi:

- **L0** — `./ctf lint` (ruff, bandit, vulture, jscpd) e `docker compose config -q`.
- **L1** — `app/tests/run_unit.sh app/tests/test_<x>.py`, poi il caso reale che
  ti riguarda, sotto il lock di StegSuite (comando in `AGENTS.md`).
- **L2** — il gate completo (`./ctf test`) gira **solo in CI**, sulla PR: non
  lanciarlo in locale. Una sola FAIL nuova in L2 blocca il merge.

## Licenza e autori

Il progetto è distribuito con licenza MIT (vedi [`LICENSE`](LICENSE)):
contribuendo accetti gli stessi termini. Gli autori sono in [`AUTHORS`](AUTHORS);
aggiungiti lì nella stessa pull request che porta il tuo contributo.
