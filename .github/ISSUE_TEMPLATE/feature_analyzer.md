---
name: Nuovo analyzer
about: Una issue = un analyzer o una funzione di StegSuite
title: "[analyzer] "
labels: analyzer
assignees: ""
---

## Cosa deve fare

<!-- Nome dell'analyzer, categoria e una riga di descrizione. -->

- nome:
- categoria (`metadata`, `text`, `hex`, `decode`, `extract`, `steg`, `vision`, `radio`, `audio`, `network`, `elf`, `forensics`):
- descrizione:

## File da toccare

- `app/backend/analyzers/<nome>.py` (nuovo, sullo schema di `dsstore.py`,
  `cryptojs.py`, `androidboot.py`)
- `app/backend/analyzers/__init__.py` (import)
- una sola riga in `DEFAULT_PLAN` di `app/backend/planner.py`, se deve girare da
  solo: nessun'altra modifica a quel file
- `app/tests/test_<nome>.py` (test con un file minuscolo generato nel test, niente rete)

## Gating

<!-- Deve uscire `skipped` in pochi millisecondi sui file che non lo riguardano,
senza leggere il file intero. -->

- estensione / mime:
- firma o struttura nei primi byte:

## Tetti

- dimensione in ingresso:
- byte in uscita (`output[:200_000]`):
- numero di figli / profondità di ricorsione:
- budget di tempo totale (deadline, non per iterazione):

## Tool esterni

<!-- Comandi solo via `ctx.run(...)` / `run_cmd(...)`, lista di argomenti,
timeout, mai shell=True. Pacchetto apt o pip con versione fissata in
`app/Dockerfile`, oppure "nessuno". -->

## Caso reale che sblocca

- evento / challenge:
- file distribuito (README "Distribution" o `provide:` di `challenge.yaml`):
- flag attesa:

## Criterio di "fatto"

- [ ] unit test che fallisce col codice vecchio e passa con quello nuovo
- [ ] gating verificato su un file che non lo riguarda
- [ ] L0 pulito: `./ctf lint` e `docker compose config -q`
- [ ] L1: unit + caso reale sotto il lock di StegSuite (comando in `AGENTS.md`)
- [ ] caso reale risolto, output incollato nel messaggio di commit

## Bloccato / note
