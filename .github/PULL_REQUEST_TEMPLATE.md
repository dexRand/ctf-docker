## Cosa cambia

<!-- In due o tre righe: quale issue, quale analyzer o funzione, perché. -->

Refs #<numero-issue> <!-- `Fixes` solo se il task è completo -->

## Perimetro

- [ ] **Un task = un analyzer o una funzione**: niente refactor o fix fuori tema
      nello stesso commit (il resto va in una issue separata).
- [ ] Nessuna analisi tolta o saltata per guadagnare tempo.
- [ ] Nessun file vietato toccato senza ok esplicito nella issue:
      `app/backend/planner.py` (solo l'unica riga ammessa in `DEFAULT_PLAN`),
      `pipeline.py`, `flaghunt.py`, `flagpatterns.py`, `tree.py`, `storage.py`,
      `api/fileresp.py`, `ctf`, `compose.yaml`, `.github/` (a parte i template
      richiesti dalla issue), `analyzers/vision.py`, `magic.py`.
- [ ] Nessuna flag attesa o URL cambiata in `app/tests/real_challenges*.py`.
- [ ] `CHANGELOG`, `TODO` e le spec non sono toccati.
- [ ] Nessun segreto nel diff (`.env`, token, chiavi).

## Verifiche

- [ ] **Unit**: `app/tests/run_unit.sh app/tests/test_<x>.py` — il test
      fallisce col codice vecchio e passa con quello nuovo.
- [ ] **L0**: `./ctf lint` pulito e `docker compose config -q` senza errori.
- [ ] **Caso reale** (L1), sotto il lock di StegSuite:

      flock /tmp/ctf-stegsuite.lock sh -c 'docker compose build stegsuite && \
        docker compose up -d stegsuite term && cd app/tests && \
        python3 real_challenges.py --gaps --only-new -k <nome>'

- [ ] **L2** non lanciato in locale: lo esegue la CI sulla PR.
- [ ] Caso reale nuovo (se presente): usa solo il file distribuito dalla
      challenge, e il suo PASS è incollato nel messaggio di commit.
- [ ] Gating e tetti verificati: `skipped` in pochi millisecondi sui file che
      non riguardano l'analyzer, dimensione in ingresso, byte in uscita,
      numero di figli, budget di tempo.
- [ ] Comandi esterni solo via `ctx.run(...)` / `run_cmd(...)`, mai
      `shell=True` né `subprocess` diretto.

## Output delle verifiche

<!-- Copia l'output dei comandi qui sopra, non riassumerlo. -->

```text
$ app/tests/run_unit.sh app/tests/test_<x>.py
...

$ ./ctf lint
...

$ docker compose config -q
...
```

## Bloccato / note

<!-- Cosa resta aperto, cosa non è stato possibile verificare e perché. -->
