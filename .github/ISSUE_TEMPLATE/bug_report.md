---
name: Bug report
about: Qualcosa non funziona — analyzer, servizio, CLI o test
title: "[bug] "
labels: bug
assignees: ""
---

## Sintomo

<!-- Cosa non funziona, in una o due frasi. -->

## File o input che lo scatena

<!--
Allega il file minimo che riproduce il problema.
Per una challenge usa SOLO il file distribuito dall'evento (sezione
"Distribution" del README o `provide:` in challenge.yaml), mai un file preso
dalla soluzione.
-->

- file / URL / comando:
- dimensione:

## Comportamento atteso

## Comportamento osservato

<!--
Messaggi di errore completi. Per StegSuite: analyzer, stato (`skipped`, `done`,
`error`) e summary riportati nella GUI o nella risposta API.
-->

## Output delle verifiche

<!-- Copia l'output, non riassumerlo. Togli prima eventuali segreti (.env, token). -->

```text
$ git rev-parse --short HEAD
$ docker compose version
$ ./ctf status
$ docker compose config -q
$ app/tests/run_unit.sh app/tests/test_<x>.py
```

## Bloccato / note

<!-- Cosa hai già provato, cosa sospetti, cosa ti serve dai manutentori. -->
