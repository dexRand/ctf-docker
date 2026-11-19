# Aiuto e supporto

Prima di aprire una issue, dai un'occhiata a quello che c'è già:

- **Avvio, tool, problemi comuni**: [`README.it.md`](README.it.md) (in inglese:
  [`README.md`](README.md)) — sezioni *Avvio rapido*, *Configurazione* e
  *Problemi comuni*.
- **StegSuite, API e nuovi analyzer**: [`docs/API.md`](docs/API.md),
  [`docs/ADDING-A-TOOL.md`](docs/ADDING-A-TOOL.md) e
  [`docs/CHALLENGES.md`](docs/CHALLENGES.md).
- **Come contribuire**: [`CONTRIBUTING.md`](CONTRIBUTING.md); regole complete e
  livelli di verifica in [`AGENTS.md`](AGENTS.md).
- **Condotta**: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Aprire una issue

Le issue si aprono su
<https://github.com/dexRand/ctf-docker/issues> scegliendo il template:

- **Bug report** — qualcosa non funziona in un analyzer, un servizio, la CLI o
  un test.
- **Nuovo analyzer** — una nuova analisi o funzione di StegSuite.

Nel report metti sempre il sintomo, il file o comando minimo che lo riproduce,
il comportamento atteso e quello osservato, e l'output delle verifiche
**copiato**, non riassunto. Se riguarda una challenge, allega solo il file
distribuito dall'evento. Non incollare segreti (`.env`, token, chiavi).

Per un problema di sicurezza, non scrivere i dettagli in una issue pubblica:
aprine una senza dettagli e chiedi ai manutentori un canale privato.
