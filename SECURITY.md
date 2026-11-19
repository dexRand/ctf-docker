# Sicurezza

CTF Toolbox legge ed elabora file non fidati (gli allegati delle challenge) ed
espone porte, API e ambienti di lavoro sull'host. Se trovi una vulnerabilità
ti chiediamo di segnalarla in privato, prima di renderla pubblica.

## Come segnalare

Usa il **private vulnerability reporting** di GitHub:

1. apri la scheda **Security** del repository
   (<https://github.com/dexRand/ctf-docker/security>);
2. clicca **Report a vulnerability** per aprire una security advisory privata
   in bozza, visibile solo a te e ai manutentori.

Nella segnalazione scrivi:

- componente interessato (analyzer, backend/API, compose, CLI `ctf`, …) e
  versione o commit;
- passi per riprodurre il problema e il file o comando minimo che lo innesca;
- impatto che hai osservato o che ritieni possibile;
- eventuale proof of concept.

Non allegare segreti reali (`.env`, token, chiavi) e, se il problema riguarda
una challenge, usa solo il file distribuito dall'evento.

Se il pulsante **Report a vulnerability** non è disponibile, **non scrivere i
dettagli in una issue pubblica**: aprine una senza informazioni tecniche e
chiedi ai manutentori un canale privato (come indicato in
[`SUPPORT.md`](SUPPORT.md)).

Non c'è un indirizzo email pubblico per le segnalazioni di sicurezza.

## Perimetro

**In scope**

- gli analyzer che parsano input non fidati: `app/backend/analyzers/**`
  (bomb, path traversal, esecuzione di comandi, output non limitato, …);
- il backend e l'API di StegSuite: `app/backend/`, `app/backend/api/`
  (autenticazione API key, gestione dei job, accesso ai file, MCP);
- il deployment Compose: `compose.yaml` (binding su `127.0.0.1`, gestione dei
  segreti, socket proxy `term-proxy`);
- il wrapper CLI `ctf`.

**Out of scope**

- le immagini upstream di terzi (sono fissate per digest: la segnalazione va
  ai rispettivi manutentori);
- i file delle challenge CTF in sé e i dati di lavoro in `./data/`;
- configurazioni volutamente aperte su reti non fidate (vedi il *Security
  model* del [`README.it.md`](README.it.md)).

## Tempistiche

- **Presa in carico** (acknowledge): entro **3 giorni lavorativi**.
- **Triage e severità provvisoria**: entro **7 giorni**.
- **Fix**: entro **30 giorni** per le vulnerabilità high/critical, entro
  **90 giorni** per medium/low, oppure una proroga motivata e comunicata.
- **Advisory**: pubblicata dopo il fix; chi ha segnalato viene citato, salvo
  sua richiesta di restare anonimo.

Grazie per aiutarci a tenere la suite sicura.
