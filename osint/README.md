# osint — area di lavoro del collega OSINT

Questa cartella è **tua**. Non toccare i file del core
(`compose.yaml`, `.env.example`, `config/homepage/`, `rev/`, `zap/`, `app/`):
tutto ciò che ti serve sta qui dentro.

## Avvio (compose completo + la tua parte)

Dalla radice del repo:

```bash
./ctf up                                   # core (Homepage, StegSuite, …)
docker compose -f compose.yaml -f osint/compose.yaml up -d   # core + i TUOI servizi
```

Il file `osint/compose.yaml` è un **override**: aggiunge i tuoi servizi senza
modificare `compose.yaml`. Il tuo servizio sta sulla rete **`ctfnet`**, quindi
raggiunge gli altri tool **per nome servizio** (nessuna porta host da litigare):

| Servizio | URL dalla rete `ctfnet` | URL dall'host |
|---|---|---|
| StegSuite API | `http://stegsuite:19014/api/v1` | `http://localhost:19014/api/v1` |
| StegSuite Swagger | `http://stegsuite:19014/api/docs` | `http://localhost:19014/api/docs` |
| SpiderFoot | `http://spiderfoot:8080` | `http://localhost:19007` |
| Whisper-WebUI (Gradio API) | `http://whisper:7860` | `http://localhost:19017` |
| ZAP (profilo `web`) | `http://zap:8090` | `http://localhost:19006` |

## Le API da usare

**StegSuite** è quella pensata per l'integrazione: REST completa, OpenAPI su
`/api/docs`, e la documentazione in [`../docs/API.md`](../docs/API.md). Esempio
pronto in [`example_client.py`](./example_client.py) (solo stdlib).

```bash
# health + elenco tool
curl -s http://localhost:19014/api/v1/health
curl -s http://localhost:19014/api/v1/tools | jq -r '.[].name'

# tool singolo, stateless (upload → output + artifact)
curl -s -F file=@challenge.png http://localhost:19014/api/v1/tools/binwalk-extract | jq .

# flusso "progetto" (ricorsivo, Auto/Check)
PID=$(curl -s -F mode=auto -F files=@a.png http://localhost:19014/api/v1/projects | jq -r .id)
curl -X POST http://localhost:19014/api/v1/projects/$PID/start
curl -s http://localhost:19014/api/v1/projects/$PID/findings | jq .
```

Se `STEGSUITE_API_KEY` è impostata nel `.env`, aggiungi `X-API-Key: <key>` a
ogni chiamata (anche tu: mettila nel tuo `.env`, mai nel repo).

## Il contratto (poche regole, per non farci casini)

1. **Il core non si tocca.** I tuoi file stanno in `osint/`. In git, `osint/` è
   tuo (vedi `CODEOWNERS` alla radice): nessun conflitto con me.
2. **Porte solo da `.env`**: le tue porte stanno in `OSINT_PORT`/… nel tuo `.env`
   (gitignored). Il core usa la fascia 19000+; tu usa la **19050+**.
3. **Prima di ogni push**: `docker compose -f compose.yaml -f osint/compose.yaml config -q`.
4. **Segreti e dati mai in git**: `.env` e `data/` sono già in `.gitignore`.
5. **Scope**: niente OSINT attivo su target reali senza autorizzazione.

## Aggiungere un tuo servizio

In `osint/compose.yaml` aggiungi un servizio e mettilo su `ctfnet`:

```yaml
services:
  mio-scanner:
    image: <upstream image>          # meglio immagini upstream, evita build custom
    restart: unless-stopped
    mem_limit: 1g
    cpus: 1
    ports:
      - "127.0.0.1:${OSINT_PORT:-19050}:8000"   # solo localhost
    networks: [ctfnet]
```

Dentro il container chiama StegSuite con `http://stegsuite:19014/api/v1`.
