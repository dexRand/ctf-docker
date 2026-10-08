# Spec: CTF Toolbox (repo `ctf-docker`)

## Objective
Raccogliere in un'unica repo Docker Compose i tool **realmente usati** per risolvere
CTF, il più possibile **con GUI web**, esposti su porte `9000+` per non entrare in
conflitto con gli altri progetti della macchina. Un'unica dashboard mostra tutti i
servizi, **ordinati per fase di lavoro**, con una descrizione di a cosa servono e lo
stato up/down.

Utente: studente ITS Cybersecurity che prepara/risolve CTF in locale.

## Tech Stack
- Docker + Docker Compose v2 (immagini pre-costruite, nessun build custom in v1).
- Dashboard: [Homepage](https://gethomepage.dev) (`ghcr.io/gethomepage/homepage`).
- Config dashboard in `config/homepage/` (YAML versionato).

## Commands
```bash
./ctf up                 # avvia il profilo core (dashboard + tool leggeri)
./ctf up <profilo>       # es. ./ctf up web
./ctf up-all             # avvia tutto
./ctf down               # ferma tutto
./ctf status             # stato container
docker compose config    # valida il compose
```

## Project Structure
```
compose.yaml            → definizione servizi (project name: ctf)
.env.example / .env     → porte e configurazione (segreti, non committare .env)
config/homepage/        → services.yaml, settings.yaml, widgets.yaml
config/scripts/         → script di supporto (es. helper)
ctf                     → wrapper CLI (up/down/up-all/status/logs)
SPEC.md                 → questa specifica
tasks/                  → plan.md + todo.md (piano di lavoro)
.opencode/              → Agent Skills (importate, licenza MIT in ATTRIBUTION.md)
README.md               → guida utente rapida
```

## Code Style
- Un servizio = un blocco YAML con `image` pinned + `restart: unless-stopped`.
- Porte sempre `${NOME_PORTA:-default}:<interna>` così sono modificabili da `.env`.
- Nomi tool **in inglese** nelle config, spiegazioni **in italiano**.
- Nessun `container_name` fisso: si usa il prefisso del progetto (`ctf-*`) per non
  collidere con gli altri stack (es. `veronabusapp-*`).
- Profili Compose per i tool pesanti: `web`, `recon`, `crypto`, `forensics`, `crack`, `audio`.

## Testing Strategy
Repo infrastrutturale: la "suite" è la verifica a runtime.
- `docker compose config -q` → sintassi valida.
- `curl`/`siteMonitor` di Homepage → ogni servizio risponde 2xx/3xx.
- Checkpoint manuale: dashboard raggiungibile e ogni tool apre la sua GUI.

## Porte (fascia 19000+, scelta anti-collisione)
| Porta | Servizio | Uso |
|------:|----------|-----|
| 19000 | *(libero — AperiSolve rimosso)* | — |
| 19001 | Homepage | dashboard |
| 19002 | CyberChef | encoding/crypto |
| 19003 | mitmweb UI | GUI proxy HTTP(S) |
| 19004 | mitmproxy | proxy (browser) |
| 19005 | ZAP Webswing UI | web scanner (`/zap`) |
| 19006 | ZAP proxy | proxy (browser) |
| 19007 | SpiderFoot | OSINT |
| 19008 | Wireshark http | pcap |
| 19009 | Wireshark https | pcap (TLS) |
| 19010 | SageMath Jupyter | crypto/math |
| 19011 | IT-Tools | utility varie |
| 19012 | FileBrowser Quantum | browse `./data` (senza login, solo localhost) |
| 19014 | StegSuite | workbench stego + GUI + API (solo localhost) |
| 19015 / 19016 | Hashtopolis | backend / frontend crack distribuito (profilo `crack`) |
| 19017 | Whisper-WebUI | trascrizione audio → testo/SRT con timestamp (profilo `audio`) |

## StegSuite (workbench stego/forensics)
App tutto-in-uno (porta 19014, solo localhost) che ha **sostituito** il vecchio
deep triage (CLI + GUI su 19013) e AperiSolve. Due modalità: **Auto** (fa tutto e
prova le wordlist) e **Check** (scansiona, poi scegli cosa attaccare). Analisi
ricorsiva e ordinata su **41 tool** (metadati, testo, stego, immagini/OCR,
audio/SSTV, pcap, estrazione archivi) + flag hunt configurabile (`FLAG_PATTERN`)
+ estrazione ricorsiva (7z/binwalk/foremost) + cracking (stegseek, fcrackzip,
hashcat+zip2hashcat, pdfcrack, bkcrack). Risultati via GUI/API; i report stanno
in `./data/` e si consultano con FileBrowser Quantum (noauth).

## Boundaries
- **Always:** verificare che la porta sia libera prima di aggiungere un servizio;
  validare con `docker compose config`; aggiornare dashboard e README insieme al compose.
- **Ask first:** aggiungere un tool nuovo o un'immagine > 1 GB; cambiare le porte;
  abilitare profili pesanti di default; push su remoto.
- **Never:** committare `.env` o segreti; usare porte < 9000 (occupate da altri
  progetti); attaccare target fuori dallo scope delle CTF.

## Success Criteria
- [ ] `docker compose config -q` passa senza errori.
- [ ] `./ctf up` avvia dashboard + tool core, tutte le porte sono `9000+`.
- [ ] La dashboard elenca **tutti** i tool ordinati per fase, con descrizione e stato.
- [ ] Ogni tool incluso è un'immagine upstream reale e verificata (le sole
      eccezioni documentate sono i build `app/Dockerfile` per StegSuite e `zap/Dockerfile`).
- [ ] README spiega avvio, profili e a cosa serve ogni tool.
- [ ] StegSuite (`./ctf up`, porta 19014) analizza ricorsivamente, caccia le flag
      e, sui file bloccati, fa scegliere la wordlist; report in FileBrowser Quantum.

## Decisions
1. Set completo di tool confermato (tutti quelli elencati).
2. Porte spostate sulla fascia **19000+** per ridurre al minimo le collisioni.
3. Tool pesanti come profili opzionali: `web`, `recon`, `crypto`, `forensics`, `crack`, `audio`.
4. Hashtopolis (cracking distribuito) implementato nel profilo `crack` (frontend + backend + MySQL).
5. Push di fine lavoro su `https://github.com/dexRand/ctf-docker.git`.
6. README principale in **inglese** (`README.md`), versione italiana in `README.it.md`.
