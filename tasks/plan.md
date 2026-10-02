# Implementation Plan: CTF Toolbox

## Overview
Costruire nella repo `/home/r/__Github/CTF` (remote: `dexRand/ctf-docker`) un unico
`compose.yaml` che avvia i tool CTF più usati del mondo reale, tutti con GUI web,
su porte `9000+`, più una dashboard **Homepage** che li mostra ordinati per fase con
descrizione e stato. I tool pesanti sono dietro profili Compose opzionali.

## Architecture Decisions
- **Homepage** come dashboard (non Homarr/Dashy): config YAML versionabile, gruppi
  ordinabili, `description` per tool e `siteMonitor` per lo stato → è esattamente il
  requisito "vedere tutti i servizi, a cosa servono, ordinati".
- **Profili Compose** per i tool pesanti (`web`, `recon`, `forensics`, `crypto`) così
  un semplice `./ctf up` non satura la macchina già occupata da `veronabusapp`.
- **Nessun build custom in v1**: solo immagini upstream verificate con
  `docker manifest inspect`, per avere affidabilità e aggiornamenti.
- **Prefisso progetto `ctf`** e niente `container_name` fissi: zero collisioni con
  `veronabusapp-*`, `postgres`/`redis` interni ad AperiSolve non pubblicano porte.
- **Porte da `.env`** con default `9000+`, così restano modificabili senza toccare il compose.

## Tool selezionati (solo GUI web, realmente usati)
| Gruppo | Tool | Immagine | Porta host | Profilo |
|---|---|---|---|---|
| Dashboard | Homepage | `ghcr.io/gethomepage/homepage` | 9001 | core |
| Stego | AperiSolve | `ghcr.io/zeecka/aperisolve` | 9000 | core |
| Encoding/Crypto | CyberChef | `ghcr.io/gchq/cyberchef` | 9002 | core |
| Web | mitmproxy (mitmweb) | `mitmproxy/mitmproxy` | 9003/9004 | core |
| Utility | IT-Tools | `corentinth/it-tools` | 9011 | core |
| Web | OWASP ZAP (webswing) | `ghcr.io/zaproxy/zaproxy` | 9005/9006 | web |
| Recon | SpiderFoot | `dtagdevsec/spiderfoot` | 9007 | recon |
| Forensics | Wireshark | `ghcr.io/linuxserver/wireshark` | 9008/9009 | forensics |
| Crypto | SageMath Jupyter | `sagemath/sagemath` | 9010 | crypto |
| Cracking (opz.) | Hashtopolis | `hashtopolis/*` | — | crack |

Esclusi di proposito (nessuna immagine GUI upstream affidabile): Burp Suite, Ghidra,
Autopsy, Volatility, RsaCtfTool, hashcat/john (CLI, già sull'host Kali).

## Task List

### Phase 1: Scaffolding repo
- [ ] Task 1: Inizializzare repo (`git init`, remote `origin`), `.gitignore`
      (`.env`, volumi), `AGENTS.md` con le regole del repo.
- [ ] Task 2: Definire `.env.example` con tutte le porte `9000+`.
- [ ] Task 3: Scrivere `compose.yaml` — dashboard + tool core (Homepage, AperiSolve,
      CyberChef, mitmproxy, IT-Tools), project name `ctf`.

### Checkpoint: Core
- [ ] `docker compose config -q` passa
- [ ] `./ctf up` → dashboard 9001 e tool core rispondono
- [ ] Revisione umana prima dei profili heavy

### Phase 2: Dashboard
- [ ] Task 4: `config/homepage/settings.yaml` + `widgets.yaml`.
- [ ] Task 5: `config/homepage/services.yaml` con **tutti** i tool, ordinati per
      gruppo, `description` in italiano e `siteMonitor`.

### Phase 3: Tool pesanti (profili)
- [ ] Task 6: ZAP webswing (profilo `web`) — comando `zap-webswing.sh`, 2 porte.
- [ ] Task 7: SpiderFoot (profilo `recon`).
- [ ] Task 8: Wireshark (profilo `forensics`) — PUID/PGID/TZ.
- [ ] Task 9: SageMath Jupyter (profilo `crypto`).

### Phase 4: UX + doc
- [ ] Task 10: wrapper `./ctf` (`up`, `up <profilo>`, `up-all`, `down`, `status`, `logs`).
- [ ] Task 11: `README.md` con tabella tool, porte, comandi e note risorse.

### Checkpoint: Complete
- [ ] Ogni servizio incluso risponde a runtime
- [ ] Dashboard mostra tutti i tool con stato
- [ ] README coerente con compose/porte

## Risks and Mitigations
| Rischio | Impatto | Mitigazione |
|---|---|---|
| Conflitto porte con altri stack | Alto | tutte `9000+`, check `ss -tln` prima |
| RAM/CPU saturata (ZAP/Wireshark/SageMath) | Medio | profili opzionali + `mem_limit`/`cpus` |
| Immagine SpiderFoot/Wireshark Kasm non parte standalone | Medio | pin `dtagdevsec/spiderfoot:24.04.1`; Wireshark LinuxServer (non Kasm) |
| Homepage blocca host non-localhost | Basso | `HOMEPAGE_ALLOWED_HOSTS` in `.env` |
| Segreti committati | Alto | `.env` in `.gitignore`, solo `.env.example` |

## Open Questions
1. Set tool OK o da ridurre? (vedi SPEC §Open Questions)
2. Profili opzionali per i pesanti: confermato?
3. Hashtopolis ora o dopo?
4. Push su `dexRand/ctf-docker` a fine lavoro?
