# Implementation Plan: CTF Toolbox

> **Storico.** Il piano originale è completato (vedi `tasks/todo.md` per lo stato
> fase per fase). Le porte sono state spostate da `9000+` a **`19000+`** per non
> collidere con altri stack sull'host. Il lavoro successivo (StegSuite) è tracciato
> in `tasks/remaining.md`.

## Overview
Costruire nella repo ctf-docker (remote: `dexRand/ctf-docker`, allora in
`/home/r/__Github/CTF`) un unico `compose.yaml` che avvia i tool CTF più usati del
mondo reale, tutti con GUI web,
su porte `19000+` (originariamente `9000+`), più una dashboard **Homepage** che li
mostra ordinati per fase con descrizione e stato. I tool pesanti sono dietro profili
Compose opzionali.

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
- **Porte da `.env`** con default `19000+`, così restano modificabili senza toccare il compose.

## Tool selezionati (solo GUI web, realmente usati)
| Gruppo | Tool | Immagine | Porta host | Profilo |
|---|---|---|---|---|
| Dashboard | Homepage | `ghcr.io/gethomepage/homepage` | 19001 | core |
| Stego | AperiSolve | `ghcr.io/zeecka/aperisolve` | 19000 | core |
| Encoding/Crypto | CyberChef | `ghcr.io/gchq/cyberchef` | 19002 | core |
| Web | mitmproxy (mitmweb) | `mitmproxy/mitmproxy` | 19004/19003 | core |
| Utility | IT-Tools | `corentinth/it-tools` | 19011 | core |
| Web | OWASP ZAP (webswing) | `ghcr.io/zaproxy/zaproxy` | 19005/19006 | web |
| Recon | SpiderFoot | `dtagdevsec/spiderfoot` | 19007 | recon |
| Forensics | Wireshark | `ghcr.io/linuxserver/wireshark` | 19008/19009 | forensics |
| Crypto | SageMath Jupyter | `sagemath/sagemath` | 19010 | crypto |
| Cracking (opz.) | Hashtopolis | `hashtopolis/*` | — | crack |

Esclusi di proposito (nessuna immagine GUI upstream affidabile): Burp Suite, Ghidra,
Autopsy, Volatility, RsaCtfTool, hashcat/john (CLI, già sull'host Kali).

> **Aggiornamenti successivi** (stato vivo in `tasks/todo.md`): **AperiSolve** e il
> vecchio **Triage** sono **rimossi** (sostituiti da **StegSuite**, 19014, + FileBrowser
> 19012); aggiunti **Hashtopolis** (profilo `crack`, 19015/19016) e **Whisper-WebUI**
> (profilo `audio`, 19017, trascrizione audio con timestamp).

## Task List

### Phase 1: Scaffolding repo
- [x] Task 1: Inizializzare repo (`git init`, remote `origin`), `.gitignore`
      (`.env`, volumi), `AGENTS.md` con le regole del repo.
- [x] Task 2: Definire `.env.example` con tutte le porte `19000+`.
- [x] Task 3: Scrivere `compose.yaml` — dashboard + tool core (Homepage, AperiSolve,
      CyberChef, mitmproxy, IT-Tools), project name `ctf`.

### Checkpoint: Core
- [ ] `docker compose config -q` passa
- [ ] `./ctf up` → dashboard 19001 e tool core rispondono
- [ ] Revisione umana prima dei profili heavy

### Phase 2: Dashboard
- [x] Task 4: `config/homepage/settings.yaml` + `widgets.yaml`.
- [x] Task 5: `config/homepage/services.yaml` con **tutti** i tool, ordinati per
      gruppo, `description` in italiano e `siteMonitor`.

### Phase 3: Tool pesanti (profili)
- [x] Task 6: ZAP webswing (profilo `web`) — comando `zap-webswing.sh`, 2 porte.
- [x] Task 7: SpiderFoot (profilo `recon`).
- [x] Task 8: Wireshark (profilo `forensics`) — PUID/PGID/TZ.
- [x] Task 9: SageMath Jupyter (profilo `crypto`).

### Phase 4: UX + doc
- [x] Task 10: wrapper `./ctf` (`up`, `up <profilo>`, `up-all`, `down`, `status`, `logs`).
- [x] Task 11: `README.md` con tabella tool, porte, comandi e note risorse.

### Checkpoint: Complete
- [x] Ogni servizio incluso risponde a runtime
- [x] Dashboard mostra tutti i tool con stato
- [x] README coerente con compose/porte

## Risks and Mitigations
| Rischio | Impatto | Mitigazione |
|---|---|---|
| Conflitto porte con altri stack | Alto | tutte `19000+`, check `ss -tln` prima |
| RAM/CPU saturata (ZAP/Wireshark/SageMath) | Medio | profili opzionali + `mem_limit`/`cpus` |
| Immagine SpiderFoot/Wireshark Kasm non parte standalone | Medio | pin `dtagdevsec/spiderfoot:24.04.1`; Wireshark LinuxServer (non Kasm) |
| Homepage blocca host non-localhost | Basso | `HOMEPAGE_ALLOWED_HOSTS` in `.env` |
| Segreti committati | Alto | `.env` in `.gitignore`, solo `.env.example` |

## Open Questions
1. Set tool OK o da ridurre? (vedi SPEC §Open Questions)
2. Profili opzionali per i pesanti: confermato?
3. Hashtopolis ora o dopo?
4. Push su `dexRand/ctf-docker` a fine lavoro?
