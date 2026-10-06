<h1 align="center">CTF Toolbox</h1>

<p align="center">
  Cassetta degli attrezzi <strong>self-hosted</strong> e browser-based per
  <strong>risolvere le CTF</strong>.
  <br>
  Una sola dashboard, i tool essenziali con GUI web e un unico
  <code>docker compose up</code>.
</p>

<p align="center">
  <a href="README.md">🇬🇧 English</a> · <a href="README.it.md">🇮🇹 Italiano</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker Compose">
  <img src="https://img.shields.io/badge/ports-19000%2B-6E56CF" alt="Ports 19000+">
  <img src="https://img.shields.io/badge/images-upstream--only-informational" alt="Upstream images only">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
</p>

---

**CTF Toolbox** è uno stack Docker Compose che raccoglie i tool realmente usati
durante una Capture The Flag — steganalisi, encoding/crypto, intercettazione web,
OSINT, forensics e password — ognuno con **interfaccia web**, dietro un'unica
dashboard che li elenca **ordinati per fase di lavoro**, con una breve
descrizione e lo stato live.

È pensato per convivere con altre app self-hosted: ogni servizio gira sulla
**fascia 19000+**, così non collide con i soliti noti (8080, 9000, 5432, …), e i
tool pesanti stanno dietro **profili** Compose opzionali.

## ✨ Funzionalità

- **Una sola dashboard** ([Homepage](https://gethomepage.dev)) con tutti i tool,
  raggruppati per fase CTF, con descrizione e indicatore up/down.
- **GUI web ovunque** — niente X11 forwarding, niente desktop da installare.
- **Solo immagini upstream** — nessun build custom da mantenere; ogni immagine è
  un progetto reale e attivamente usato, verificato prima di essere aggiunto.
- **Tool pesanti opzionali** (ZAP, Wireshark, SageMath, SpiderFoot) dietro
  profili Compose, così `./ctf up` resta leggero.
- **Nessuna collisione di porte** — tutto su 19000+, modificabile da `.env`.
- **Stack isolato** — project name `ctf`, nessun `container_name` fisso; il
  `postgres`/`redis` interni ad AperiSolve non pubblicano porte.

## 🧰 Tool

| Fase | Tool | URL | A cosa serve | Profilo |
| --- | --- | --- | --- | --- |
| Dashboard | Homepage | http://localhost:19001 | Panoramica e stato di tutti i tool | core |
| Stego | **AperiSolve** | http://localhost:19000 | Steganalisi immagini: binwalk, zsteg, steghide, exiftool, foremost… | core |
| Crypto/Encoding | **CyberChef** | http://localhost:19002 | Base64, XOR, RSA, hashing, JWT e molto altro | core |
| Web | **mitmproxy** | http://localhost:19003 | Intercetta e modifica HTTP(S) · proxy su `:19004` | core |
| Utility | IT-Tools | http://localhost:19011 | Encoder, converter, hash, regex e simili | core |
| Deep triage | **CTF Triage** | http://localhost:19013 | Estrazione ricorsiva + cracking wordlist + flag hunt · GUI Auto/Check, report in FileBrowser Quantum (`./ctf triage <file>`) | core |
| Stego workbench | **StegSuite** | http://localhost:19014 | Analisi ricorsiva auto su 38 tool (stego, forensics, vision/OCR, audio/Morse), albero file, log live, terminale, API REST | core |
| Web | **OWASP ZAP** | http://localhost:19005/zap | Scanner di sicurezza web con GUI nel browser · proxy su `:19006` | `web` |
| Recon | SpiderFoot | http://localhost:19007/spiderfoot/ | OSINT automation: domini, IP, email, leak | `recon` |
| Crypto | SageMath | http://localhost:19010 | Notebook Python/Sage per crypto e matematica | `crypto` |
| Forensics | Wireshark | http://localhost:19008 | Analisi pacchetti/pcap con GUI web | `forensics` |

> Esclusi di proposito perché senza immagine GUI upstream affidabile:
> Burp Suite, Ghidra, Autopsy, Volatility, hashcat/john (tool CLI, già su Kali).
> Il cracking distribuito (Hashtopolis) è in roadmap.

## 🚀 Avvio rapido

```bash
git clone https://github.com/dexRand/ctf-docker.git
cd ctf-docker
cp .env.example .env      # opzionale: ./ctf lo crea da solo
./ctf up
```

Poi apri la dashboard: **http://localhost:19001**

### Con Docker Compose puro

```bash
docker compose up -d                              # tool core
docker compose --profile web up -d                # core + OWASP ZAP
docker compose --profile web --profile recon up -d
docker compose down                               # ferma tutto
```

## 🎛️ CLI

Il piccolo wrapper `ctf` è un livello leggibile sopra Compose:

```bash
./ctf up                  # tool core
./ctf up web              # core + un profilo
./ctf up web forensics    # combina più profili
./ctf up-all              # tutto (pesante: diversi GB di immagini)
./ctf status              # stato container
./ctf logs wireshark      # segui i log di un servizio
./ctf triage <file>       # triage profondo ricorsivo (vedi sotto)
./ctf reports             # URL e credenziali del browser dei report
./ctf down                # ferma e rimuove i container
```

## 🔬 Triage profondo

`./ctf triage <file|cartella>` esegue una pipeline steg/forense completa in un
container basato sull'immagine AperiSolve e scrive un report consultabile in
**FileBrowser Quantum** (http://localhost:19012, nessun login).

C'è anche una **GUI web** su **http://localhost:19013** (linkata dalla dashboard)
con due modalità:

- **Auto** — fa tutto da sé e prova tutte le wordlist;
- **Check** — prima scansiona, poi mostra l'albero dei file e gli elementi
  bloccati e ti fa scegliere, per ognuno, quale wordlist usare (o saltare).

Automaticamente:

1. **ricorre**: `7z`, `binwalk -e`, `foremost` su ogni file estratto, finché
   l'albero non è esaurito (profondità limitata);
2. **analizza** ogni file: `strings`, `exiftool`, `zsteg`, `steghide`, `pdfinfo`…;
3. **caccia le flag** con pattern sensati (`ITS{}`, `flag{}`, `CTF{}`, `HTB{}`,
   `picoCTF{}` + uno generico sul testo stampabile);
4. quando incontra qualcosa **protetto da password** (zip/7z/PDF cifrati, o
   un'immagine che può nascondere un payload steghide) **si ferma e ti chiede
   quale wordlist usare**.

Gli attacchi usano il tool giusto per formato — `stegseek` (steghide),
`fcrackzip` + **`hashcat`** (ZIP, anche **AES-256** via il vendored
`zip2hashcat`), `pdfcrack` (PDF) — e le wordlist sono provate
**dalla più piccola alla più grande**, così le liste veloci partono per prime.
Una password trovata viene riusata automaticamente sugli altri file.

```bash
./ctf triage ./challenge.png            # interattivo: chiede la wordlist
./ctf triage ./challenge.png -w wordlists/rockyou.txt
./ctf triage ./challenge.png --yes      # nessun prompt: prova tutte, piccola→grande
./ctf triage ./dir --no-crack --depth 4 # nessun attacco password
```

Le wordlist più usate sono già incluse, ordinate dalla più piccola alla più
grande: `passwords.txt`, `500-worst-passwords`, `probable-v2_top-1575`,
`10k-most-common`, `darkweb2017_top-10000`, `rockyou-75` (nel repo) e la
**rockyou.txt** completa (14M voci, inclusa nell'immagine). Metti altri dizionari
in `./wordlists/` (montata read-only su `/wordlists`): compaiono nel menu
automaticamente, ordinati per dimensione.

| Profilo | Aggiunge |
| --- | --- |
| *(core)* | Homepage, AperiSolve, CyberChef, mitmproxy, IT-Tools |
| `web` | OWASP ZAP |
| `recon` | SpiderFoot |
| `crypto` | SageMath |
| `forensics` | Wireshark |

## 🔌 Porte

Tutte le porte host stanno nella **fascia 19000+** e sono configurabili in `.env`:

| Porta | Servizio |
| ---: | --- |
| 19000 | AperiSolve |
| 19001 | Homepage (dashboard) |
| 19002 | CyberChef |
| 19003 / 19004 | mitmweb UI / mitmproxy |
| 19005 / 19006 | ZAP UI (`/zap`) / ZAP proxy |
| 19007 | SpiderFoot |
| 19008 / 19009 | Wireshark HTTP / HTTPS |
| 19010 | SageMath (Jupyter) |
| 19011 | IT-Tools |
| 19012 | FileBrowser Quantum (report triage, senza login, solo localhost) |
| 19013 | GUI web triage (Auto/Check, solo localhost) |
| 19014 | StegSuite workbench + API (solo localhost) |
| 19181 | RQ Dashboard (AperiSolve, solo localhost) |

## 📂 Struttura

```
compose.yaml            definizione servizi (project name: ctf)
ctf                     wrapper CLI (up / up-all / down / status / logs)
.env.example            porte e configurazione
config/homepage/        configurazione dashboard (services / settings / widgets)
config/zap/             working dir ZAP (certificati)
SPEC.md                 specifica
tasks/                  plan.md + todo.md
.opencode/              Agent Skills (MIT — vedi ATTRIBUTION.md)
```

## 🧪 StegSuite (workbench stego)

**StegSuite** è l'app tutto-in-uno per stego/forensics (il sostituto di AperiSolve):
http://localhost:19014 (solo localhost).

- Modalità **Auto / Check**: Auto fa tutto e prova tutte le wordlist; Check
  scansiona e poi ti fa scegliere cosa attaccare.
- Analisi **ricorsiva e ordinata** su **40 tool**: `file`, `exiftool`,
  `identify`, `ffprobe`, `pdfinfo`, `strings`, `xxd`/`hexdump`/`hexyl`,
  `decode`, `pdfid`, `pdftotext`, `binwalk` (scan + `binwalk -e`), `foremost`,
  `nested-archive` (catene di archivi annidati), `7z`, `pngcheck`, `png-repair`,
  `image-repair` (JPEG/BMP header/altezza),
  `qr`, `pcap` (con decifratura TLS se fornita la chiave), `zsteg`, `steghide`,
  `outguess`, `jsteg`, `png-chunks`, `openstego`, `bit-planes`,
  `channel-remap`, `image-enhance`, `gif-frames` (split + frame-diff +
  decodifica delay + OCR per frame), `ocr` (tesseract), `morse`,
  `morse-text`, `dtmf`, `spectrogram`, `waveform`, `wav-lsb`, `sstv` (Scottie S1/S2).
- **GUI**: tema terminale, **inglese di default** con switch **EN/IT** in
  qualsiasi momento (scelta memorizzata), albero file, output per tool, figli
  estratti, anteprime immagini/audio, log live via WebSocket, **terminale**
  integrato (xterm.js) e **report** Markdown con selettore lingua dedicato.
- **Flag hunt + cracking**: ZIP (anche AES via hashcat), steghide, PDF.
- **API REST** (OpenAPI su `/api/docs`), incluso il singolo tool stateless:
  `POST /api/v1/tools/{tool}`.

## ⚙️ Configurazione

Tutto è guidato da `.env` (creato da `.env.example`):

| Variabile | Scopo |
| --- | --- |
| `*_PORT` | Porta host di ogni servizio (tutte in 19000+) |
| `HOMEPAGE_ALLOWED_HOSTS` | Host ammessi verso la dashboard (aggiungi l'IP LAN per accesso remoto) |
| `MITMWEB_PASSWORD` | Password per la GUI di mitmweb (l'utente è ignorato) |
| `WORDLIST` | Wordlist di default usata dal triage |
| `PUID` / `PGID` / `TZ` | Mappatura utente e timezone per Wireshark |
| `POSTGRES_*`, `DB_URI`, `REDIS_URL` | Database/broker interni ad AperiSolve (non esposti) |

## 📝 Note

- **Primo avvio**: scarica immagini pesanti (ZAP, Wireshark, SageMath), servono
  alcuni minuti. Eseguire *tutti* i profili insieme richiede circa **8 GB di RAM libera**.
- **SageMath** stampa il token d'accesso a Jupyter nei log:
  `./ctf logs sagemath`.
- **mitmproxy** richiede una password: la pagina di login usa `MITMWEB_PASSWORD`
  (default `mitm`). Lo stato in dashboard controlla un endpoint senza auth.
- **I tool con profilo** risultano *down* in dashboard finché non avvii il
  profilo — è normale.
- L'immagine **triage** è l'unica costruita in locale (dall'immagine AperiSolve,
  con l'aggiunta di `stegseek`, `john`, `fcrackzip`, `pdfcrack`); il primo
  `./ctf up` la compila una volta.
- **FileBrowser Quantum** (il fork mantenuto del FileBrowser archiviato) è
  esposto solo su `127.0.0.1` e gira **senza login** (`auth.methods.noauth`).
- AperiSolve usa `postgres` e `redis` interni; **non** sono pubblicati sull'host e
  non toccano altri database.

## 🤖 Agent Skills

Le skill in `.opencode/skills/` provengono da
[`addyosmani/agent-skills`](https://github.com/addyosmani/agent-skills) (MIT).
Vedi [`.opencode/ATTRIBUTION.md`](.opencode/ATTRIBUTION.md) e
[`AGENTS.md`](AGENTS.md).

## 📚 Documentazione

- Specifica: [`SPEC.md`](SPEC.md)
- Piano e task: [`tasks/plan.md`](tasks/plan.md) · [`tasks/todo.md`](tasks/todo.md)
- Guida per agenti: [`AGENTS.md`](AGENTS.md)

## 📄 Licenza

MIT — vedi [`LICENSE`](LICENSE) per il progetto e
[`.opencode/LICENSE-agent-skills`](.opencode/LICENSE-agent-skills) per le Agent
Skills importate.
