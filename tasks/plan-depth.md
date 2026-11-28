# Piano — profondità d'analisi (normal / deep / full) + backlog #11–#16

Obiettivo concordato: massimizzare le flag CTF risolte per unità di sforzo, con un
**default `normal` rapido su tutte** le challenge (nessun numero fisso: "il più
veloce possibile senza perdere flag", misura prima/dopo, regola del 5%) e un
**override manuale per singola challenge** che alza la profondità.

## Modello a tre livelli

| Livello | Cosa gira | Costo | Quando |
|---|---|---|---|
| `normal` | `DEFAULT_PLAN` attuale **meno** i costosi a bassa resa (spostati sotto) | veloce (default) | sempre |
| `deep` | `normal` + tecniche medie (demod audio FSK/ASK/SAME, morse su rumore, aCropalypse, WPA/*2john leggeri, più OCR/carving selettivo) | minuti | richiesta manuale |
| `full` | tutto, inclusi gli uber-pesanti (Volatility 3, core-dump GDB, brute-force rockyou, TLS/FTPS/SSH) | ore | richiesta manuale |

I pesanti (WPA, core-dump, TLS/FTPS/SSH) stanno **solo in `full`** (sono lunghi).

## Esposizione

- Parametro API `depth` (`normal`|`deep`|`full`) — sorgente di verità.
- SPA: dropdown sul dettaglio della challenge / sull'upload.
- CLI `ctf`: flag `--depth <livello>`.
- Internamente si chiama **`tier`**: `planner.py` usa già `depth` per la
  ricorsione degli archivi (non collidere).

## Classificazione dei tier

- Ogni analyzer/azione ha un attributo `tier` (`normal`/`deep`/`full`); il planner
  filtra il piano in base al tier richiesto. Gli analyzer esistenti restano
  `normal` finché non ne viene dimostrato il costo (misura) e spostati sotto solo
  con la prova del prima/dopo.
- File toccati (autorizzati esplicitamente dall'utente il 20/11): `planner.py`,
  l'API (parametro `depth` + validazione), la SPA (dropdown), il wrapper `ctf`.

## Backlog ordinato (sub-feature → flag → tier)

Ordine per resa/sforzo, tecniche **generiche** (niente regole su misura per una
singola challenge). Epic di riferimento tra parentesi.

### deep — rapide e generiche (1 flag ciascuna)
1. ~~**FSK demod** (audio) → `bk23-weather.wav` · #15~~ ✅ FATTO (28/11, PR #63): consolidato in un unico analyzer `same` insieme a SAME ×3.
2. **ASK demod** (audio) → `sleepy.mp3` · #15
3. ~~**SAME ×3** (audio, errori volontari) → `warning.wav` · #15~~ ✅ FATTO (28/11, PR #63): analyzer `same` (SAME/EAS FSK + best-2-of-3 + canale "errors"); `tier=normal` (misurato ~4s, high-yield).
4. **Morse su musica/rumore** → `blinkybill.wav`, `robot.wav` · #15
5. **aCropalypse** (dati dopo IEND) → `wani23-apocalypse.png` · #15
6. **ZIP timestamps** → `b1g_mac.zip` · #13
7. **Profilo Firefox** (login/artifact) → `ictf23_web.zip` · #13
8. **TrevorC2 AES** (chiave di default) → `uoft24-illusion.pcapng` · #11
9. ***2john PDF** (crack via hashcat) → `bk24-the_cia.pdf` · #14
10. **Audio reverse/speed + stego** → `du22-rage.wav` · #15

### full — pesanti (solo su richiesta)
11. **WPA con wordlist più grosse** → `ui21-megacorp-01.cap` · #11
12. **Core dump / Volatility 3** → `bk24-wreck-dump` · #13
13. **TLS/FTPS/SSH decrypt** → `tcp1p23-compromised.pcap`, `du25-fishy-capture.pcapng`, `tcp1p23-reminiscence.pcap` · #11

### Fuori scope (ora)
Case-specific o bloccate: Piet (`npiet` assente), esolang "aussie", Minecraft 3D,
Discord deleted files, steno keyboard, PNG "knitting", OCR WordArt/graffiti,
`.pyc`/wasm2wat (nessun caso reale che li sblocca).

## Blocco 1 — meccanismo depth (prerequisito) ✅ FATTO (issue #40, PR #57)

Prima di implementare i sub-feature: introdurre `tier` nel planner + `depth` in
API/SPA/CLI, e ri-tierare gli analyzer esistenti (spostare fuori da `normal` i
costosi a bassa resa, con misura prima/dopo). È il blocco che rende "rapido su
tutte" possibile e che abilita i livelli sotto.

**Chiuso 27/11 (commit `8544f3d`):** `planner._plan_for(..., tier=...)` filtra per
rank (normal<deep<full, `TIERS`/`_TIER_RANK`); `Project.depth` + migrazione `0004`;
API `depth` (create/PATCH, 422 su invalido) + SPA dropdown + CLI `./ctf scan --depth`;
ri-tiering `sstv`+`wpa` → `deep`. Verifica: unit **553 passed**, `lint clean`,
`--fast` fixture **33/33** + reali **11/11** + writeup **ALL CORRECT** (1451.0s → 1362.5s),
L2 CI verde. Nessuna flag persa.

Follow-up aperti dal blocco (non bloccanti per i sub-feature `deep`, necessari prima
di `full`):
- **`full` oggi == `deep`** (nessun analyzer è `full`): si materializza con #51/#52/#53.
- **`real_challenges.py`/`verify_flags.py` non threadano `--depth`** (issue #59): senza,
  la verifica `--gaps -k <nome>` dei casi `deep`/`full` girerebbe a `normal` in silenzio.

## Come si misura

- Tempi `ToolRun.started_at/finished_at` prima/dopo, copiati nei commit.
- Regola del 5% sulla suite (fixture + reali + extra): mai rallentare oltre, mai
  perdere una flag risolta.
- Un caso passa da `GAPS` a `EXTRA` solo con il file distribuito dalla challenge e
  il PASS incollato.

## Vincoli invariati (da `AGENTS.md`)

- Gating su estensione/mime/firma nei primi byte: `skipped` in pochi ms sui file
  non pertinenti; niente letture intere per decidere.
- Tetti prima del lavoro (input, output, figli, deadline); comandi solo
  `ctx.run`/`run_cmd` (mai `shell=True`/`subprocess`).
- Niente duplicati (helper in `util.py`/`base.py`); tool nuovi solo apt/pip pinnati
  in `app/Dockerfile`.
- Un test nuovo in `app/tests/test_<x>.py` per ogni tecnica (file minuscolo, niente
  rete), che fallisce col codice vecchio.

## Issue create

Ogni riga del backlog → una issue GitHub (un pezzo delegabile), più una issue per il
blocco depth. Ogni issue riporta epic di riferimento, caso reale, criterio di
"fatto" e vincoli.
