# Nuove fonti di CTF reali (ricognizione 27/10)

Repository pubbliche con **file della challenge + flag ufficiale**, controllate
via API GitHub (esistono e hanno la cartella forensics/misc). Già in uso:
picoCTF 2019/2021/2025, DUCTF 2023/2024, ImaginaryCTF 2023/2024, TJCTF 2023/2024,
LA CTF, UIUCTF 2023 (`app/tests/real_challenges_extra.py`).

Le colonne "dove sta la flag" sono da confermare aprendo un paio di casi prima di
aggiungerli a `EXTRA`/`GAPS`.

## Priorità alta: struttura pulita, file + flag nello stesso posto

| Repo | Cartella | Casi | Struttura (esempio) | Note |
|---|---|---|---|---|
| `TJCSec/tjctf-2025-challenges` | `forensics/` | 8 | `album-cover/`: `albumcover.png`, `flag.txt`, `challenge.yaml`, `solve.py` | stesso formato di TJCTF 2023/24 già usati; `flag.txt` diretto |
| `ImaginaryCTF/ImaginaryCTF-2025-Challenges` | `Forensics/` | 8 | `dinosaur/`: `dist/`, `metadata.yaml`, `README.md` | flag probabilmente in `metadata.yaml` (da confermare) |
| `cscosu/buckeyectf-2024-public` | `forensics/` | 7 | `couch_potato/`: `dump1.png`, `dump1.wav`, `challenge.yaml` | flag probabilmente in `challenge.yaml`; anche `buckeyectf-2023-public` (cartelle `forensics-*`) |
| `DownUnderCTF/Challenges_2025_Public` | `misc/`, `beginner/` | – | struttura da controllare (2023/24: `publish/` + `challenge.yaml`) | niente `forensics/` nel 2025: guardare misc/beginner |
| `DownUnderCTF/Challenges_2022_Public` | `dfir/` | 9 | `dfir-investigation-1/`: `ctfcli.yaml`, `solve/` | file spesso grandi/esterni: verificare `publish/` |

## Priorità media: buone ma con qualche passaggio in più

| Repo | Cartella | Casi | Note |
|---|---|---|---|
| `hackthebox/cyber-apocalypse-2024` | `forensics/` | 10 | `[Very Easy] Urgent/`: `README.md` (writeup + flag `HTB{…}`) + `assets/`; i file sono zip con password (di solito `hackthebox`): il runner deve scompattarli |
| `hackthebox/cyber-apocalypse-2025` | `forensics/` | 7 | stessa struttura, alcuni con `docker_run.sh` (servizio, non file) → scartare |
| `hackthebox/business-ctf-2024` | `forensics/` | 5 | stessa struttura (anche `hardware/`, `misc/`) |
| `project-sekai-ctf/sekaictf-2023` | `forensics/` | 4 | `defcon-invitation`, `dumpster-dive`, `eval-me`, `infected`; flag nel README/writeup |
| `BYU-CSA/BYUCTF-2024` | `forensics/` | 6 | `advanced-steak/`: `steak.zip` + `README.md` |
| `les-amateurs/AmateursCTF-Public` | `2023/`, `2024/`, `2025/` | – | divisi per categoria (`misc/`, `rev/`, …); flag nei file `bear.toml`/challenge |
| `utisss/UTCTF-24` | `forensics-*` | – | cartelle piatte per challenge |

## Da scartare o usare solo come archivio

- `google/google-ctf`: molto difficile, poche forensics "a file".
- `sigpwny/UIUCTF-2022/2024-Public`, `idekctf/idekctf-2024`, `b01lers-ctf-2024-public`: quasi tutto web/pwn/crypto a servizio.
- Non trovati (rinominati o privati): corCTF 2024 archive, CSAW 2023/24 quals (osirislab), wolvCTF 2024, PatriotCTF 2024, GreyCTF 2024, MetaCTF.

## Come aggiungerli

1. Per ogni candidato: URL raw del file + flag dal file ufficiale (`flag.txt` /
   `challenge.yaml` / `metadata.yaml` / README HTB). Niente flag "a memoria".
2. Lanciarli con `real_challenges.py --extra --only-new -k <nome>`:
   quelli risolti vanno in `EXTRA`, gli altri in `GAPS` con la tecnica mancante.
3. HTB: aggiungere al runner lo scompattamento degli zip con password nota.

## Stato (27/10)

Aggiunti 32 casi a `CANDIDATES` (`app/tests/real_challenges_extra.py`), da
lanciare con `--candidates`. URL verificati (nessun puntatore Git LFS). Esclusi:
- HackTheBox (cyber-apocalypse-2024/2025, business-ctf-2024): le repo hanno solo i
  writeup con screenshot, non i file della challenge;
- SekaiCTF 2023: flag non presenti nei file della repo;
- BYUCTF 2024: flag placeholder (`byuctf{flag}`, `byuctf{ip.address}`) o domande;
- OSINT/servizi/jail (TJCTF airport, ICTF zoom/significant, DUCTF beginner web/crypto);
- DUCTF 2025 `beepbeep.wav`: puntatore Git LFS (19 byte).
