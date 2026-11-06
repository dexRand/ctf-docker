# Task per opencode (deepseek) — uno alla volta, in quest'ordine

Prima di iniziare leggi `AGENTS.md`, sezione **"Regole per il lavoro autonomo"**:
perimetro, schema degli analyzer, verifica, commit, quando fermarsi.

Baseline da non peggiorare (04/11, commit `7f34de2`): unit 355 · lint pulito ·
extra 47/47 · fixture 33/33 · reali 35/35 · `ALL CORRECT`.

Per ogni task: un branch non serve, ma **un commit per task** e la verifica completa
prima del push. Se un task si blocca, scrivilo in "Bloccato" e passa al successivo.

---

## Task 1 — Vigenère e rail fence in `decode` (issue #12)

**File da toccare:** solo `app/backend/analyzers/decode.py` e un test nuovo
`app/tests/test_decode_classic.py`.

**Cosa fare**
- **Vigenère con chiave ricavata dal prefisso** (attacco a testo noto): per ogni
  prefisso di `FLAG_PREFIXES` cerca nel testo una sequenza di lettere della stessa
  lunghezza seguita da `{`; la differenza lettera per lettera dà la chiave (ripetuta
  con periodo = lunghezza del prefisso, poi prova anche periodi 1..lunghezza). Tieni
  il risultato **solo** se decifrando compare `PREFISSO{`. Le non-lettere restano
  invariate e non fanno avanzare la chiave.
- **Rail fence** con 2..10 binari, solo su testi ≤ 4096 caratteri, risultato tenuto
  solo se compare un prefisso noto + `{`.
- Aggiungili dentro `candidates()` nel blocco `if len(text0) <= _SMALL:` (come Caesar).

**Test (`test_decode_classic.py`)**: cifra una flag con Vigenère (chiave "KEY") e con
rail fence (3 binari) dentro il test, verifica che `candidates()` restituisca la flag;
verifica che un testo normale non produca risultati `vigenere*`/`railfence*`.

**Fatto quando:** unit + lint verdi, verifica completa invariata.
Chiusura: `Fixes #12` NO (l'issue ha altri punti) → `Refs #12` + commento.

---

## Task 2 — `olevba`: macro VBA dei documenti Office (issue #14)

**File da toccare:** `app/Dockerfile` (aggiungere `oletools==0.60.2` al pip install
del venv di StegSuite, versione fissata), nuovo `app/backend/analyzers/olevba.py`,
`analyzers/__init__.py`, una riga in `DEFAULT_PLAN` (subito dopo `"office"`),
test nuovo `app/tests/test_olevba.py`.

**Cosa fare**
- Analyzer `olevba`: `accepts` = estensioni Office (`.doc .docm .docx .xls .xlsm
  .xlsx .ppt .pptm .pptx .dotm .xlam`) + mime `application/x-ole-storage`.
- Gating: OLE (`\xd0\xcf\x11\xe0`) oppure zip che contiene un membro
  `vbaProject.bin` (controlla con `zipfile` la lista dei nomi, non estrarre tutto).
  Altrimenti `skipped`.
- Esegui `olevba --decode --deobf <file>` con `ctx.run(..., timeout=120)`; output
  (max 200 000 caratteri) = sorgente delle macro + stringhe decodificate. Il flag
  hunt lavora sull'output da solo.
- Riassunto: numero di macro e se ci sono `AutoOpen`/`Document_Open`/`Shell`.

**Test**: gating (`skipped` su un docx senza `vbaProject.bin` generato nel test con
`zipfile`) + parsing con `ctx.run` sostituito da un finto risultato (monkeypatch).
**Caso reale**: `Weird File` nelle reali (`weird.docm`) deve restare PASS e
l'output di `olevba` deve contenere il codice della macro.

**Fatto quando:** come sopra. `Refs #14` + commento.

---

## Task 3 — Hive del registro Windows con `regipy` (issue #13)

**File da toccare:** `app/Dockerfile` (`regipy==6.5.0` nel pip install, versione
fissata), nuovo `app/backend/analyzers/winreg.py` (NON `registry.py`: quel nome è
già il registro degli analyzer), `__init__.py`, una riga in `DEFAULT_PLAN`
(vicino a `"sam"`), test nuovo `app/tests/test_winreg.py`.

**Cosa fare**
- Analyzer `winreg`: gating sulla firma `regf` nei primi 4 byte (in `magic.py` c'è già),
  altrimenti `skipped`. Accetta qualsiasi nome (le hive non hanno estensione:
  `NTUSER.DAT`, `SOFTWARE`, `SYSTEM`…): `accepts = ()` e controllo della firma.
- Con `regipy` estrai e scrivi nell'output (testo, max 200 000 caratteri):
  chiavi `Run`/`RunOnce`, `RecentDocs`, `TypedPaths`, `RunMRU`, `WordWheelQuery`,
  `UserAssist` (i nomi sono in ROT13: decodificali), `Environment`, e **tutti i
  valori stringa** con un tetto (es. 20 000 valori). Il flag hunt fa il resto.
- Non usare SYSTEM+SAM per estrarre hash: lo fa già `sam.py`.
- Hive enormi (> 256 MB): `skipped` con il motivo.

**Test**: gating (`skipped` su un file qualsiasi); per il parsing usa una piccola
hive di test pubblica **con licenza compatibile** (es. dai test di regipy, MIT),
salvata in `app/tests/data/` (NON in `app/tests/fixtures/`, che è la regressione),
e citane la fonte in un commento.
**Caso reale**: `ic25-obfuscated-Users.zip` — non è richiesto che passi; basta che
`winreg` giri sulle hive estratte e l'output contenga le chiavi. Annota nel commento
del caso in `GAPS` cosa si vede.

**Fatto quando:** come sopra. `Refs #13` + commento.

---

## Task 4 — Handshake WPA da pcap → hashcat 22000 (issue #11)

**File da toccare:** `app/Dockerfile` (pacchetto apt `hcxtools`, versione fissata, oggi Debian trixie dà `6.3.5-1`), nuovo
`app/backend/analyzers/wpa.py`, `__init__.py`, una riga in `DEFAULT_PLAN` (dopo
`"pcap"`), test nuovo `app/tests/test_wpa.py`.

**Cosa fare**
- Gating: pcap/pcapng con link type 802.11 (105, 127 radiotap, 163) — riusa
  `link_types()` da `analyzers/usbhid.py` (non copiarla: importala). Altrimenti `skipped`.
- `hcxpcapngtool -o <out>.22000 <file>` con `ctx.run(timeout=120)`. Nessun hash →
  `skipped` "no handshake".
- Crack con hashcat `-m 22000` sulle wordlist di `cracking.resolve_wordlists(...)`
  (solo le piccole, come l'auto-crack: guarda come lo fa `sam.py`) con un budget di
  tempo fisso (es. 120 s). Password trovata → nell'output `password: <pw>  (SSID)`.
- Il file `.22000` va anche tra gli artifact (l'utente può craccarlo dalla GUI).

**Test**: gating (`skipped` su un pcap Ethernet generato nel test come in
`test_usbhid.py`); parsing dell'output di hashcat `--show` con un finto risultato.
**Caso reale**: `ui21-megacorp-01.cap` — la flag attesa `uiuctf{nanotechnology}` va
avvolta a mano, quindi resta in `GAPS`; basta che l'output mostri la password
`nanotechnology` se è nelle wordlist. Annotalo nel commento del caso.

**Fatto quando:** come sopra. `Refs #11` + commento.

---

## Stato (aggiornalo tu, con i numeri copiati dall'output)

| Task | Stato | Commit | Verifica |
|---|---|---|---|
| 1 Vigenère / rail fence | fatto | 8246477 | unit 374, lint clean |
| 2 olevba | fatto | df03c17 | lint clean, `weird.docm` PASS 8.2s, output con `Sub AutoOpen()` |
| 3 winreg (regipy) | fatto | f23f033 | lint clean, hive NTUSER `done · 2131 keys, 4214 value(s)` |
| 4 WPA → hashcat | fatto | c7bccf7 | lint clean, 2 hash 22000 estratti da `ui21-megacorp-01.cap`; crack ok con dizionario ad hoc, non con le wordlist piccole |

**Gate finale (05/11, dopo i 4 task + jpeg-dqt):** `./ctf test -j 2 --extra` →
fixture **33/33** · reali **83/83** (35 core + 48 extra) · writeup **ALL CORRECT**
· 0 FAIL · 6445.3 s di analisi. Unit **379 passed**, `./ctf lint` clean. CI verde
su `30d4c57`.
Nessuna flag persa rispetto alla baseline.

Restano aperti (nessun blocco): i casi in `GAPS` per #11/#13/#14 e i task
#11–#16 nella loro interezza (`ic25-obfuscated-Users` non ha il flag nella hive,
`ui21-megacorp` non ha la password nelle wordlist piccole).

## Sessione 05/11 pomeriggio — extra fuori dai 4 task

- **`jpeg-dqt`** (nuovo analyzer): JPEG con DQT azzerate → tabelle ricostruite
  (prima tutte a 1: "the lion doesn't quantize", poi Annex K) e immagine
  decodificata come figlio per OCR. `tj25-quant-lost.jpg` **PASS 28.7 s** →
  spostato in `EXTRA` (48 extra, 55 GAPS). Test in `app/tests/test_jpegdqt.py`;
  unit **379**, lint clean. README a **81 analyzer** (aggiunti anche `olevba`,
  `winreg`, `wpa`, `jpeg-dqt` nelle tabelle) e due `display_order` duplicati
  sistemati (`olevba` 221, `wpa` 266).
- **`tar-chain`** (nuovo analyzer) + una variante OCR "unleet": i 999 tar
  annidati si percorrono **in memoria** (1,5 s) e l'ultima PNG viene letta con
  un passaggio OCR 2x binarizzato; la variante ricostruisce `l0t5_0f_TAR5` da
  `lOtS Of TAR5` (spazi→`_`, O→0, S→5 nei corpi già "leet").
  `1000.tar` **PASS 51,2 s** → in `EXTRA` (49 extra, 54 GAPS).

## Verifiche intermedie: `./ctf test --fast`

`real_challenges.py --fast` esegue 11 casi core scelti uno per famiglia di
analyzer (metadata, OCR, bit-plane, pcap HTTP/DNS/commenti, TLS keylog, Office
macro, git, archivi, stream TCP): **11/11 PASS in 334 s di analisi (~2 min a
`-j 3`)**, più le fixture. Serve per i controlli durante il lavoro; il gate
completo (`./ctf test -j 2 --extra`, ~2h) resta obbligatorio prima del push.

## Bloccato

### `ic25-thrift-capture.pcap` (GAP, analisi 06/11, ~45 min)
Thrift **binary + TFramedTransport** (ogni messaggio preceduto da 4 byte di
lunghezza; header `80 01 00 01 <len> <name> <seqid>`).

Mappa ricavata dai byte:
- metodi: `createBasket` 212, `addToBasket` 418, `getBasket` 74, `getInventory` 194, **`pay` 24**;
- tipi osservati: `0x0b`=string, `0x0c`=struct, `0x0f`=list, `0x0a`=intero 8 byte, `0x00`=stop
  (NON coincidono con la tabella standard di Thrift, quindi non è il binary
  protocol ufficiale: serve l'IDL della challenge o un parser scritto a mano);
- `pay` manda `{1: uuid stringa, 2: intero}` (es. 700) e il server risponde con
  l'eccezione "Total does not match basket total"; 134 stream, 170 KB di payload;
- la flag **non è in chiaro** (`strings` sul pcap: nessun `ictf`), nessuna stringa
  non-ASCII o blob base64.

Provato: parser Thrift generico (fallisce per i tipi non standard), estrazione
degli interi di `pay`, dump delle stringhe. Non risolto in 1h: serve capire dove
sta il dato (probabile: totali di `pay` che codificano ASCII, oppure field id).
Prossimo passo: scrivere un parser che segua la mappa dei tipi sopra e stampare
tutti i campi, `pay` compreso.
