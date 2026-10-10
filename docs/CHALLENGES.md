# Challenge di riferimento e soluzioni

StegSuite **non** contiene un database di soluzioni: questo documento elenca le
challenge usate come **riferimento di verifica** (regressione e test su
challenge reali) con la flag attesa e i comandi manuali per ottenerla. Serve a
due cose:

1. sapere cosa la suite deve trovare (verifica end-to-end);
2. poter risolvere la challenge **a mano** e confrontare il risultato.

> **Attenzione alle flag "per-istanza".** Alcune challenge picoCTF incorporano
> una parte casuale nella flag: lo **stesso** challenge in due writeup diversi
> ha flag diverse (es. So Meta `picoCTF{s0_m3ta_43f253bb}` vs
> `picoCTF{s0_m3ta_dc38ce45}`; Glory of the Garden `..._3y35a97d3bB` vs
> `..._3y3f20F5be9`). Quindi la "risposta giusta" dipende dall'**artifact**.
> La verifica va fatta artifact-per-artifact: vedi `app/tests/verify_flags.py`,
> che controlla anche una **seconda istanza** (repo `kevinjycui`). Altre hanno
> flag **statiche** (What Lies Within, Weird File, extensions, information).
> Le fixture `ITS{...}` sono **generate** dallo script di regressione, quindi la
> flag è nota per costruzione.

## Challenge picoCTF reali

Test: `app/tests/real_challenges.py` (scarica i file dai mirror GitHub, perché
`picoctf.net` non risolve da questo host).

| Challenge | Anno | File | Flag (istanza HHousen) |
|---|---|---|---|
| So Meta | 2019 | `pico_img.png` | `picoCTF{s0_m3ta_43f253bb}` |
| information | 2021 | `cat.jpg` | `picoCTF{the_m3tadata_1s_modified}` |
| Matryoshka doll | 2021 | `dolls.jpg` | `picoCTF{336cf6d51c9d9774fd37196c1d7320ff}` |
| What Lies Within | 2019 | `buildings.png` | `picoCTF{h1d1ng_1n_th3_b1t5}` |
| Glory of the Garden | 2019 | `garden.jpg` | `picoCTF{more_than_m33ts_the_3y35a97d3bB}` |
| extensions | 2019 | `flag.txt` (è un PNG) | `picoCTF{now_you_know_about_extensions}` |
| Weird File | 2021 | `weird.docm` | `picoCTF{m4cr0s_r_d4ng3r0us}` |
| WebNet0 | 2019 | `capture.pcap` + `picopico.key` | `picoCTF{nongshim.shrimp.crackers}` (TLS decifrato) |
| WebNet1 | 2019 | `capture.pcap` + `picopico.key` | `picoCTF{honey.roasted.peanuts}` (TLS → metadata JPEG) |
| St3g0 | 2022 | `pico.flag.png` | `picoCTF{7h3r3_15_n0_5p00n_96ae0ac1}` (LSB → `zsteg`) |
| Very very very Hidden | 2021 | `try_me.pcap` | `picoCTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}` (pcap → HTTP export → Invoke-PSImage → XOR) |
| MacroHard WeakEdge | 2021 | `Forensics is fun.pptm` | `picoCTF{D1d_u_kn0w_ppts_r_z1p5}` (base64 separato da spazi in `ppt/slideMasters/hidden` → `office`) |
| Surfing the Waves | 2021 | `main.wav` | `picoCTF{mU21C_1s_1337_115155af}` (campioni quantizzati a livelli → hex → `wav-levels`) |

Mirror usati:

```
B19 = https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics
B21 = https://raw.githubusercontent.com/HHousen/PicoCTF-2021/master/Forensics
B22 = https://raw.githubusercontent.com/HHousen/PicoCTF-2022/master/Forensics
OLI = https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/NETWORK
OLIM = https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/Olimpiadi Italiane di Cybersecurity
SW = https://raw.githubusercontent.com/00xFE/Olicyber/HEAD/SOFTWARE
```

### OliCyber / ITS (training) — mirror pubblico

Le piattaforme `training.olicyber.it` e `training.itscybergame.it` richiedono il
**login**, quindi i file vengono da un **mirror pubblico di write-up**
(`00xFE/Olicyber`). Sono le challenge "Network" introduttive.

| Challenge | File | Flag | Tecnica |
|---|---|---|---|
| OLI NW_1 | `nw-intro01.pcap` | `flag{Y0u_kn0w_Wh4t_a_Pc4p_1s}` | stringhe nel pcap |
| OLI NW_3 | `nw-intro03.pcapng` | `flag{L3aRn1N9_4b0uT_F1lter5_p1}` | filtro HTTP |
| OLI NW_4 | `nw-intro03.pcapng` | `flag{L3aRn1N9_4b0uT_F1lter5_1P_DN5_f1lt3r}` | filtro DNS |
| OLI NW_5 | `nw-intro03.pcapng` | `flag{L3aRn1N9_4b0uT_F1lter5_C0mm3Nt5_4R3_H4rd_t0_f1nD}` | commenti pcapng |
| OLI NW_8 | `nw-intro08.pcap` | `flag{Byt35_Ex7rAct10n_1s_3a5y!}` | estrazione byte |
| OLI NW_9 | `nw-intro09.pcapng` + `tls-keys.log` | `flag{S3cr3t_K3y5_4re_n0_J0k3}` | keylog **TLS 1.3** → header **HTTP/2** |

Le NW_6/NW_7/NW_10 (stringhe mirate, follow del flusso TCP, PNG esadecimale nel
POST) restano non automatiche. Due migliorie al `pcap` sono nate da qui: keylog
**TLS 1.3** riconosciuto (label `*_TRAFFIC_SECRET*`, non solo `CLIENT_RANDOM`),
**header HTTP/2** decifrati e **commenti pcapng** estratti.

### Olimpiadi Italiane di Cybersecurity — mirror pubblico

Dallo stesso mirror, sezione "Olimpiadi" (artifact reali + `flags.txt`).

| Challenge | File | Flag | Tecnica |
|---|---|---|---|
| Byte-flag | `flag.png` | `flag{Hex1sntFunn1}` | immagine/hex |
| Dashed | `dashed.txt` | `flag{PNRFNE_ZR!-y0u_G07_iT_r1ghT!}` | Morse + rot13 |
| Zipception | `flag0.zip` | `flag{Un0_z1p_d3n7r0_un0_z1p_1mp0551b1l3!}` | archivi annidati |
| easy stream | `easy_stream.pcapng` | `flag{1sto3asy}` | follow stream |
| Useless | `capture.pcapng` | `flag{4lw4y5_ch3ck_th3_c0mm3nt5}` | commenti pcapng |
| Sicurezza dei trasporti | `capture.pcapng` + `keys.log` | `flag{tls_is_really_hard}` | TLS keylog |
| gitgud | `gitgud.zip` | `flag{0h_n0_my_4p1_k3y}` | stego in un **repo git** (`cat-file`, reflog, `pastebin` branch) |
| Gab-Chan | `Gab-chan.png` + `gabchan.txt` | `flag{n0n_3_m15c_s3nz4_s73g0}` | zip protetto negli **LSB RGBA** (`lsb-carve`) + password dal file "fratello" |
| Corrupted flag | `corrupted_file` | `flag{Wh4t_th3_fl4g}` | `image-repair` carva il GIF (prefisso) → `gif-frames` analizza i frame come **figli**; la flag è in un frame su due righe (flag hunt su view **senza spazi**) |

*(Altre Olimpiadi — Zipception 2.0, Suoni misteriosi, Bel paesaggio, Bright sun,
C-H-A-O-S, G4tto, Gab-Chan, Corrupted flag, wordwang — restano non automatiche.)*

### OliCyber SOFTWARE (reversing) — mirror pubblico

Binari reali; in 5 la flag è una **stringa nel binario** (la analizza anche il
sandbox `rev`).

| Challenge | File | Flag | Tecnica |
|---|---|---|---|
| SW_4 | `sw-04` | `flag{0cca06f6}` | stringa nel binario |
| SW_8 | `sw-08` | `flag{e25b8bdf}` | stringa nel binario |
| SW_9 | `sw-09` | `flag{01b81d48}` | stringa nel binario |
| SW_10 | `sw-10` | `flag{0f32826c}` | stringa nel binario (esca `THisIsNotYourFlag`) |
| SW_11 | `sw-11` | `flag{5a11b5a6}` | stringa nel binario |

### Altri archivi: `susers/Writeups` (CTF cinesi)

[`susers/Writeups`](https://github.com/susers/Writeups) è un archivio di challenge
CTF cinesi (2017–2019) con write-up e **allegati**; la flag attesa è nel `README.md`
di ogni challenge. Aggiunto anche come **bookmark** in dashboard.

| Challenge | File | Flag | Tecnica |
|---|---|---|---|
| SusCTF 2017 — Fun jpg (Misc1) | `flag.jpg` | `SusCTF{MetaData_1s_Important}` | flag nei **metadati XMP** (`dc:creator`) → analyzer `exiftool` (prefisso custom `SusCTF{}`) |

### Fonti esterne valutate (raccolte di challenge)

| Fonte | Cosa contiene | Uso / esito |
|---|---|---|
| [`susers/Writeups`](https://github.com/susers/Writeups) | challenge CTF cinesi 2017–2019 + writeup + **allegati** | **usata**: challenge reale *Fun jpg* (sopra) |
| [`project-sekai-ctf`](https://github.com/project-sekai-ctf) (2022/2023) | sorgenti+writeup web/pwn/rev/crypto/forensics/misc, alta qualità | **riferimento**. Quasi tutte **server/jail/pwn** o con artefatti esterni/per-istanza → non auto-testabili offline qui (es. *Eval Me* richiede la key esterna, *DEF CON Invitation* un download remoto, *matryoshka* stego PNG custom) |
| [`SniperOJ/Jeopardy-Dockerfiles`](https://github.com/SniperOJ/Jeopardy-Dockerfiles) | Dockerfile di challenge (web/pwn/misc) con flag statiche | per **hostare** challenge locali (lab), non per l'analisi offline |
| [`abs0lut3pwn4g3/RTB-CTF-Framework`](https://github.com/abs0lut3pwn4g3/RTB-CTF-Framework) | piattaforma CTF (Flask) per **ospitare** eventi | riferimento (hosting), non per l'analisi |

Le fonti sono anche in dashboard come **bookmark** (`config/homepage/bookmarks.yaml`).
Suggerimenti raccolti e non ancora implementati: parsing **`.eml`/email** (allegati
base64), **XOR-exfil da pcap** (byte esfiltrati con key), **USB HID** nel pcap,
ricostruzione **QR** con format-info mancante.

### SekaiCTF 2026 — archivio online (giocabile da browser)

`https://ctf.sekai.team/` reindirizza a `https://2026.ctf.sekai.team/`: la
piattaforma è **archiviata** ma navigabile (si aprono le challenge e si
scaricano gli allegati; **nessun invio flag**). Risolta via browser (MCP Chrome) +
analisi locale:

| Challenge | File | Flag | Tecnica |
|---|---|---|---|
| impossible stego (Misc) | `misc_impossible-stego.tar.gz` → `messages.log` (23 MB) | `SEKAI{impossible_stego_round_trip_works}` | log di traffico API **AI (JSON) in base64**; **risolta automaticamente da StegSuite** (analyzer `blobs`) e aggiunta ai **test reali** (`real_challenges.py`) |

Per rendere il flusso ripetibile: **`./ctf pull <url>`** scarica un allegato in
`./data/pull` (estrae tar/zip/7z) e **`./ctf scan <file>`** lo passa a StegSuite e
stampa le flag.

Altri allegati dell'archivio (analizzati ma **non risolti**: servono tool RE che non
abbiamo): `misc_ufo` (APK Android — serve un decompilatore DEX), `misc_deadgame2`
(replay StarCraft II, MPQ), `rev_untitled-encore` (PE Windows).

### So Meta — EXIF `Artist`

```bash
exiftool pico_img.png        # → Artist : picoCTF{s0_m3ta_43f253bb}
```

### information — metadati con base64

Il campo EXIF/IPTC `License` contiene una stringa base64:

```bash
exiftool cat.jpg | grep License
# License : cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9
exiftool -b -License cat.jpg | base64 -d
# picoCTF{the_m3tadata_1s_modified}
```

### Matryoshka doll — archivi annidati (e flag UTF-16)

Un archivio ZIP è appeso al JPEG; dentro ce ne sono altri, ricorsivamente
(`dolls.jpg` → `2_c.jpg` → `3_c.jpg` → `4_c.jpg` → `flag.txt`). Con binwalk
2.4 l'estrazione richiede `--run-as=root` (anche da root) e va ripetuta sui
livelli successivi. La `flag.txt` è in **UTF-16**, quindi i byte NUL vanno tolti.

```bash
cd /tmp && binwalk -Me --run-as=root dolls.jpg
for i in 1 2 3 4; do
  find _dolls.jpg.extracted -name '*.jpg' -exec binwalk -e --run-as=root {} \; >/dev/null 2>&1
done
find _dolls.jpg.extracted -name flag.txt -exec cat {} \; | tr -d '\0' | sort -u
# picoCTF{336cf6d51c9d9774fd37196c1d7320ff}
```

### What Lies Within — steganografia LSB

```bash
zsteg buildings.png          # cerca il canale LSB che contiene il testo
# oppure con Python / StegSolve: bit 0 del canale R/G/B
# picoCTF{h1d1ng_1n_th3_b1t5}
```

### Glory of the Garden — `strings`

```bash
strings garden.jpg | grep -i pico
# Here is a flag "picoCTF{more_than_m33ts_the_3y35a97d3bB}"
```

### extensions — l'estensione mente

Il file `flag.txt` è in realtà un PNG: va riconosciuto dal contenuto, non dal nome.

```bash
file flag.txt                 # PNG image data, 1697 x 608, ...
tesseract flag.txt stdout 2>/dev/null | grep -o 'picoCTF{[^}]*}'
# picoCTF{now_you_know_about_extensions}
# (oppure: mv flag.txt flag.png e aprilo)
```

### Weird File — macro con base64

Un `.docm` è uno ZIP: si estrae e nel flusso macro c'è un blob base64.

```bash
unzip -o weird.docm -d weird
strings weird/word/vbaProject.bin | grep -oE '[A-Za-z0-9+/=]{24,}' \
  | while read b; do echo "$b" | base64 -d 2>/dev/null; done \
  | grep -ao 'picoCTF{[^}]*}' | head -1
# picoCTF{m4cr0s_r_d4ng3r0us}
```

### St3g0 — steganografia LSB

La flag è nascosta nei bit LSB dei canali RGB.

```bash
zsteg -a pico.flag.png | grep -i pico
# picoCTF{7h3r3_15_n0_5p00n_96ae0ac1}
```

### WebNet0 / WebNet1 — TLS con chiave privata

Il pcap è una sessione TLS; la chiave privata fornita accanto permette a
`tshark` di decifrarla. StegSuite **rileva automaticamente** un file che
contiene `PRIVATE KEY` (o un keylog con `CLIENT_RANDOM`) nella cartella del
progetto e lo passa a tshark (`tls.keys_list` / `tls.keylog_file`).

```bash
# WebNet0: la flag è in un header HTTP della sessione decifrata
tshark -r capture.pcap -o "tls.keys_list:0.0.0.0,0,http,picopico.key" \
  -Y http -T fields -e http.request.full_uri -e http.response.line
# Pico-Flag: picoCTF{nongshim.shrimp.crackers}

# WebNet1: la flag vera è nei metadati di un JPEG scaricato via TLS
tshark -r capture.pcap -o "tls.keys_list:0.0.0.0,0,http,picopico.key" \
  --export-objects http,./out
exiftool out/vulture.jpg | grep Artist      # picoCTF{honey.roasted.peanuts}
```

## Fixture di regressione

Generazione e attese: `app/tests/ctf_regression.py` (le flag sono create dallo
script, quindi il test verifica che l'analizzatore le ritrovi).

| Caso | Tecnica | Flag attesa |
|---|---|---|
| strings | flag in chiaro in un file di testo | `ITS{strings_flag_1}` |
| exif | campo EXIF `Artist` | `ITS{exif_flag_2}` |
| binwalk | ZIP appeso al file | `ITS{appended_zip_3}` |
| aes-zip | ZIP con cifratura AES + crack con wordlist | `ITS{aes_zip_4}` |
| steghide | `steghide embed` (password `ctf`) | `ITS{steghide_5}` |
| gif-frames | flag disegnata su un frame GIF | `ITS{gif_frame_6}` |
| png-chunks | chunk PNG `tEXt` | `ITS{png_chunk_7}` |
| decode | catena rot13 / base64 | `ITS{decode_8}` |
| morse-text | codice Morse nel testo | `ITS{morse_layer_9}` |
| bit-planes | testo nei bit LSB dei piani | `ITS{lsb_10}` |
| image-enhance | testo a basso contrasto | `ITS{enhance_11}` |
| decode-chain | Morse "dashed" + rot13 | `ITS{dashed_12}` |
| qr | QR code con la flag (`zbarimg`) | `ITS{qr_13}` |
| wav-lsb | flag nei bit LSB dei campioni WAV | `ITS{wav_lsb_14}` |
| pcap | flag nella URI HTTP (`tshark`) | `ITS{pcap_15}` |
| real-challenge | PNG con ZIP appeso + password `robot` | `ITS{stego_z1p_appended}` |
| image-repair | BMP con header corrotto, riparato | `ITS{repair_17}` |
| dns-tunnel | base32 nei label DNS di un pcap | `ITS{dns_tunnel_18}` |
| nested-archive | 30 tar annidati (stile *like1000*) + `filler.txt` | `ITS{nested_archive_19}` |
| sstv | trasmissione SSTV Scottie S1 di un frame con la flag | `ITS{sstv20}` |
| tls-pcap | pcap TLS + chiave privata (WebNet0), header decifrato | `picoCTF{nongshim.shrimp.crackers}` |
| openstego | payload OpenStego non cifrato (`openstego embed` → `extract`) | `ITS{openstego22}` |
| psimage | payload Invoke-PSImage (4 LSB di B/G) con due stringhe XORate | `ITS{psimageTeXt}` |
| office | `.pptm` con base64 separato da spazi in `ppt/slideMasters/hidden` | `ITS{office_24}` |
| wav-levels | WAV con campioni a livelli discreti che codificano una stringa hex | `ITS{wav_levels_25}` |

L'ultima riga usa il nuovo analyzer **`psimage`**: risolve *Invoke-PSImage*, che
nasconde **un byte per pixel nei 4 bit bassi dei canali Blu e Verde**
(`byte = (B & 0x0F) << 4 | G & 0x0F`). Il payload è spesso uno script PowerShell
che fa da "mappa": il flag hunt ora prova anche lo **XOR di due stringhe** di pari
lunghezza presenti nel testo, quindi la mappa diventa la flag.

La riga **`office`** copre i documenti Office/OpenDocument (`.pptm/.docm/.docx/…`):
li scompatta e decodifica il base64 anche quando è **separato da spazi** (o da un
carattere per riga) — è il caso di *MacroHard WeakEdge*.

## Come verificare

```bash
cd <repo>
docker compose up -d stegsuite

# regressione (nel container; le fixture sono generate al volo)
docker cp app/tests/ctf_regression.py ctf-stegsuite-1:/tmp/ctf_regression.py
docker cp app/tests/fixtures ctf-stegsuite-1:/tmp/fixtures
docker exec -e FIXTURES_DIR=/tmp/fixtures ctf-stegsuite-1 \
  /opt/stegsuite/venv/bin/python /tmp/ctf_regression.py     # → 25/25

# challenge reali (host: scaricano i file da sole)
python3 app/tests/real_challenges.py                        # → 35/35 (lento: ~10 min)

# verifica INDIPENDENTE: per ogni (artifact, writeup) confronta la flag trovata
# con quella dichiarata dal writeup per QUELL'artifact; include una seconda
# istanza (repo kevinjycui) con flag diverse -> 11/11
python3 app/tests/verify_flags.py                           # → ALL CORRECT

# smoke test della UI: un Chromium headless (in Docker) guida la SPA e controlla
# pannelli, tab, layout mobile (375px) e assenza di errori in console
./ctf ui-smoke                                              # → ALL UI CHECKS PASSED
```

`verify_flags.py` legge le risposte **a runtime** (niente costanti nostre) e
stampa anche il confronto tra istanze, es.:
```
(per-instance) So Meta A != So Meta B:
  picoCTF{s0_m3ta_43f253bb} vs picoCTF{s0_m3ta_dc38ce45}
```
cioè dimostra che StegSuite estrae correttamente la flag dall'artifact che gli
viene dato, qualunque sia l'istanza.

`real_challenges.py` fallisce anche se una flag trovata è un **frammento** di
un'altra (es. `CTF{x}` dentro `picoCTF{x}`): è una guardia contro i falsi
positivi troncati.

## Altri casi provati (gap noti)

Queste sono state provate sui file reali: StegSuite **non** le risolve ancora
del tutto. Restano qui come riferimento e come TODO per nuovi analyzer.

| Challenge | Anno | Flag | Cosa manca |
|---|---|---|---|
| c0rrupt | 2019 | `picoCTF{c0rrupt10n_1847995}` | **PNG repair** produce l'immagine valida; la flag è visiva e l'OCR la legge **quasi** (`cOrrupt`: il font rende `0`=`O`) → limite accettato |
| like1000 | 2019 | `picoCTF{l0t5_0f_TAR5}` | **risolta strutturalmente** da `nested-archive`: apre i 1000 tar annidati in un colpo solo e arriva a `flag.png`; l'OCR legge `l0t5_0f_TAR5` come `lOtS Of TAR5S` (confusione `0/O`, `5/S` del font) |
| tunn3l v1s10n | 2021 | `picoCTF{qu1t3_a_v13w_2020}` | **risolta strutturalmente** da `image-repair` (header BMP standard + altezza ricalcolata); resta il near-miss OCR (`1→i`, spazi) |
| m00nwalk | 2019 | `picoCTF{beep_boop_im_in_space}` | **decodificata** da `sstv` (Scottie S1, frame verificato contro QSSTV); il testo è trasmesso capovolto in un frame 320×256 rumoroso → OCR near-miss |

## Formati di flag non standard

Non tutte le challenge hanno `flag{...}`. La flag hunt riconosce i prefissi noti
(`ITS`, `flag`, `CTF`, `HTB`, `picoCTF`…), il pattern generico `<parola>{...}` e,
per OCR/decodifiche inline, base64/hex/rot13/url. Il pattern generico è però
**disattivato sulle sorgenti rumorose** (`strings`, hex, pcap) per non generare
falsi positivi, e i flag **senza graffe** non vengono riconosciuti.

Per questi casi imposta una **regex** in `FLAG_PATTERN` (env): viene applicata a
**tutte** le sorgenti, anche senza graffe.

```bash
# prefisso custom
FLAG_PATTERN='DUCTF\{[^}]+\}'
# formato senza graffe (es. token esadecimale)
FLAG_PATTERN='FLAG-[0-9a-f]{8}'
```

Se una challenge non ha proprio una flag (la risposta è una password, un messaggio
decodificato o un artefatto), guarda **Report**/**Transcript**: elencano password,
findings, catena solver e output dei tool — la risposta è lì, anche quando nessun
pattern la riconosce come "flag".

## Aggiungere una challenge

1. Aggiungi la tupla `(nome, url, flag_attesa)` in `CASES` di
   `app/tests/real_challenges.py`.
2. Aggiungi la tupla `(label, url_artifact, url_writeup)` in `CASES` di
   `app/tests/verify_flags.py` (il writeup deve dichiarare la flag).
3. Verifica che i file siano scaricabili dai mirror GitHub (o da un URL che
   risolva da questo host).
4. Aggiungi la riga alle tabelle qui sopra con la tecnica e i comandi manuali.
