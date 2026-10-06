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

Mirror usati:

```
B19 = https://raw.githubusercontent.com/HHousen/PicoCTF-2019/master/Forensics
B21 = https://raw.githubusercontent.com/HHousen/PicoCTF-2021/master/Forensics
```

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

## Come verificare

```bash
cd "/home/romeo/Progetti/ctf-docker"
docker compose up -d stegsuite

# regressione (nel container; le fixture sono generate al volo)
docker cp app/tests/ctf_regression.py ctf-stegsuite-1:/tmp/ctf_regression.py
docker cp app/tests/fixtures ctf-stegsuite-1:/tmp/fixtures
docker exec -e FIXTURES_DIR=/tmp/fixtures ctf-stegsuite-1 \
  /opt/stegsuite/venv/bin/python /tmp/ctf_regression.py     # → 21/21

# challenge reali (host: scaricano i file da sole)
python3 app/tests/real_challenges.py                        # → 9/9

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
| c0rrupt | 2019 | `picoCTF{c0rrupt10n_1847995}` | **PNG repair** produce l'immagine valida (la flag è visiva, OCR non affidabile) |
| like1000 | 2019 | `picoCTF{l0t5_0f_TAR5}` | **risolta strutturalmente** da `nested-archive`: apre i 1000 tar annidati in un colpo solo e arriva a `flag.png`; l'OCR legge `l0t5_0f_TAR5` come `lOtS Of TAR5S` (confusione `0/O`, `5/S` del font) |
| tunn3l v1s10n | 2021 | `picoCTF{qu1t3_a_v13w_2020}` | **risolta strutturalmente** da `image-repair` (header BMP standard + altezza ricalcolata); resta il near-miss OCR (`1→i`, spazi) |
| MacroHard WeakEdge | 2021 | `picoCTF{D1d_u_kn0w_ppts_r_z1p5}` | base64 multi-step nel `pptm` |
| Surfing the Waves | 2021 | `picoCTF{mU21C_1s_1337_115155af}` | decodifica custom dei campioni WAV |
| Very very very Hidden | 2021 | `picoCTF{n1c3_job_f1nd1ng_th3_s3cr3t_in_the_im@g3}` | pcap + tool dedicato |
| m00nwalk | 2019 | `picoCTF{beep_boop_im_in_space}` | **decodificata** da `sstv` (Scottie S1, frame verificato contro QSSTV); il testo è trasmesso capovolto in un frame 320×256 rumoroso → OCR near-miss |

## Aggiungere una challenge

1. Aggiungi la tupla `(nome, url, flag_attesa)` in `CASES` di
   `app/tests/real_challenges.py`.
2. Aggiungi la tupla `(label, url_artifact, url_writeup)` in `CASES` di
   `app/tests/verify_flags.py` (il writeup deve dichiarare la flag).
3. Verifica che i file siano scaricabili dai mirror GitHub (o da un URL che
   risolva da questo host).
4. Aggiungi la riga alle tabelle qui sopra con la tecnica e i comandi manuali.
