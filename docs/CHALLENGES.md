# Challenge di riferimento e soluzioni

StegSuite **non** contiene un database di soluzioni: questo documento elenca le
challenge usate come **riferimento di verifica** (regressione e test su
challenge reali) con la flag attesa e i comandi manuali per ottenerla. Serve a
due cose:

1. sapere cosa la suite deve trovare (verifica end-to-end);
2. poter risolvere la challenge **a mano** e confrontare il risultato.

> Le challenge picoCTF sono statiche per queste versioni; le flag elencate sono
> quelle dei file nei mirror GitHub indicati sotto. Le fixture `ITS{...}` sono
> **generate** dallo script di regressione, quindi la flag è nota per costruzione.

## Challenge picoCTF reali

Test: `app/tests/real_challenges.py` (scarica i file dai mirror GitHub, perché
`picoctf.net` non risolve da questo host).

| Challenge | Anno | File | Flag |
|---|---|---|---|
| So Meta | 2019 | `pico_img.png` | `picoCTF{s0_m3ta_43f253bb}` |
| information | 2021 | `cat.jpg` | `picoCTF{the_m3tadata_1s_modified}` |
| Matryoshka doll | 2021 | `dolls.jpg` | `picoCTF{336cf6d51c9d9774fd37196c1d7320ff}` |
| What Lies Within | 2019 | `buildings.png` | `picoCTF{h1d1ng_1n_th3_b1t5}` |
| Glory of the Garden | 2019 | `garden.jpg` | `picoCTF{more_than_m33ts_the_3y35a97d3bB}` |

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
| real-challenge | PNG con ZIP appeso + password `robot` | `ITS{stego_z1p_appended}` |

## Come verificare

```bash
cd "/home/r/__Github/CTF"
docker compose up -d stegsuite

# regressione (nel container; le fixture sono generate al volo)
docker cp app/tests/ctf_regression.py ctf-stegsuite-1:/tmp/ctf_regression.py
docker cp app/tests/fixtures ctf-stegsuite-1:/tmp/fixtures
docker exec -e FIXTURES_DIR=/tmp/fixtures ctf-stegsuite-1 \
  /opt/stegsuite/venv/bin/python /tmp/ctf_regression.py     # → 13/13

# challenge reali (host: scaricano i file da sole)
python3 app/tests/real_challenges.py                        # → 5/5
```

`real_challenges.py` fallisce anche se una flag trovata è un **frammento** di
un'altra (es. `CTF{x}` dentro `picoCTF{x}`): è una guardia contro i falsi
positivi troncati.

## Aggiungere una challenge

1. Aggiungi la tupla `(nome, url, flag_attesa)` in `CASES` di
   `app/tests/real_challenges.py`.
2. Verifica che il file sia scaricabile dai mirror GitHub (o da un URL che
   risolva da questo host).
3. Aggiungi la riga alle tabelle qui sopra con la tecnica e i comandi manuali.
