# photo-geolocate

Script locale per rispondere a **"dove è stata scattata questa foto?"**.
Raccoglie i fatti in modo deterministico e produce un report Markdown **e** un
JSON pronto per essere agganciato a un altro sistema (es. la webapp OSINT del
collega).

Cosa estrae:

- **EXIF completo**: GPS (lat/lon/alt), data di scatto, fotocamera/obiettivo,
  software, orientamento;
- **coordinate decimali + link mappa** (OSM, Google, Bing) e, con `--geocode`,
  il **reverse geocoding** via OpenStreetMap Nominatim;
- **posizione del sole** (elevazione/azimut) all'ora e al luogo dello scatto:
  serve a verificare ombre lunghe, facciate illuminate e orientamento della via;
- **OCR** (insegne, targhe, prefissi telefonici, URL) quando `tesseract` c'è;
- un **"agent brief"** già impaginato quando il GPS **non** c'è, con le
  osservazioni e i prossimi passi OSINT.

È la parte locale/deterministica di un workflow di geolocalizzazione (nello
spirito della skill [`Oldcircle/geo-sleuth`](https://github.com/Oldcircle/geo-sleuth)),
in un unico file così può essere richiamata anche da un altro programma.

## Uso

```bash
python geolocate.py foto.jpg                 # report Markdown su stdout
python geolocate.py foto.jpg --geocode       # + reverse geocoding (rete)
python geolocate.py foto.jpg --json out.json --md report.md
python geolocate.py a.jpg b.jpg --offline    # più foto, niente rete
python geolocate.py foto.jpg --no-ocr        # salta l'OCR
```

Senza installare nulla sull'host (usa l'immagine StegSuite, che ha già
`exiftool`, `tesseract`, Pillow):

```bash
./run.sh foto.jpg --geocode --json out.json
```

Requisiti (se eseguito sul host): Python 3.9+ (solo stdlib). Opzionali:
`exiftool` (EXIF completo + GPS decimale), `tesseract` (OCR), Pillow (fallback
EXIF). La **rete è usata solo con `--geocode`** (default: offline).

## Output JSON (contratto di integrazione)

```jsonc
{
  "tool": "photo-geolocate",
  "version": "1.0",
  "images": [
    {
      "file": "/path/foto.jpg",
      "name": "foto.jpg",
      "meta": {
        "gps": { "lat": 45.4642, "lon": 9.19, "alt_m": 120.0, "datum": "WGS-84" },
        "datetime_original": "2024:06:01 15:30:00",
        "offset": "+02:00",
        "make": "Apple", "model": "iPhone 15 Pro",
        "focal_length": 6.86, "focal_length_35mm": 24.0,
        "width": 800, "height": 600, "format": "JPEG",
        "exif": { /* … tutti i tag, flat … */ }
      },
      "geo": {
        "lat": 45.4642, "lon": 9.19, "alt_m": 120.0,
        "links": { "osm": "…", "osm_geouri": "geo:45.4642,9.19",
                   "google": "…", "bing": "…" },
        "reverse": { "display_name": "…", "address": { /* … */ } }  // solo con --geocode
      },
      "sun": { "elevation_deg": 52.3, "azimuth_deg": 231.0, "assumed_utc": false },
      "ocr": "testo letto…",
      "clues": { "calling_codes": [], "urls": [], "emails": [], "plate_like": [] },
      "agent_brief": null
    }
  ]
}
```

- Se il GPS c'è: `geo` è valorizzato, `sun` calcolato, `agent_brief` è `null`.
- Se il GPS **non** c'è: `geo` è `null` e `agent_brief` contiene il testo
  pronto da passare a un agente/LLM (o da mostrare in UI).

## Cosa NON fa (e come estenderlo)

Questo script è volutamente **offline e deterministico**. Non fa, da solo:

- **reverse image search** (Google Lens/Bing/Yandex) → richiede un browser e i
  loro servizi; si può aggiungere come step separato che consuma il JSON;
- **skyline fit / elevazione / satellite** → richiede dati di elevazione
  (es. AWS Terrain Tiles) e le geometrie OSM; sono i moduli `terrain.py`,
  `osm.py`, `sat_scan.py` di geo-sleuth;
- **street view** (Google/Mapillary/KartaView).

I punti di aggancio sono apposta isolati: `get_meta()`, `sun_for()`,
`reverse_geocode()`, `ocr_text()`, `find_clues()`. Per la webapp del collega,
basta importare `analyse_one()` o leggere il JSON.

## Licenza / crediti

Codice originale di questa repo. L'idea del workflow si ispira a
`Oldcircle/geo-sleuth` (MIT); qui non è incluso nessun dato o script di quel
progetto. I dati OSM (Nominatim/Overpass) sono © OpenStreetMap contributors.
