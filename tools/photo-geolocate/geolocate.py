#!/usr/bin/env python3
"""photo-geolocate - local intake for "where was this photo taken?".

Deterministic, self-contained pre-analysis of one or more images:

  * full EXIF (GPS lat/lon/alt, capture time, camera/lens, software, orientation)
  * the exact decimal coordinates -> OSM / Google map links (+ optional reverse geocode)
  * the sun position (elevation & azimuth) at the capture time and place, to
    sanity-check long shadows, lit faces and street orientation
  * OCR text (signs, plates, calling codes) when tesseract is available
  * a ready-to-paste "agent brief" with the observations and the next geolocation
    steps (reverse image search, Overpass, elevation skyline fit, street view)

It is the local, deterministic core of an image-geolocation workflow (in the
spirit of the Oldcircle/geo-sleuth agent skill), packaged as one script so it can
also be called by another system (see README: the JSON output is the integration
contract).

Dependencies: Python 3.9+ standard library. Optional: PILLOW (EXIF fallback),
the `exiftool` and `tesseract` binaries (used when present). The network is only
touched with --geocode (OpenStreetMap Nominatim).

Usage:
    python geolocate.py photo.jpg
    python geolocate.py photo.jpg --json out.json --geocode
    python geolocate.py a.jpg b.jpg --offline
"""
from __future__ import annotations

import argparse
import json
import math
import re
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "1.0"
USER_AGENT = "photo-geolocate/1.0 (+local CTF tool; contact: local)"


# --------------------------------------------------------------------------- utils
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run(cmd: list[str], timeout: int = 60) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                           timeout=timeout, stdin=subprocess.DEVNULL)
        return (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    except (OSError, subprocess.TimeoutExpired):
        return ""


# --------------------------------------------------------------------------- exif
def _exiftool(path: Path) -> dict:
    """Full EXIF as a flat dict, numeric values (-n) so GPS is decimal."""
    if not have("exiftool"):
        return {}
    out = _run(["exiftool", "-j", "-n", "-G1", "-charset", "utf8", str(path)])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}
    if not data:
        return {}
    d = data[0]
    return {k.split(":", 1)[-1]: v for k, v in d.items()}


def _pillow_exif(path: Path) -> dict:
    """Minimal fallback EXIF (no GPS conversion) when exiftool is missing."""
    try:
        from PIL import ExifTags, Image
    except Exception:
        return {}
    try:
        img = Image.open(path)
        raw = img.getexif()
    except Exception:
        return {}
    out: dict = {}
    for tag, val in raw.items():
        name = ExifTags.TAGS.get(tag, str(tag))
        out[name] = val
    # GPS IFD
    try:
        gps = raw.get_ifd(0x8825)
        for tag, val in gps.items():
            out["GPS" + ExifTags.GPSTAGS.get(tag, str(tag))] = val
    except Exception:
        pass
    out["_width"], out["_height"] = getattr(img, "size", (None, None))
    return out


def _to_float(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _dms_to_deg(v, ref) -> float | None:
    """Convert a DMS tuple/str (from Pillow) to decimal degrees."""
    try:
        if isinstance(v, (tuple, list)) and v:
            if isinstance(v[0], (tuple, list)):
                d, m, s = (float(x[0]) / float(x[1]) for x in v[:3])
            else:
                d, m, s = (float(x) for x in v[:3])
            deg = d + m / 60 + s / 3600
        else:
            deg = float(v)
    except Exception:
        return None
    if ref in ("S", "W") or (isinstance(ref, str) and ref.upper() in ("S", "W")):
        deg = -deg
    return deg


def get_meta(path: Path) -> dict:
    """Normalised metadata, whatever tool is available."""
    exif = _exiftool(path) or _pillow_exif(path)
    m: dict = {"exif": exif}

    lat = _to_float(exif.get("GPSLatitude"))
    lon = _to_float(exif.get("GPSLongitude"))
    if lat is None and "GPSLatitude" in exif:
        lat = _dms_to_deg(exif.get("GPSLatitude"), exif.get("GPSLatitudeRef"))
        lon = _dms_to_deg(exif.get("GPSLongitude"), exif.get("GPSLongitudeRef"))
    if lat is not None and lat == 0.0 and lon == 0.0:
        lat = lon = None  # 0,0 is "no fix" far more often than the Gulf of Guinea

    m["gps"] = {
        "lat": lat, "lon": lon,
        "alt_m": _to_float(exif.get("GPSAltitude")),
        "datum": exif.get("GPSMapDatum") or "WGS-84",
    }
    m["datetime_original"] = exif.get("DateTimeOriginal") or exif.get("CreateDate")
    m["offset"] = exif.get("OffsetTimeOriginal") or exif.get("OffsetTime")
    m["gps_datetime"] = exif.get("GPSDateTime")
    for k in ("Make", "Model", "LensModel", "LensID", "Software"):
        m[k.lower()] = exif.get(k)
    m["focal_length"] = _to_float(exif.get("FocalLength"))
    m["focal_length_35mm"] = _to_float(exif.get("FocalLengthIn35mmFormat"))
    m["orientation"] = exif.get("Orientation")

    w = exif.get("ImageWidth") or exif.get("_width") or exif.get("ExifImageWidth")
    h = exif.get("ImageHeight") or exif.get("_height") or exif.get("ExifImageHeight")
    m["width"], m["height"] = (int(w) if w else None), (int(h) if h else None)
    m["format"] = exif.get("FileType") or exif.get("MIMEType")
    return m


# --------------------------------------------------------------------------- sun
def _sun_position(lat: float, lon: float, when_utc: datetime) -> dict:
    """Low-precision solar elevation/azimuth (NOAA-style), degrees."""
    when_utc = when_utc.astimezone(timezone.utc)
    y, mo = when_utc.year, when_utc.month
    d = (when_utc.day + (when_utc.hour + (when_utc.minute
         + when_utc.second / 60.0) / 60.0) / 24.0)
    if mo <= 2:
        y, mo = y - 1, mo + 12
    a = y // 100
    b = 2 - a + a // 4
    jd = int(365.25 * (y + 4716)) + int(30.6001 * (mo + 1)) + d + b - 1524.5
    n = jd - 2451545.0
    L = (280.460 + 0.9856474 * n) % 360.0
    g = math.radians((357.528 + 0.9856003 * n) % 360.0)
    lam = math.radians((L + 1.915 * math.sin(g) + 0.020 * math.sin(2 * g)) % 360.0)
    eps = math.radians(23.439 - 0.0000004 * n)
    ra = math.atan2(math.cos(eps) * math.sin(lam), math.cos(lam))
    dec = math.asin(math.sin(eps) * math.sin(lam))
    gmst = (18.697374558 + 24.06570982441908 * n) % 24.0
    lst = math.radians((gmst * 15.0 + lon) % 360.0)
    ha = lst - ra
    la = math.radians(lat)
    alt = math.asin(math.sin(la) * math.sin(dec) + math.cos(la) * math.cos(dec) * math.cos(ha))
    az = math.atan2(-math.sin(ha),
                    math.tan(dec) * math.cos(la) - math.sin(la) * math.cos(ha))
    return {"elevation_deg": round(math.degrees(alt), 2),
            "azimuth_deg": round((math.degrees(az) + 360.0) % 360.0, 2)}


def sun_for(meta: dict) -> dict | None:
    """Sun position using capture time + GPS; None when we cannot know the UTC instant."""
    gps = meta.get("gps") or {}
    lat, lon = gps.get("lat"), gps.get("lon")
    if lat is None or lon is None:
        return None
    dt_utc = None
    if meta.get("gps_datetime"):
        try:
            dt_utc = datetime.strptime(meta["gps_datetime"][:19], "%Y:%m:%d %H:%M:%S")
            dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        except ValueError:
            dt_utc = None
    if dt_utc is None and meta.get("datetime_original"):
        try:
            base = datetime.strptime(meta["datetime_original"][:19], "%Y:%m:%d %H:%M:%S")
        except ValueError:
            return None
        off = meta.get("offset")
        if off:
            m = re.match(r"([+-])(\d{2}):?(\d{2})", str(off))
            if m:
                delta = timedelta(hours=int(m.group(2)), minutes=int(m.group(3)))
                if m.group(1) == "-":
                    delta = -delta
                dt_utc = (base - delta).replace(tzinfo=timezone.utc)
        else:
            dt_utc = base.replace(tzinfo=timezone.utc)  # assume UTC (flagged below)
    if dt_utc is None:
        return None
    out = _sun_position(lat, lon, dt_utc)
    out["assumed_utc"] = bool(not meta.get("offset") and not meta.get("gps_datetime"))
    return out


# ------------------------------------------------------------------------ geocode
def reverse_geocode(lat: float, lon: float) -> dict | None:
    """OpenStreetMap Nominatim reverse lookup (only called with --geocode)."""
    q = urllib.parse.urlencode({"lat": lat, "lon": lon, "format": "jsonv2",
                                "zoom": 14, "addressdetails": 1})
    req = urllib.request.Request(f"https://nominatim.openstreetmap.org/reverse?{q}",
                                 headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as exc:                       # network blocked / rate limited
        return {"error": str(exc)}
    return {"display_name": data.get("display_name"),
            "type": data.get("type"), "address": data.get("address", {}),
            "osm": data.get("osm_type") and f"{data.get('osm_type')}/{data.get('osm_id')}"}


# ---------------------------------------------------------------------------- ocr
def ocr_text(path: Path, langs: str | None = None) -> str | None:
    if not have("tesseract"):
        return None
    cmd = ["tesseract", str(path), "stdout"]
    if langs:
        cmd += ["-l", langs]
    txt = _run(cmd, timeout=120)
    return " ".join(txt.split()).strip()[:4000] or None


# -------------------------------------------------------------------------- clues
_CALLING = re.compile(r"(?<!\d)\+\d{1,3}[\s.\-]?\d{2,4}[\s.\-]?\d{2,4}(?!\d)")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PLATE = re.compile(r"\b[A-Z]{1,3}[\s\-]?\d{2,4}[\s\-]?[A-Z]{0,3}\b")


def find_clues(text: str | None) -> dict:
    if not text:
        return {}
    return {
        "calling_codes": sorted(set(_CALLING.findall(text))),
        "urls": sorted(set(_URL.findall(text))),
        "emails": sorted(set(_EMAIL.findall(text))),
        "plate_like": sorted({p for p in _PLATE.findall(text) if any(c.isdigit() for c in p)})[:20],
    }


# ------------------------------------------------------------------------- report
def map_links(lat: float, lon: float) -> dict:
    return {
        "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=18/{lat}/{lon}",
        "osm_geouri": f"geo:{lat},{lon}",
        "google": f"https://www.google.com/maps/search/?api=1&query={lat},{lon}",
        "bing": f"https://www.bing.com/maps?cp={lat}~{lon}&lvl=18",
    }


def analyse_one(path: Path, *, do_ocr: bool, ocr_langs: str | None,
                do_geocode: bool) -> dict:
    meta = get_meta(path)
    res: dict = {"file": str(path), "name": path.name, "meta": meta,
                 "geo": None, "sun": None, "ocr": None, "clues": {},
                 "agent_brief": None}
    gps = meta.get("gps") or {}
    if gps.get("lat") is not None and gps.get("lon") is not None:
        geo = {"lat": gps["lat"], "lon": gps["lon"], "alt_m": gps.get("alt_m"),
               "datum": gps.get("datum"), "links": map_links(gps["lat"], gps["lon"])}
        if do_geocode:
            geo["reverse"] = reverse_geocode(gps["lat"], gps["lon"])
        res["geo"] = geo
        res["sun"] = sun_for(meta)
    if do_ocr:
        text = ocr_text(path, ocr_langs)
        res["ocr"] = text
        res["clues"] = find_clues(text)
    if not res["geo"]:
        res["agent_brief"] = _agent_brief(res)
    return res


def _agent_brief(res: dict) -> str:
    m = res["meta"]
    lines = ["# Geolocation brief (no GPS in EXIF)",
             "",
             "## Observations"]
    if m.get("datetime_original"):
        lines.append(f"- Capture time: {m['datetime_original']} (offset {m.get('offset') or 'unknown'})")
    if m.get("width"):
        lines.append(f"- Image: {m['width']}x{m['height']} {m.get('format') or ''}".rstrip())
    cam = " ".join(str(x) for x in (m.get("make"), m.get("model")) if x)
    if cam:
        lines.append(f"- Camera: {cam} · lens {m.get('lensmodel') or '?'} · "
                     f"focal {m.get('focal_length') or '?'}mm ({m.get('focal_length_35mm') or '?'}mm eq.)")
    if m.get("software"):
        lines.append(f"- Software: {m['software']}")
    if res.get("ocr"):
        lines.append(f"- OCR text: {res['ocr']}")
    if res.get("clues"):
        lines.append(f"- Clue hits: {json.dumps(res['clues'], ensure_ascii=False)}")
    lines += [
        "",
        "## Suggested next steps (geo-sleuth style)",
        "1. Reverse image search on the full frame and on edge/corner crops.",
        "2. Read regional clues: plates, road markings, signs, calling codes, driving side,",
        "   vegetation, architecture, language.",
        "3. OpenStreetMap Overpass: query candidate features (bridges, power lines, silos,",
        "   the street tree set, ...) and scan them with elevation data.",
        "4. Skyline fit: compare the photo's ridge line with the horizon computed from",
        "   elevation tiles; use shadows -> sun azimuth -> local time.",
        "5. Confirm with street-level imagery (Google Street View / Mapillary / KartaView).",
        "",
        "Every conclusion should name the command/data source that produced it.",
    ]
    return "\n".join(lines)


def to_markdown(results: list[dict], *, do_geocode: bool) -> str:
    out = [f"# photo-geolocate {VERSION}", ""]
    for res in results:
        m, geo = res["meta"], res.get("geo")
        out.append(f"## `{res['name']}`")
        out.append("")
        if geo:
            lat, lon = geo["lat"], geo["lon"]
            out.append(f"- **Coordinates (from EXIF GPS): `{lat:.6f}, {lon:.6f}`**")
            if geo.get("alt_m") is not None:
                out.append(f"- Altitude: {geo['alt_m']} m ({geo['datum']})")
            out.append(f"- OSM: {geo['links']['osm']}")
            out.append(f"- Google: {geo['links']['google']}")
            rev = geo.get("reverse")
            if isinstance(rev, dict) and rev.get("display_name"):
                out.append(f"- Reverse geocode: {rev['display_name']}")
        else:
            out.append("- No GPS in the metadata (stripped or never present).")
        if res.get("sun"):
            s = res["sun"]
            extra = " (time assumed UTC)" if s.get("assumed_utc") else ""
            out.append(f"- Sun at capture: elevation {s['elevation_deg']}°, "
                       f"azimuth {s['azimuth_deg']}°{extra}")
        if m.get("datetime_original"):
            out.append(f"- Capture time: {m['datetime_original']} (offset {m.get('offset') or '?'})")
        cam = " ".join(str(x) for x in (m.get("make"), m.get("model")) if x)
        if cam:
            out.append(f"- Camera: {cam} · {m.get('lensmodel') or ''} "
                       f"{m.get('focal_length') or ''}mm")
        if res.get("ocr"):
            out.append(f"- OCR: {res['ocr']}")
        if res.get("clues"):
            out.append(f"- Clues: `{json.dumps(res['clues'], ensure_ascii=False)}`")
        out.append("")
        if res.get("agent_brief"):
            out.append("```markdown")
            out.append(res["agent_brief"])
            out.append("```")
            out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------- cli
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Local intake for photo geolocation.")
    ap.add_argument("images", nargs="+", type=Path, help="image file(s)")
    ap.add_argument("--json", type=Path, help="also write the machine-readable result here")
    ap.add_argument("--offline", action="store_true",
                    help="never touch the network (disables --geocode)")
    ap.add_argument("--geocode", action="store_true",
                    help="reverse-geocode the GPS point via OSM Nominatim")
    ap.add_argument("--ocr", action="store_true", help="run OCR (needs tesseract)")
    ap.add_argument("--no-ocr", action="store_true", help="skip OCR ")
    ap.add_argument("--ocr-langs", default=None, help="OCR languages (e.g. eng,ita)")
    ap.add_argument("--md", type=Path, help="write the Markdown report here")
    args = ap.parse_args(argv)

    do_geocode = args.geocode and not args.offline
    do_ocr = (args.ocr and not args.no_ocr)
    if not do_ocr and not args.no_ocr and have("tesseract"):
        do_ocr = True  # sensible default: use OCR when it is available

    results = []
    for img in args.images:
        if not img.is_file():
            print(f"[!] not a file: {img}", file=sys.stderr)
            continue
        results.append(analyse_one(img, do_ocr=do_ocr, ocr_langs=args.ocr_langs,
                                   do_geocode=do_geocode))

    payload = {"tool": "photo-geolocate", "version": VERSION, "images": results}
    md = to_markdown(results, do_geocode=do_geocode)
    if args.md:
        args.md.write_text(md, encoding="utf-8")
    if args.json:
        args.json.write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    if not args.md and not args.json:
        print(md)
    else:
        got = sum(1 for r in results if r.get("geo"))
        print(f"[ok] {len(results)} image(s), {got} with GPS "
              f"{'-> ' + str(args.json) if args.json else ''}"
              f"{' + ' + str(args.md) if args.md else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
