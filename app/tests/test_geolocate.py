"""photo-geolocate: DMS conversion, sun position and the JSON contract."""
import sys
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "photo-geolocate"))
import geolocate as g  # noqa: E402  (the tool is a standalone script)


def test_dms_to_degrees():
    assert g._dms_to_deg(((45, 1), (27, 1), (0, 1)), "N") == 45.45
    west = g._dms_to_deg(((9, 1), (11, 1), (0, 1)), "W")
    assert abs(west + (9 + 11 / 60)) < 1e-9
    assert g._dms_to_deg(12.5, "E") == 12.5
    assert g._dms_to_deg("nope", "N") is None


def test_sun_is_high_and_south_at_noon_in_june():
    # Milan, 2026-06-21 11:00 UTC (13:00 local): sun high in the south
    sun = g._sun_position(45.4642, 9.19, datetime(2026, 6, 21, 11, 0, tzinfo=timezone.utc))
    assert 55 <= sun["elevation_deg"] <= 75
    assert 150 <= sun["azimuth_deg"] <= 210


def test_find_clues():
    clues = g.find_clues("call +39 02 1234, see https://example.org or mail a@b.it, plate AB 123 CD")
    assert "https://example.org" in clues["urls"]
    assert "a@b.it" in clues["emails"]
    assert "+39 02 1234" in clues["calling_codes"]
    assert "AB 123 CD" in clues["plate_like"]


def test_json_contract_on_an_image_without_exif(tmp_path):
    img = tmp_path / "plain.jpg"
    Image.new("RGB", (32, 24), (20, 30, 40)).save(img)
    res = g.analyse_one(img, do_ocr=False, ocr_langs=None, do_geocode=False)
    assert res["name"] == "plain.jpg"
    assert {"file", "name", "meta", "geo", "sun", "ocr", "clues", "agent_brief"} <= set(res)
    assert res["geo"] is None
    assert res["agent_brief"]          # the no-GPS brief is still produced
