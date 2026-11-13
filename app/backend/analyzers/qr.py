"""QR / barcode decoder (zbarimg).

Besides the direct decode, two generic fallbacks are tried: deblurring (a
smeared photo) and de-masking the data modules of a structural QR. The latter
needs no knowledge of the payload: it samples the module grid, leaves the
functional patterns alone and re-renders the QR once per standard mask, plus
the XOR of all eight ("all the masks").
"""
from __future__ import annotations

import time
from pathlib import Path

from .base import Analyzer, ToolContext, ToolResult, out_of, which
from .registry import register
from .util import IMG_EXT

# input/output caps: a QR is small, and the de-masking loop is bounded anyway
_MAX_BYTES = 32 << 20
_MAX_PIXELS = 4_000_000
_MAX_SIDE = 1200              # finder scan on a downscaled copy of big photos
_QUIET = 4                    # quiet zone (modules) of the re-rendered QR
_UNMASK_BUDGET = 120          # seconds for the whole de-masking attempt
_MAX_DIM = 1600               # rendered image cap

# standard QR finder pattern (7x7), used to score candidate centres
_FINDER = (
    (1, 1, 1, 1, 1, 1, 1),
    (1, 0, 0, 0, 0, 0, 1),
    (1, 0, 1, 1, 1, 0, 1),
    (1, 0, 1, 1, 1, 0, 1),
    (1, 0, 1, 1, 1, 0, 1),
    (1, 0, 0, 0, 0, 0, 1),
    (1, 1, 1, 1, 1, 1, 1),
)

# alignment-pattern centre coordinates by version (0 unused, 1 has none)
_ALIGNMENT = (
    (), (), (6, 18), (6, 22), (6, 26), (6, 30), (6, 34),
    (6, 22, 38), (6, 24, 42), (6, 26, 46), (6, 28, 50), (6, 30, 54),
    (6, 32, 58), (6, 34, 62), (6, 26, 46, 66), (6, 26, 48, 70),
    (6, 26, 50, 74), (6, 30, 54, 78), (6, 30, 56, 82), (6, 30, 58, 86),
    (6, 34, 62, 90), (6, 28, 50, 72, 94), (6, 26, 50, 74, 98),
    (6, 30, 54, 78, 102), (6, 28, 54, 80, 106), (6, 32, 58, 84, 110),
    (6, 30, 58, 86, 114), (6, 34, 62, 90, 118), (6, 26, 50, 74, 98, 122),
    (6, 30, 54, 78, 102, 126), (6, 26, 52, 78, 104, 130),
    (6, 30, 56, 82, 108, 134), (6, 34, 60, 86, 112, 138),
    (6, 30, 58, 86, 114, 142), (6, 34, 62, 90, 118, 146),
    (6, 30, 54, 78, 102, 126, 150), (6, 24, 50, 76, 102, 128, 154),
    (6, 28, 54, 80, 106, 132, 158), (6, 32, 58, 84, 110, 136, 162),
    (6, 26, 54, 82, 110, 138, 166), (6, 30, 58, 86, 114, 142, 170),
)


def _deblurred(path: Path, outdir: Path):
    """Deblurred copies of an image: upscale, strong unsharp mask, adaptive
    threshold. A smeared QR (ImaginaryCTF "blurry") decodes only after this."""
    try:
        from PIL import Image, ImageFilter
        import numpy as np
    except Exception:
        return
    try:
        im = Image.open(path).convert("L")
    except Exception:
        return
    # a blurred QR is small; upscaling a multi-megapixel photo 4x costs minutes
    if max(im.size) > 500:
        f = 500 / max(im.size)
        im = im.resize((max(1, round(im.width * f)), max(1, round(im.height * f))),
                       Image.LANCZOS)
    for sc in (3, 4):
        up = im.resize((im.width * sc, im.height * sc), Image.LANCZOS)
        for rad, pct in ((6, 500), (8, 600)):
            sh = up.filter(ImageFilter.UnsharpMask(radius=rad, percent=pct, threshold=0))
            arr = np.asarray(sh, dtype=np.float32)
            local = np.asarray(sh.filter(ImageFilter.GaussianBlur(15)), dtype=np.float32)
            bw = np.where(arr < local - 6, 0, 255).astype("uint8")
            out = outdir / f"qr_{sc}_{rad}.png"
            Image.fromarray(bw).save(out)
            yield out


# --- QR structure -------------------------------------------------------------
def mask_patterns(size: int):
    """The 8 standard QR data masks plus their XOR ("all the masks")."""
    import numpy as np
    y, x = np.mgrid[0:size, 0:size]
    masks = [
        (x + y) % 2 == 0,
        y % 2 == 0,
        x % 3 == 0,
        (x + y) % 3 == 0,
        (y // 2 + x // 3) % 2 == 0,
        ((x * y) % 2) + ((x * y) % 3) == 0,
        (((x * y) % 3) + x * y) % 2 == 0,
        (((x * y) % 3) + x + y) % 2 == 0,
    ]
    all_masks = np.zeros((size, size), dtype=bool)
    for m in masks:
        all_masks ^= m
    return list(masks) + [all_masks]


def functional_modules(size: int):
    """(size, size) bool: finder/separator/timing/alignment/format/version and
    the dark module. These modules are never touched by a mask."""
    import numpy as np
    version = max(1, min(40, (size - 17) // 4))
    fm = np.zeros((size, size), dtype=bool)
    # finder + separator + the adjacent format bits, at the three corners
    fm[0:9, 0:9] = True
    fm[0:9, max(0, size - 8):size] = True
    fm[max(0, size - 8):size, 0:9] = True
    # timing patterns
    fm[6, 8:size - 8] = True
    fm[8:size - 8, 6] = True
    # alignment patterns, except the three that would overlap a finder
    for cy in _ALIGNMENT[version]:
        for cx in _ALIGNMENT[version]:
            if (cx < 9 and (cy < 9 or cy > size - 9)) or (cy < 9 and cx > size - 9):
                continue
            fm[cy - 2:cy + 3, cx - 2:cx + 3] = True
    # dark module
    if size >= 9:
        fm[size - 8, 8] = True
    # version information blocks (version >= 7)
    if version >= 7:
        fm[0:6, size - 11:size - 8] = True
        fm[size - 11:size - 8, 0:6] = True
    return fm


def apply_mask(matrix, pattern, functional):
    """XOR `pattern` into the data modules only."""
    out = matrix.copy()
    data = ~functional
    out[data] ^= pattern[data]
    return out


# --- finder detection / sampling ---------------------------------------------
def _runs(line):
    """(starts, ends, colours) of the constant-colour runs of a 1-D bool array."""
    import numpy as np
    n = len(line)
    if n == 0:
        return np.asarray([], dtype=int), np.asarray([], dtype=int), np.asarray([], bool)
    change = np.flatnonzero(line[1:] != line[:-1]) + 1
    starts = np.concatenate(([0], change))
    ends = np.concatenate((change, [n]))
    return starts, ends, line[starts]


def _ratio_ok(lens, module: float) -> bool:
    tol = max(0.75, module * 0.55)
    return (abs(lens[0] - module) <= tol and abs(lens[1] - module) <= tol
            and abs(lens[2] - 3 * module) <= 3 * tol
            and abs(lens[3] - module) <= tol and abs(lens[4] - module) <= tol)


def _vertical_ok(arr, x: int, y: int, module: float) -> bool:
    starts, ends, colours = _runs(arr[:, x])
    idx = int(starts.searchsorted(y, side="right")) - 1
    if idx < 2 or idx + 2 >= len(starts):
        return False
    if not (colours[idx - 2] and not colours[idx - 1] and colours[idx]
            and not colours[idx + 1] and colours[idx + 2]):
        return False
    lens = ends[idx - 2:idx + 3] - starts[idx - 2:idx + 3]
    return _ratio_ok(lens, module)


def _finder_candidates(arr):
    """Centres (x, y, module_size) whose row and column show a 1:1:3:1:1 run."""
    candidates = []
    for y, row in enumerate(arr):
        if not row.any():
            continue
        starts, ends, colours = _runs(row)
        for i in range(len(starts) - 4):
            if not (colours[i] and not colours[i + 1] and colours[i + 2]
                    and not colours[i + 3] and colours[i + 4]):
                continue
            lens = ends[i:i + 5] - starts[i:i + 5]
            module = float(lens.sum()) / 7.0
            if module < 1.0 or not _ratio_ok(lens, module):
                continue
            cx = int((starts[i + 2] + ends[i + 2]) // 2)
            if _vertical_ok(arr, cx, y, module):
                candidates.append((cx, y, module))
    return candidates


def _cluster(candidates):
    clusters = []                       # [sum_x, sum_y, sum_m, count]
    for cx, cy, module in candidates:
        radius = max(3.0, module * 3)
        for c in clusters:
            if (abs(c[0] / c[3] - cx) <= radius
                    and abs(c[1] / c[3] - cy) <= radius):
                c[0] += cx
                c[1] += cy
                c[2] += module
                c[3] += 1
                break
        else:
            clusters.append([float(cx), float(cy), float(module), 1])
    return [(c[0] / c[3], c[1] / c[3], c[2] / c[3]) for c in clusters]


def _finder_score(arr, cx: float, cy: float, module: float) -> float:
    h, w = arr.shape
    hits = total = 0
    for row in range(7):
        for col in range(7):
            x = int(round(cx + (col - 3) * module))
            y = int(round(cy + (row - 3) * module))
            if not (0 <= x < w and 0 <= y < h):
                continue
            total += 1
            hits += bool(arr[y, x]) == bool(_FINDER[row][col])
    return hits / total if total else 0.0


def _grid(points):
    """(top-left centre, ex, ey, size) of the QR from its three finders."""
    import numpy as np
    best = None
    for i in range(3):
        p = points[i]
        a = points[(i + 1) % 3]
        b = points[(i + 2) % 3]
        va = np.array([a[0] - p[0], a[1] - p[1]], dtype=float)
        vb = np.array([b[0] - p[0], b[1] - p[1]], dtype=float)
        na, nb = float(np.hypot(*va)), float(np.hypot(*vb))
        if na < 1 or nb < 1:
            continue
        cos = abs(float(va @ vb)) / (na * nb)
        ratio = abs(na - nb) / max(na, nb)
        if best is None or cos + ratio < best[0]:
            cross = va[0] * vb[1] - va[1] * vb[0]
            if cross < 0:               # keep TR on the right of TL, BL below
                a, b = b, a
            best = (cos + ratio, p, a, b)
    if best is None:
        return None
    _score, tl, tr, bl = best
    module = sorted((tl[2], tr[2], bl[2]))[1]
    side = float(np.hypot(tr[0] - tl[0], tr[1] - tl[1])) / module
    version = int(round((side - 10) / 4))
    version = max(1, min(40, version))
    size = 17 + 4 * version
    ex = ((tr[0] - tl[0]) / (size - 7), (tr[1] - tl[1]) / (size - 7))
    ey = ((bl[0] - tl[0]) / (size - 7), (bl[1] - tl[1]) / (size - 7))
    mx, my = float(np.hypot(*ex)), float(np.hypot(*ey))
    if min(mx, my) < 0.8 or max(mx, my) / min(mx, my) > 1.5:
        return None
    return (tl[0], tl[1]), ex, ey, size


def _sample_grid(arr, tl, ex, ey, size: int):
    import numpy as np
    h, w = arr.shape
    matrix = np.zeros((size, size), dtype=bool)
    offsets = (-0.2, 0.0, 0.2)
    for row in range(size):
        for col in range(size):
            votes = seen = 0
            for du in offsets:
                for dv in offsets:
                    x = int(round(tl[0] + (col - 3 + du) * ex[0]
                                  + (row - 3 + dv) * ey[0]))
                    y = int(round(tl[1] + (col - 3 + du) * ex[1]
                                  + (row - 3 + dv) * ey[1]))
                    if 0 <= x < w and 0 <= y < h:
                        seen += 1
                        votes += bool(arr[y, x])
            matrix[row, col] = seen > 0 and votes * 2 > seen
    return matrix


def _threshold(arr):
    """Otsu threshold; None when the picture has no usable contrast."""
    import numpy as np
    hist = np.bincount(arr.ravel(), minlength=256).astype(float)
    total = float(hist.sum())
    if total == 0 or int(arr.max()) - int(arr.min()) < 32:
        return None
    values = np.arange(256, dtype=float)
    sum_all = float((values * hist).sum())
    weight_b = sum_b = 0.0
    best = -1.0
    threshold = 127
    for t in range(256):
        weight_b += hist[t]
        if weight_b == 0:
            continue
        weight_f = total - weight_b
        if weight_f == 0:
            break
        sum_b += t * hist[t]
        mean_b = sum_b / weight_b
        mean_f = (sum_all - sum_b) / weight_f
        between = weight_b * weight_f * (mean_b - mean_f) ** 2
        if between > best:
            best = between
            threshold = t
    return threshold


def _render(matrix, path: Path) -> None:
    import numpy as np
    from PIL import Image
    size = matrix.shape[0]
    full = size + 2 * _QUIET
    scale = max(1, min(10, _MAX_DIM // full))
    arr = np.full((full * scale, full * scale), 255, dtype=np.uint8)
    for row, col in np.argwhere(matrix):
        y = (int(row) + _QUIET) * scale
        x = (int(col) + _QUIET) * scale
        arr[y:y + scale, x:x + scale] = 0
    Image.fromarray(arr).save(path)


def _unmasked(path: Path, outdir: Path, deadline: float | None = None):
    """Re-rendered QRs with the data modules XORed by each candidate mask.

    Yields nothing (fast) when the image is not a structural QR or is too big.
    """
    import numpy as np
    from PIL import Image
    try:
        if path.stat().st_size > _MAX_BYTES:
            return
        with Image.open(path) as im:
            w, h = im.size
            if w * h > _MAX_PIXELS or min(w, h) < 21:
                return
            if im.mode in ("RGBA", "LA"):
                bg = Image.new("RGBA", im.size, (255, 255, 255, 255))
                arr = np.asarray(Image.alpha_composite(bg, im.convert("RGBA")).convert("L"))
            else:
                arr = np.asarray(im.convert("L"))
    except Exception:
        return
    scale = min(1.0, _MAX_SIDE / max(arr.shape))
    if scale < 1.0:
        work = np.asarray(Image.fromarray(arr).resize(
            (max(1, round(arr.shape[1] * scale)), max(1, round(arr.shape[0] * scale))),
            Image.NEAREST))
    else:
        work = arr
    threshold = _threshold(work)
    if threshold is None:
        return
    candidates = _finder_candidates(work <= threshold)
    if len(candidates) < 3:
        return
    points = []
    for cx, cy, module in _cluster(candidates):
        score = _finder_score(work <= threshold, cx, cy, module)
        if score >= 0.7:
            points.append((cx / scale, cy / scale, module / scale))
    if len(points) < 3:
        return
    points = sorted(points, key=lambda p: _finder_score(
        arr <= threshold, p[0], p[1], p[2]), reverse=True)[:3]
    grid = _grid(points)
    if grid is None:
        return
    tl, ex, ey, size = grid
    matrix = _sample_grid(arr <= threshold, tl, ex, ey, size)
    functional = functional_modules(size)
    outdir.mkdir(parents=True, exist_ok=True)
    for index, pattern in enumerate(mask_patterns(size)):
        if deadline is not None and time.monotonic() > deadline:
            return
        label = "all" if index == 8 else str(index)
        out = outdir / f"{path.stem}_unmask_{label}.png"
        _render(apply_mask(matrix, pattern, functional), out)
        yield out


class QrAnalyzer(Analyzer):
    name = "qr"
    category = "extract"
    description = "Decode QR codes and barcodes (zbarimg)."
    accepts = IMG_EXT
    display_order = 245

    def run(self, ctx: ToolContext) -> ToolResult:
        if not which("zbarimg"):
            return ToolResult(self.name, status="skipped", summary="zbarimg not installed")
        proc = ctx.run(["zbarimg", "--quiet", "--raw", str(ctx.input)], timeout=120)
        out = out_of(proc)
        if not out.strip():
            for img in _deblurred(ctx.input, ctx.sub(self.name)):
                proc = ctx.run(["zbarimg", "--quiet", "--raw", str(img)], timeout=60)
                out = out_of(proc)
                if out.strip():
                    break
        if not out.strip():
            deadline = time.monotonic() + _UNMASK_BUDGET
            for img in _unmasked(ctx.input, ctx.sub(self.name), deadline=deadline):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                proc = ctx.run(["zbarimg", "--quiet", "--raw", str(img)],
                               timeout=max(5, int(remaining)))
                out = out_of(proc)
                if out.strip():
                    break
        if not out.strip():
            # zbarimg exits 4 when no symbol is found: informational, not an error
            return ToolResult(self.name, status="skipped", summary="no QR/barcode",
                              output=out[-1000:], exit_code=proc.returncode)
        n = len(out.splitlines())
        return ToolResult(self.name, status="done", summary=f"{n} code(s) decoded",
                          output=out, exit_code=proc.returncode)


register(QrAnalyzer())
