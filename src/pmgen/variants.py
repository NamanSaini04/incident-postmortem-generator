"""Messy variants of the synthetic incidents, with ground truth kept correct.

Clean hand-written logs flatter any system. Each variant adds one kind of
real-world mess, and rewrites the ground truth where the mess moves things
(e.g. shuffled rows get new row numbers).

  shuffled     CSV rows in random order (logs exported unsorted)
  noisy        benign rows appended to every CSV (unrelated activity)
  offset_tz    one CSV's timestamps rewritten as +05:30 (same instant, different zone)
  dup_alert    first item of each JSON list duplicated (alert fired twice)
  combined     all of the above together

Deterministic: same seed, same output.
"""
from __future__ import annotations

import csv
import io
import json
import random
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .samples import DATA_DIR, GROUND_TRUTH_FILE, load_ground_truth
from .schemas import GroundTruth

VARIANTS = ["shuffled", "noisy", "offset_tz", "dup_alert", "combined"]
TS_COLUMNS = {"timestamp", "time", "eventtime"}
IST = timezone(timedelta(hours=5, minutes=30))


def _read_csv(path: Path) -> tuple[list[str], list[dict]]:
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader.fieldnames or []), list(reader)


def _write_csv(path: Path, header: list[str], rows: list[dict]) -> None:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")


def _remap_rows(gt: dict, file: str, mapping: dict[int, int]) -> None:
    """Rewrite every 'row N' citation for `file` in the raw ground-truth dict."""
    def fix(ref: dict) -> None:
        if ref["file"] == file and ref["locator"].startswith("row "):
            ref["locator"] = f"row {mapping[int(ref['locator'][4:])]}"
    for ev in gt["timeline"]:
        fix(ev["source"])
    for ref in gt["root_cause"]["evidence"]:
        fix(ref)
    for f in gt["contributing_factors"]:
        for ref in f["evidence"]:
            fix(ref)


def _shuffle(folder: Path, gt: dict, rng: random.Random) -> None:
    for p in sorted(folder.glob("*.csv")):
        header, rows = _read_csv(p)
        order = list(range(len(rows)))
        rng.shuffle(order)
        _write_csv(p, header, [rows[i] for i in order])
        _remap_rows(gt, p.name, {old + 1: new + 1 for new, old in enumerate(order)})


def _noise(folder: Path, rng: random.Random) -> None:
    for p in sorted(folder.glob("*.csv")):
        header, rows = _read_csv(p)
        ts_col = next((h for h in header if h.lower() in TS_COLUMNS), None)
        for k in range(3):
            row = {h: "" for h in header}
            for h in header:
                hl = h.lower()
                if hl in ("user", "src_host"):
                    row[h] = f"noise{k}.user" if hl == "user" else f"WS-NOISE-{k}"
                elif "ip" in hl:
                    row[h] = f"192.0.2.{200 + k}"
                elif "url" in hl:
                    row[h] = f"https://intranet.example/page{k}"
                else:
                    row[h] = rows[0].get(h, "") if rows else ""
            if ts_col and rows:
                base = datetime.fromisoformat(rows[0][ts_col].replace("Z", "+00:00"))
                row[ts_col] = (base + timedelta(hours=1 + k, minutes=rng.randint(1, 50))).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append(row)
        _write_csv(p, header, rows)


def _offset_tz(folder: Path) -> None:
    csvs = sorted(folder.glob("*.csv"))
    for p in csvs:
        header, rows = _read_csv(p)
        ts_col = next((h for h in header if h.lower() in TS_COLUMNS), None)
        if ts_col:
            for r in rows:
                dt = datetime.fromisoformat(r[ts_col].replace("Z", "+00:00"))
                r[ts_col] = dt.astimezone(IST).isoformat()
            _write_csv(p, header, rows)
            return  # one source only: mixed zones are the realistic case


def _dup_alert(folder: Path) -> None:
    for p in sorted(folder.glob("*.json")):
        if p.name == GROUND_TRUTH_FILE:
            continue
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list) and v:
                    v.append(dict(v[0]) if isinstance(v[0], dict) else v[0])
                    break
            p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def make_variant(incident_id: str, name: str, out_dir: Path, seed: int = 7) -> tuple[Path, GroundTruth]:
    if name not in VARIANTS:
        raise ValueError(f"unknown variant {name!r}")
    src = DATA_DIR / incident_id
    dst = Path(out_dir) / f"{incident_id}__{name}"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    gt = json.loads((dst / GROUND_TRUTH_FILE).read_text(encoding="utf-8"))
    rng = random.Random(f"{seed}-{incident_id}-{name}")

    steps = VARIANTS[:-1] if name == "combined" else [name]
    # Noise is appended before shuffling, so shuffled noise is mixed into real rows.
    if "noisy" in steps:
        _noise(dst, rng)
    if "offset_tz" in steps:
        _offset_tz(dst)
    if "dup_alert" in steps:
        _dup_alert(dst)
    if "shuffled" in steps:
        _shuffle(dst, gt, rng)

    (dst / GROUND_TRUTH_FILE).write_text(json.dumps(gt, indent=2), encoding="utf-8")
    return dst, GroundTruth.model_validate(gt)


# Keep a reference for callers that want the clean ground truth too.
__all__ = ["VARIANTS", "make_variant", "load_ground_truth"]
