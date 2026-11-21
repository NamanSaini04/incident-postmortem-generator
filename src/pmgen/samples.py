"""Load the bundled synthetic incidents and their ground truth."""
from __future__ import annotations

import json
from pathlib import Path

from .schemas import GroundTruth

DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "incidents"
GROUND_TRUTH_FILE = "ground_truth.json"


def list_incidents(data_dir: Path = DATA_DIR) -> list[str]:
    return sorted(p.name for p in data_dir.iterdir() if (p / GROUND_TRUTH_FILE).exists())


def evidence_files(incident_id: str, data_dir: Path = DATA_DIR) -> list[Path]:
    folder = data_dir / incident_id
    return sorted(p for p in folder.iterdir() if p.is_file() and p.name != GROUND_TRUTH_FILE)


def load_ground_truth(incident_id: str, data_dir: Path = DATA_DIR) -> GroundTruth:
    raw = json.loads((data_dir / incident_id / GROUND_TRUTH_FILE).read_text(encoding="utf-8"))
    return GroundTruth.model_validate(raw)
