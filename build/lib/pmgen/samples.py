"""Load the bundled synthetic incidents and their ground truth."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .schemas import GroundTruth

GROUND_TRUTH_FILE = "ground_truth.json"
ENV_VAR = "PMGEN_DATA_DIR"


def find_data_dir() -> Path:
    """Locate data/incidents.

    Order: $PMGEN_DATA_DIR, then ./data/incidents under the current folder,
    then next to the source tree (works for `pip install -e` and pytest).
    A plain `pip install` copies the code into site-packages but not the data,
    so relying only on the code's own location breaks; see README.
    """
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    for base in (Path.cwd(), Path(__file__).resolve().parents[2]):
        candidate = base / "data" / "incidents"
        if candidate.is_dir():
            return candidate
    return Path.cwd() / "data" / "incidents"


DATA_DIR = find_data_dir()


def list_incidents(data_dir: Path | None = None) -> list[str]:
    data_dir = data_dir or DATA_DIR
    if not data_dir.is_dir():
        raise FileNotFoundError(
            f"incident data not found at {data_dir}. Run from the project folder "
            f"(the one containing data/incidents) or set {ENV_VAR}."
        )
    return sorted(p.name for p in data_dir.iterdir() if (p / GROUND_TRUTH_FILE).exists())


def evidence_files(incident_id: str, data_dir: Path | None = None) -> list[Path]:
    folder = (data_dir or DATA_DIR) / incident_id
    return sorted(p for p in folder.iterdir() if p.is_file() and p.name != GROUND_TRUTH_FILE)


def load_ground_truth(incident_id: str, data_dir: Path | None = None) -> GroundTruth:
    raw = json.loads(((data_dir or DATA_DIR) / incident_id / GROUND_TRUTH_FILE).read_text(encoding="utf-8"))
    return GroundTruth.model_validate(raw)
