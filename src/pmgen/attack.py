"""Phase 7: MITRE ATT&CK catalogue lookups.

The model proposes technique IDs from its own knowledge (no list is given to it,
so the answer key cannot leak through the prompt). Every ID is then checked
against the official Enterprise ATT&CK data, and names and tactics are taken from
that data, never from the model.

Catalogue: data/attack/enterprise_techniques.json, built from MITRE's
enterprise-attack.json by scripts/build_attack_catalog.py (source URL, SHA-256,
version and MITRE's notice are stored in the file).

Run:  python -m pmgen.attack T1059.001 T1566
"""
from __future__ import annotations

import json
import re
import sys
from functools import lru_cache
from pathlib import Path

TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def catalog_path() -> Path:
    from .samples import DATA_DIR
    return DATA_DIR.parent / "attack" / "enterprise_techniques.json"


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    return json.loads(catalog_path().read_text(encoding="utf-8"))


def lookup(tid: str) -> dict | None:
    return load_catalog()["techniques"].get(tid.strip().upper())


def check_id(tid: str) -> str | None:
    """None if tid is a current Enterprise ATT&CK technique, else the problem."""
    t = tid.strip().upper()
    if not TECHNIQUE_ID.match(t):
        return f"{tid!r} is not a valid ATT&CK technique ID format"
    entry = lookup(t)
    if entry is None:
        return f"{t} does not exist in Enterprise ATT&CK ({load_catalog()['version']})"
    if entry["revoked"] or entry["deprecated"]:
        return f"{t} ({entry['name']}) is revoked or deprecated in the current ATT&CK release"
    return None


def parent(tid: str) -> str:
    return tid.split(".")[0]


def related(a: str, b: str) -> bool:
    """Same technique, or one is the parent of the other (T1566 ~ T1566.002).
    Two different sub-techniques of one parent are NOT related."""
    return a == b or a == parent(b) or b == parent(a)


def full_name(tid: str) -> str:
    e = lookup(tid)
    if e is None:
        return tid
    if "." in tid:
        p = lookup(parent(tid))
        return f"{p['name']}: {e['name']}" if p else e["name"]
    return e["name"]


if __name__ == "__main__":
    print(load_catalog()["version"])
    for t in sys.argv[1:]:
        problem = check_id(t)
        print(f"{t}: {problem or full_name(t) + ' ' + str(lookup(t)['tactics'])}")
