"""Resolve an EvidenceRef back to the exact text it points at.

Uses the same readers as ingestion, so a citation produced from an
ingested record always resolves to that record's text.

Locator formats:
  CSV  -> "row N"      (1-based, header excluded)
  TXT  -> "line N"     (1-based, original line numbers; blank lines are not citable)
  JSON -> "key[i]", "[i]" for a top-level list, or "meta" for top-level scalar fields
"""
from __future__ import annotations

from pathlib import Path

from .ingest import IngestError, load_file
from .schemas import EvidenceRef


class LocatorError(ValueError):
    pass


def resolve(ref: EvidenceRef, incident_dir: Path) -> str:
    """Return the cited record as text. Raises LocatorError if it doesn't exist."""
    path = Path(incident_dir) / ref.file
    try:
        doc = load_file(path)
    except IngestError as e:
        raise LocatorError(str(e)) from e
    for rec in doc.records:
        if rec.locator == ref.locator:
            return rec.text
    raise LocatorError(f"{ref.file}: locator {ref.locator!r} not found ({len(doc.records)} records)")


def excerpt_matches(ref: EvidenceRef, incident_dir: Path) -> bool:
    """True if the cited record actually contains the quoted excerpt."""
    if ref.excerpt is None:
        return True
    text = resolve(ref, incident_dir)
    # JSON-dumped records escape backslashes; compare on a normalised form too.
    return ref.excerpt in text or ref.excerpt in text.replace("\\\\", "\\")
