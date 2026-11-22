"""Phase 2: evidence ingestion.

Turns raw evidence files into EvidenceDocuments made of citable records.
No interpretation happens here: no IOC extraction, no timestamp parsing.
This layer only answers "what is in the file, exactly, and where".

Guarantees:
  * sha256 of the raw bytes is kept (chain of custody).
  * Every record has a locator that provenance.resolve() can turn back
    into the same text (tested).
  * Problems (bad encoding, ragged CSV rows) become warnings on the
    document instead of being silently fixed.

Run:  python -m pmgen.ingest data/incidents/INC-2026-001
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import sys
from pathlib import Path

from .schemas import EvidenceBundle, EvidenceDocument, EvidenceRecord, FileType

MAX_BYTES = 25 * 1024 * 1024  # 25 MB per file; bigger files need streaming (later phase)
SKIP_NAMES = {"ground_truth.json"}
SUPPORTED = {".txt": FileType.TXT, ".log": FileType.TXT, ".csv": FileType.CSV, ".json": FileType.JSON}
DEFERRED = {".pdf", ".docx"}  # planned; rejected with a clear message for now
META_LOCATOR = "meta"


class IngestError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def _decode(raw: bytes) -> tuple[str, str, list[str]]:
    """Decode bytes. utf-8-sig strips a BOM if present. Falls back to cp1252
    and records a warning, rather than guessing silently."""
    try:
        return raw.decode("utf-8-sig"), "utf-8", []
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace"), "cp1252", [
            "file is not valid UTF-8; decoded as cp1252, some characters may be wrong"
        ]


# ---------------------------------------------------------------------------
# Readers: each returns (records, warnings). They are also used by
# provenance.resolve, so reading and citing can never disagree.
# ---------------------------------------------------------------------------


def read_csv(text: str) -> tuple[list[EvidenceRecord], list[str]]:
    warnings: list[str] = []
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        return [], ["CSV has no header row"]
    records = []
    for i, row in enumerate(reader, start=1):
        extra = row.pop(None, None)  # DictReader puts surplus cells under key None
        if extra:
            warnings.append(f"row {i}: {len(extra)} more cell(s) than header columns")
        if any(v is None for v in row.values()):
            warnings.append(f"row {i}: fewer cells than header columns")
            row = {k: ("" if v is None else v) for k, v in row.items()}
        records.append(EvidenceRecord(locator=f"row {i}", text=json.dumps(row, ensure_ascii=False), fields=row))
    return records, warnings


def read_txt(text: str) -> tuple[list[EvidenceRecord], list[str]]:
    records = [
        EvidenceRecord(locator=f"line {i}", text=line)
        for i, line in enumerate(text.splitlines(), start=1)
        if line.strip()
    ]
    return records, []


def read_json(text: str) -> tuple[list[EvidenceRecord], list[str]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise IngestError(f"invalid JSON: {e}") from e

    records: list[EvidenceRecord] = []
    if isinstance(data, list):
        for i, item in enumerate(data):
            records.append(_json_record(f"[{i}]", item))
        return records, []

    if not isinstance(data, dict):
        raise IngestError("JSON must be an object or a list")

    # Scalar top-level fields (e.g. "policy_mode": "detect_only") are evidence too.
    meta = {k: v for k, v in data.items() if not isinstance(v, list)}
    if meta:
        records.append(EvidenceRecord(locator=META_LOCATOR, text=json.dumps(meta, ensure_ascii=False), fields=meta))
    list_keys = [k for k, v in data.items() if isinstance(v, list)]
    for key in list_keys:
        for i, item in enumerate(data[key]):
            records.append(_json_record(f"{key}[{i}]", item))
    warnings = [] if list_keys else ["JSON object has no list of records; only top-level fields kept"]
    return records, warnings


def _json_record(locator: str, item) -> EvidenceRecord:
    fields = item if isinstance(item, dict) else {"value": item}
    return EvidenceRecord(locator=locator, text=json.dumps(item, ensure_ascii=False), fields=fields)


_READERS = {FileType.CSV: read_csv, FileType.TXT: read_txt, FileType.JSON: read_json}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def file_type_for(path: Path) -> FileType:
    suffix = path.suffix.lower()
    if suffix in SUPPORTED:
        return SUPPORTED[suffix]
    if suffix in DEFERRED:
        raise IngestError(f"{suffix} support is planned but not built yet")
    raise IngestError(f"unsupported file type: {suffix or '(none)'}")


def load_file(path: Path, source_id: str = "E01") -> EvidenceDocument:
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"not a file: {path}")
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise IngestError(f"{path.name} is {size} bytes; limit is {MAX_BYTES}")
    ftype = file_type_for(path)
    raw = path.read_bytes()
    text, encoding, warnings = _decode(raw)
    records, reader_warnings = _READERS[ftype](text)
    if not records:
        reader_warnings.append("file produced no records")
    return EvidenceDocument(
        source_id=source_id,
        file_name=path.name,
        file_type=ftype,
        sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=size,
        encoding=encoding,
        records=records,
        warnings=warnings + reader_warnings,
    )


def ingest_folder(folder: Path, incident_id: str | None = None) -> EvidenceBundle:
    """Ingest every evidence file in a folder. Bad files are skipped and
    reported, so one broken file doesn't block the whole incident."""
    folder = Path(folder)
    if not folder.is_dir():
        raise IngestError(f"not a folder: {folder}")
    docs: list[EvidenceDocument] = []
    skipped: list[str] = []
    files = sorted(p for p in folder.iterdir() if p.is_file() and not p.name.startswith("."))
    for path in files:
        if path.name in SKIP_NAMES:
            continue
        try:
            docs.append(load_file(path, source_id=f"E{len(docs) + 1:02d}"))
        except IngestError as e:
            skipped.append(f"{path.name}: {e}")
    return EvidenceBundle(incident_id=incident_id or folder.name, documents=docs, skipped=skipped)


def _summary(bundle: EvidenceBundle) -> str:
    lines = [f"Incident {bundle.incident_id}: {len(bundle.documents)} file(s) ingested"]
    for d in bundle.documents:
        lines.append(f"  {d.source_id}  {d.file_name:<22} {d.file_type.value:<5} "
                     f"{len(d.records):>4} records  sha256={d.sha256[:12]}…")
        lines += [f"        warning: {w}" for w in d.warnings]
    lines += [f"  skipped: {s}" for s in bundle.skipped]
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m pmgen.ingest <incident_folder>")
    print(_summary(ingest_folder(Path(sys.argv[1]))))
