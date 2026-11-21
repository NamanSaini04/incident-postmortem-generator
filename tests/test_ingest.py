"""Phase 2 tests: ingestion must be exact, traceable and loud about problems."""
import hashlib
import json

import pytest

from pmgen.ingest import IngestError, ingest_folder, load_file
from pmgen.provenance import resolve
from pmgen.samples import DATA_DIR, list_incidents
from pmgen.schemas import EvidenceRef, FileType

INC1 = DATA_DIR / "INC-2026-001"
INC2 = DATA_DIR / "INC-2026-002"


# --- real sample files -----------------------------------------------------

def test_csv_one_record_per_row():
    doc = load_file(INC1 / "auth_logs.csv")
    assert doc.file_type is FileType.CSV
    assert [r.locator for r in doc.records] == ["row 1", "row 2", "row 3", "row 4"]
    assert doc.records[1].fields["src_ip"] == "203.0.113.45"
    assert doc.warnings == []


def test_json_list_items_and_meta():
    doc = load_file(INC2 / "edr_events.json")
    locators = [r.locator for r in doc.records]
    assert locators[0] == "meta"
    assert doc.records[0].fields["policy_mode"] == "detect_only"  # context, not lost
    assert locators[1:] == [f"events[{i}]" for i in range(6)]


def test_txt_skips_blank_lines_but_keeps_line_numbers(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("first\n\nthird\n", encoding="utf-8")
    doc = load_file(p)
    assert [(r.locator, r.text) for r in doc.records] == [("line 1", "first"), ("line 3", "third")]


def test_sha256_is_of_raw_bytes():
    path = INC1 / "auth_logs.csv"
    assert load_file(path).sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("inc", list_incidents())
def test_every_record_resolves_to_itself(inc):
    """Core guarantee: any record can be cited and the citation resolves back to it."""
    bundle = ingest_folder(DATA_DIR / inc)
    for doc in bundle.documents:
        for rec in doc.records:
            assert resolve(EvidenceRef(file=doc.file_name, locator=rec.locator), DATA_DIR / inc) == rec.text


@pytest.mark.parametrize("inc", list_incidents())
def test_folder_ingest_skips_ground_truth(inc):
    bundle = ingest_folder(DATA_DIR / inc)
    names = [d.file_name for d in bundle.documents]
    assert "ground_truth.json" not in names
    assert bundle.skipped == []
    assert [d.source_id for d in bundle.documents] == [f"E{i:02d}" for i in range(1, len(names) + 1)]


def test_bundle_counts_for_incident_1():
    bundle = ingest_folder(INC1)
    assert {d.file_name: len(d.records) for d in bundle.documents} == {
        "analyst_notes.txt": 11, "auth_logs.csv": 4, "email_gateway.csv": 3,
        "proxy_logs.csv": 2, "siem_alerts.json": 3,
    }


# --- messy input -----------------------------------------------------------

def test_csv_with_bom_header_is_clean(tmp_path):
    p = tmp_path / "bom.csv"
    p.write_bytes("﻿timestamp,user\n2026-01-01T00:00:00Z,a\n".encode("utf-8"))
    doc = load_file(p)
    assert "timestamp" in doc.records[0].fields  # not "﻿timestamp"


def test_non_utf8_falls_back_with_warning(tmp_path):
    p = tmp_path / "legacy.txt"
    p.write_bytes("user caf\xe9 login".encode("latin-1"))
    doc = load_file(p)
    assert doc.encoding == "cp1252"
    assert "café" in doc.records[0].text
    assert any("not valid UTF-8" in w for w in doc.warnings)


def test_ragged_csv_rows_are_warned_not_dropped(tmp_path):
    p = tmp_path / "ragged.csv"
    p.write_text("a,b,c\n1,2,3\n1,2\n1,2,3,4\n", encoding="utf-8")
    doc = load_file(p)
    assert len(doc.records) == 3
    assert doc.records[1].fields == {"a": "1", "b": "2", "c": ""}
    assert any("row 2: fewer" in w for w in doc.warnings)
    assert any("row 3: 1 more" in w for w in doc.warnings)


def test_top_level_json_list(tmp_path):
    p = tmp_path / "alerts.json"
    p.write_text(json.dumps([{"id": 1}, {"id": 2}]), encoding="utf-8")
    doc = load_file(p)
    assert [r.locator for r in doc.records] == ["[0]", "[1]"]
    assert resolve(EvidenceRef(file="alerts.json", locator="[1]"), tmp_path) == '{"id": 2}'


def test_empty_file_warns(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("", encoding="utf-8")
    doc = load_file(p)
    assert doc.records == []
    assert doc.warnings


def test_invalid_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(IngestError, match="invalid JSON"):
        load_file(p)


@pytest.mark.parametrize("name,msg", [("report.pdf", "planned"), ("tool.exe", "unsupported")])
def test_unsupported_types_rejected(tmp_path, name, msg):
    p = tmp_path / name
    p.write_bytes(b"x")
    with pytest.raises(IngestError, match=msg):
        load_file(p)


def test_oversize_file_rejected(tmp_path, monkeypatch):
    import pmgen.ingest as ing
    monkeypatch.setattr(ing, "MAX_BYTES", 10)
    p = tmp_path / "big.txt"
    p.write_text("x" * 11, encoding="utf-8")
    with pytest.raises(IngestError, match="limit"):
        load_file(p)


def test_bad_file_skipped_not_fatal(tmp_path):
    (tmp_path / "good.csv").write_text("a\n1\n", encoding="utf-8")
    (tmp_path / "bad.json").write_text("{oops", encoding="utf-8")
    (tmp_path / "scan.pdf").write_bytes(b"%PDF")
    bundle = ingest_folder(tmp_path, incident_id="INC-TEST")
    assert [d.file_name for d in bundle.documents] == ["good.csv"]
    assert len(bundle.skipped) == 2
