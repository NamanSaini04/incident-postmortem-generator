"""Check the synthetic incidents are internally consistent.

If the ground truth is wrong, every later evaluation score is meaningless,
so these tests check the ground truth against the raw evidence files.
"""
import json

import pytest

from pmgen.provenance import LocatorError, excerpt_matches, resolve
from pmgen.samples import DATA_DIR, evidence_files, list_incidents, load_ground_truth
from pmgen.schemas import EvidenceRef

INCIDENTS = list_incidents()


def test_six_incidents_bundled():
    assert INCIDENTS == [f"INC-2026-00{i}" for i in range(1, 7)]


@pytest.mark.parametrize("inc", INCIDENTS)
def test_ground_truth_loads_and_ids_match(inc):
    gt = load_ground_truth(inc)
    assert gt.incident_id == inc


@pytest.mark.parametrize("inc", INCIDENTS)
def test_every_citation_resolves_and_excerpt_matches(inc):
    gt = load_ground_truth(inc)
    folder = DATA_DIR / inc
    refs = [e.source for e in gt.timeline] + gt.root_cause.evidence
    refs += [ev for f in gt.contributing_factors for ev in f.evidence]
    for ref in refs:
        assert excerpt_matches(ref, folder), f"{inc}: excerpt {ref.excerpt!r} not in {ref.file} {ref.locator}"


@pytest.mark.parametrize("inc", INCIDENTS)
def test_timeline_timestamps_match_cited_record(inc):
    """The ground-truth time must appear in the record it cites."""
    gt = load_ground_truth(inc)
    folder = DATA_DIR / inc
    for ev in gt.timeline:
        record = resolve(ev.source, folder)
        if ev.source.file.endswith(".txt"):
            expected = ev.timestamp.strftime("%H:%M")
        else:
            expected = ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert expected in record, f"{inc}/{ev.key}: {expected} not in {record}"


@pytest.mark.parametrize("inc", INCIDENTS)
def test_every_ioc_appears_in_evidence(inc):
    """Ground truth must not contain IOCs that aren't in the evidence."""
    gt = load_ground_truth(inc)
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in evidence_files(inc))
    for ioc_type, values in gt.iocs.items():
        for v in values:
            assert v in corpus, f"{inc}: {ioc_type.value} IOC {v!r} not found in evidence"


@pytest.mark.parametrize("inc", INCIDENTS)
def test_each_incident_has_hallucination_traps(inc):
    assert len(load_ground_truth(inc).must_not_claim) >= 3


def test_bad_locator_raises():
    folder = DATA_DIR / "INC-2026-001"
    with pytest.raises(LocatorError):
        resolve(EvidenceRef(file="auth_logs.csv", locator="row 99"), folder)
    with pytest.raises(LocatorError):
        resolve(EvidenceRef(file="missing.csv", locator="row 1"), folder)


def test_evidence_json_files_are_valid():
    for inc in INCIDENTS:
        for p in evidence_files(inc):
            if p.suffix == ".json":
                json.loads(p.read_text(encoding="utf-8"))


# --- locating the data folder (regression: plain pip install put code in site-packages) ---

def test_env_var_wins(tmp_path, monkeypatch):
    from pmgen.samples import find_data_dir
    monkeypatch.setenv("PMGEN_DATA_DIR", str(tmp_path))
    assert find_data_dir() == tmp_path.resolve()


def test_found_from_current_folder(tmp_path, monkeypatch):
    from pmgen.samples import find_data_dir
    (tmp_path / "data" / "incidents").mkdir(parents=True)
    monkeypatch.delenv("PMGEN_DATA_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert find_data_dir() == tmp_path / "data" / "incidents"


def test_missing_data_gives_clear_error(tmp_path):
    from pmgen.samples import list_incidents
    with pytest.raises(FileNotFoundError, match="PMGEN_DATA_DIR"):
        list_incidents(tmp_path / "nope")
