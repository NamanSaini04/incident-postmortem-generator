"""Phase 9: independent verifier for saved reports. Each tamper must be caught."""

import shutil

import pytest

from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient
from pmgen.postmortem import generate
from pmgen.samples import DATA_DIR
from pmgen.schemas import Certainty, Postmortem
from pmgen.verify import main, verify

from .test_impact import phase8_draft

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def report() -> Postmortem:
    pack = build_pack(ingest_folder(DATA_DIR / INC))
    d = phase8_draft(pack)
    d["corrective_actions"][0]["citations"].append({"record_id": "K01", "quote": pack.kb["K01"].text[:40]})
    return generate(pack, FakeClient([d]))


def fresh(report) -> Postmortem:
    return Postmortem.model_validate_json(report.model_dump_json())


def failed(result) -> dict[str, list[str]]:
    return {c.name: c.failures for c in result.checks if c.failures}


def test_clean_report_passes(report):
    r = verify(report, DATA_DIR / INC)
    assert r.ok, failed(r)
    names = {c.name: c.checked for c in r.checks}
    assert names["citations resolve and quotes match"] > 20
    assert names["policy quotes found in the knowledge base"] >= 1
    assert names["response milestones and durations recompute"] == 8


def test_round_trip_through_json_still_passes(report, tmp_path):
    f = tmp_path / f"{INC}_postmortem.json"
    f.write_text(report.model_dump_json(), encoding="utf-8")
    assert main([str(tmp_path)]) == 0


@pytest.mark.parametrize("how,check", [
    (lambda pm: setattr(pm.root_cause.evidence[0], "excerpt", "MFA was enforced for everyone"),
     "citations resolve and quotes match"),
    (lambda pm: setattr(pm.root_cause.evidence[0], "locator", "line 99"), "citations resolve and quotes match"),
    (lambda pm: setattr(pm.indicators[0], "value", "203.0.113.99"), "indicators appear in their cited record"),
    (None, "ATT&CK technique IDs exist and are current"),  # handled below: add a non-existent technique
    (lambda pm: setattr(pm.response.durations[0], "seconds", 60), "response milestones and durations recompute"),
    (lambda pm: pm.impact.accounts_involved.append("ceo.account"), "impact systems/accounts appear in the evidence"),
    (lambda pm: setattr(pm.corrective_actions[0].policy_refs[0], "excerpt", "MFA is optional"),
     "policy quotes found in the knowledge base"),
    (lambda pm: setattr(pm.root_cause, "evidence", []), "confirmed/probable findings have evidence"),
    (lambda pm: pm.file_hashes.update({"auth_logs.csv": "0" * 64}), "evidence files unchanged (SHA-256)"),
])
def test_tampering_is_caught(report, how, check):
    pm = fresh(report)
    if how is None:
        from pmgen.schemas import AttackMapping, EvidenceRef
        pm.attack.append(AttackMapping(technique_id="T1999", technique_name="Fake", tactic="none",
                                       evidence=[EvidenceRef(file="auth_logs.csv", locator="row 2")], confidence=0.5))
    else:
        how(pm)
    r = verify(pm, DATA_DIR / INC)
    assert check in failed(r), failed(r)
    assert not r.ok


def test_edited_evidence_file_is_caught(report, tmp_path):
    work = tmp_path / INC
    shutil.copytree(DATA_DIR / INC, work)
    notes = work / "analyst_notes.txt"
    notes.write_text(notes.read_text().replace("MFA was not enforced", "MFA was enforced"), encoding="utf-8")
    r = verify(fresh(report), work)
    f = failed(r)
    assert any("contents changed" in m for m in f["evidence files unchanged (SHA-256)"])
    assert "citations resolve and quotes match" in f   # the root-cause quote no longer exists


def test_extra_evidence_file_is_reported(report, tmp_path):
    work = tmp_path / INC
    shutil.copytree(DATA_DIR / INC, work)
    (work / "late_addition.txt").write_text("new evidence\n", encoding="utf-8")
    assert any("late_addition.txt" in m for m in failed(verify(fresh(report), work))["evidence files unchanged (SHA-256)"])


def test_possible_finding_without_evidence_is_fine(report):
    pm = fresh(report)
    pm.root_cause.certainty, pm.root_cause.evidence = Certainty.POSSIBLE, []
    assert "confirmed/probable findings have evidence" not in failed(verify(pm, DATA_DIR / INC))


def test_cli_exit_code_on_failure(report, tmp_path, capsys):
    pm = fresh(report)
    pm.impact.systems_involved.append("SAP-PROD-01")
    (tmp_path / f"{INC}_postmortem.json").write_text(pm.model_dump_json(), encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert "SAP-PROD-01" in capsys.readouterr().out


def test_counts_claims_removed_during_generation():
    pack = build_pack(ingest_folder(DATA_DIR / INC))
    d = phase8_draft(pack)
    d["impact"]["systems_involved"].append("SAP-PROD-01")
    pm = generate(pack, FakeClient([d, d]))
    r = verify(pm, DATA_DIR / INC)
    assert r.ok and r.claims_removed == 1


def test_missing_folder_is_a_message_not_a_crash(tmp_path, capsys):
    from pmgen.pdf import main as pdf_main
    from pmgen.agents import main as agents_main
    from pmgen.evalsuite import main as eval_main
    missing = str(tmp_path / "reports" / "phase8")
    assert main([missing]) == 2
    assert pdf_main([missing]) == 2
    assert agents_main(["review", missing, "--dry-run"]) == 2
    assert eval_main([missing]) == 2
    assert "docs/sample_reports/phase8" in capsys.readouterr().err
