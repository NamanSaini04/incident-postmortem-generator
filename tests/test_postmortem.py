"""Phase 5 tests. No API calls: FakeClient returns scripted drafts, good and bad,
so we can prove the validator catches each kind of LLM failure."""
import copy
import json

import pytest

from pmgen.evaluate import score_report
from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient, LLMError, inline_refs
from pmgen.postmortem import generate, main, render_markdown
from pmgen.samples import DATA_DIR, load_ground_truth
from pmgen.schemas import DraftReport
from pmgen.validate import validate_draft

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def pack():
    return build_pack(ingest_folder(DATA_DIR / INC))


def rid(pack, file, locator):
    return pack.by_location[(file, locator)]


def good_draft(pack) -> dict:
    c = lambda f, l, q: {"record_id": rid(pack, f, l), "quote": q}  # noqa: E731
    notes = "analyst_notes.txt"
    return {
        "title": "Credential phishing led to mailbox takeover",
        "category": "credential_compromise", "severity": "SEV2",
        "severity_rationale": "One account taken over; 3 emails forwarded externally.",
        "classification_confidence": 0.85,
        "executive_summary": "A phishing email led j.patel to submit credentials; the attacker signed in from "
                             "203.0.113.45 without MFA and created a forwarding rule.",
        "what_happened": [
            {"statement": "Attacker signed in from 203.0.113.45", "certainty": "confirmed",
             "citations": [c("auth_logs.csv", "row 2", "203.0.113.45")]},
            {"statement": "The attacker may have accessed SharePoint", "certainty": "possible", "citations": []},
        ],
        "key_event_ids": ["EV002", "EV007"],
        "indicators": ["203.0.113.45", "login-micros0ft.test"],
        "root_cause": {"statement": "MFA was not enforced for the account", "certainty": "confirmed",
                       "citations": [c(notes, "line 8", "MFA was not enforced for j.patel")]},
        "contributing_factors": [
            {"statement": "Gateway rated the phishing email clean", "certainty": "confirmed",
             "citations": [c(notes, "line 9", "rated the phishing message clean")]}],
        "detection_gaps": [
            {"statement": "Impossible travel alert was not triaged", "certainty": "confirmed",
             "citations": [c(notes, "line 3", "AL-5521 had not been triaged yet")]}],
        "lessons": [{"area": "technology", "lesson": "MFA exceptions need expiry dates",
                     "citations": [c(notes, "line 8", "exception was never removed")]}],
        "corrective_actions": [
            {"recommendation": "Remove all MFA exclusions", "priority": "critical",
             "reason": "Missing MFA allowed the takeover", "owner_team": "IAM", "timeframe": "7 days",
             "expected_benefit": "Stolen passwords alone no longer work",
             "citations": [c(notes, "line 8", "MFA was not enforced")]}],
        "open_questions": ["Was SharePoint accessed?"],
        "remaining_risks": ["Other accounts may have MFA exceptions."],
    }


def test_ground_truth_never_shown_to_llm(pack):
    assert "ground_truth" not in pack.to_prompt()
    assert "must_not_claim" not in pack.to_prompt()


def test_good_draft_passes_cleanly(pack):
    pm = generate(pack, FakeClient([good_draft(pack)]))
    assert pm.validation_log == ["attempt 1: 0 validation problem(s)"]
    assert pm.root_cause.evidence[0].locator == "line 8"
    assert [i.value for i in pm.indicators] == ["203.0.113.45", "login-micros0ft.test"]


# --- each kind of LLM failure is caught ------------------------------------------

@pytest.mark.parametrize("mutate,expected", [
    (lambda d: d["root_cause"]["citations"][0].update(record_id="R999"), "does not exist"),
    (lambda d: d["root_cause"]["citations"][0].update(quote="MFA was enabled and enforced"), "not found in"),
    (lambda d: d["what_happened"][0].update(citations=[]), "needs at least one valid citation"),
    (lambda d: d["indicators"].append("198.51.100.99"), "not extracted from the evidence"),
    (lambda d: d.update(executive_summary="Attacker used evil-c2.example for exfiltration."), "not in the evidence"),
    (lambda d: d["key_event_ids"].append("EV999"), "not a timeline event"),
    (lambda d: d["lessons"][0].update(area="vibes"), "must be one of"),
    (lambda d: d["corrective_actions"][0].update(citations=[]), "needs at least one valid citation"),
])
def test_validator_catches(pack, mutate, expected):
    d = good_draft(pack)
    mutate(d)
    issues = validate_draft(DraftReport.model_validate(d), pack)
    assert any(expected in i.problem for i in issues), issues


def test_possible_claim_without_citation_is_allowed(pack):
    issues = validate_draft(DraftReport.model_validate(good_draft(pack)), pack)
    assert not [i for i in issues if i.where == "what_happened[1]"]


# --- retry and repair ------------------------------------------------------------

def test_retry_sends_problems_back_and_uses_fixed_draft(pack):
    bad = good_draft(pack)
    bad["root_cause"]["citations"][0]["quote"] = "invented quote"
    client = FakeClient([bad, good_draft(pack)])
    pm = generate(pack, client)
    assert len(client.calls) == 2
    assert "FAILED THESE CHECKS" in client.calls[1][1] and "invented quote" in client.calls[1][1]
    assert pm.root_cause is not None
    # a fake quote gives 2 problems: the quote isn't in the record, and no valid citation is left
    assert pm.validation_log[:2] == ["attempt 1: 2 validation problem(s)", "attempt 2: 0 validation problem(s)"]


def test_still_bad_after_retry_drops_claim_and_logs_it(pack):
    bad = good_draft(pack)
    bad["root_cause"]["citations"] = []
    pm = generate(pack, FakeClient([bad, copy.deepcopy(bad)]))
    assert pm.root_cause is None
    assert any("root_cause: DROPPED" in x for x in pm.validation_log)
    assert "_Not determined" in render_markdown(pm)


def test_invented_indicator_is_redacted_from_text(pack):
    bad = good_draft(pack)
    bad["executive_summary"] += " Data went to 198.51.100.250."
    pm = generate(pack, FakeClient([bad, copy.deepcopy(bad)]))
    assert "198.51.100.250" not in pm.executive_summary
    assert "[unverified indicator removed]" in pm.executive_summary
    md = render_markdown(pm)
    assert "198.51.100.250" not in md          # nowhere in the report, including the log
    assert "198[.]51[.]100[.]250" in md        # the log shows it defanged


def test_malformed_draft_retried_then_errors(pack):
    with pytest.raises(LLMError, match="no draft matched"):
        generate(pack, FakeClient([{"title": "x"}, {"title": "y"}]))


# --- output ------------------------------------------------------------------------

def test_markdown_has_all_sections_and_citations(pack):
    md = render_markdown(generate(pack, FakeClient([good_draft(pack)])))
    for h in ["Executive summary", "Timeline (UTC)", "What happened", "Indicators of compromise", "Root cause",
              "Contributing factors", "Detection gaps", "Lessons learned", "Corrective actions",
              "Open questions", "Validation log", "Evidence index", "SHA-256", "DRAFT: requires human review"]:
        assert h in md, h
    assert "[E1]" in md and "| E1 |" in md
    assert "**EV002**" in md  # key event highlighted


def test_score_report(pack):
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([good_draft(pack)])))
    assert s.category_correct and s.severity_correct and s.root_cause_grounded
    assert s.contributing_factor_recall == 1.0
    assert s.indicator_precision == 1.0 and 0 < s.indicator_recall < 1  # listed only 2 of the IOCs


def test_tool_schema_has_no_refs():
    assert "$ref" not in json.dumps(inline_refs(DraftReport.model_json_schema()))


def test_cli_dry_run_needs_no_key(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main([str(DATA_DIR / INC), "--dry-run"]) == 0
    assert "EVIDENCE RECORDS" in capsys.readouterr().out


def test_cli_without_key_fails_clearly(capsys, monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main([str(DATA_DIR / INC), "--out", str(tmp_path)]) == 1
    assert "ANTHROPIC_API_KEY is not set" in capsys.readouterr().err
