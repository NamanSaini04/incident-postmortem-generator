"""Phase 8: immediate cause, impact scope and response milestones."""

import pytest

from pmgen.evaluate import score_report
from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient
from pmgen.postmortem import SYSTEM_PROMPT, fmt_duration, generate, render_markdown
from pmgen.samples import DATA_DIR, list_incidents, load_ground_truth
from pmgen.schemas import MILESTONES, DraftReport
from pmgen.validate import check_milestones, validate_draft

from .test_postmortem import good_draft, rid

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def pack():
    return build_pack(ingest_folder(DATA_DIR / INC))


def ev(pack, file, locator):
    for e in pack.timeline.events:
        if any((s.file, s.locator) == (file, locator) for s in e.sources):
            return e.event_id
    raise AssertionError((file, locator))


def phase8_draft(pack) -> dict:
    d = good_draft(pack)
    c = lambda f, l, q: {"record_id": rid(pack, f, l), "quote": q}  # noqa: E731
    d["immediate_cause"] = {"statement": "j.patel signed in from the attacker IP after the phishing email",
                            "certainty": "confirmed", "citations": [c("auth_logs.csv", "row 2", "203.0.113.45")]}
    d["impact"] = {
        "systems_involved": ["Exchange Online"], "accounts_involved": ["j.patel"],
        "data_affected": {"statement": "Mailbox contents exposed", "certainty": "probable",
                          "citations": [c("auth_logs.csv", "row 2", "Exchange Online")]},
        "business_impact": {"statement": "Financial cost not stated in the evidence", "certainty": "unknown",
                            "citations": []},
    }
    d["milestones"] = {"attack_start": ev(pack, "email_gateway.csv", "row 1"),
                       "first_detection": ev(pack, "siem_alerts.json", "alerts[0]"),
                       "response_start": ev(pack, "analyst_notes.txt", "line 3"),
                       "containment": ev(pack, "analyst_notes.txt", "line 4")}
    return d


# --- ground truth is complete and points at real events --------------------------

@pytest.mark.parametrize("inc", list_incidents())
def test_every_milestone_answer_is_a_timeline_event(inc):
    gt = load_ground_truth(inc)
    p = build_pack(ingest_folder(DATA_DIR / inc))
    located = {(s.file, s.locator) for e in p.timeline.events for s in e.sources}
    assert set(gt.response_milestones) == set(MILESTONES)
    for name, refs in gt.response_milestones.items():
        assert refs, (inc, name)
        for r in refs:
            assert (r.file, r.locator) in located, (inc, name, r)
    assert gt.impact is not None


def test_answer_key_not_in_prompt(pack):
    prompt = SYSTEM_PROMPT + pack.to_prompt()
    assert "response_milestones" not in prompt and "systems_forbidden" not in prompt


# --- good path: code computes the durations --------------------------------------

def test_durations_computed_by_code(pack):
    pm = generate(pack, FakeClient([phase8_draft(pack)]))
    assert pm.validation_log == ["attempt 1: 0 validation problem(s)"]
    d = {x.name: x for x in pm.response.durations}
    # 09:14:xx email -> 09:24:xx impossible-travel alert; exact seconds come from the logs
    m = pm.response.milestones
    assert d["time_to_detect"].seconds == int((m["first_detection"].timestamp - m["attack_start"].timestamp).total_seconds())
    assert d["dwell_time"].seconds == int((m["containment"].timestamp - m["attack_start"].timestamp).total_seconds())
    assert not d["time_to_detect"].approximate          # both endpoints exact log timestamps
    assert d["time_to_respond"].approximate              # analyst note time with inferred date
    assert pm.impact.systems_involved == ["Exchange Online"]
    assert pm.immediate_cause.certainty.value == "confirmed"


def test_markdown_has_phase8_sections(pack):
    md = render_markdown(generate(pack, FakeClient([phase8_draft(pack)])))
    for h in ("## 7. Impact assessment", "## 8. Response analysis", "Immediate cause", "time to detect",
              "approximate", "`j.patel`", "## 13. Validation log"):
        assert h in md, h


def test_null_milestone_gives_partial_durations(pack):
    d = phase8_draft(pack)
    d["milestones"]["response_start"] = None
    pm = generate(pack, FakeClient([d]))
    names = {x.name for x in pm.response.durations}
    assert names == {"time_to_detect", "time_to_contain", "dwell_time"}
    assert "not in evidence" in render_markdown(pm)


@pytest.mark.parametrize("s,expected", [(0, "0s"), (45, "45s"), (600, "10m"), (3725, "1h 2m 5s"),
                                        (90061, "1d 1h 1m"), (-120, "-2m")])
def test_fmt_duration(s, expected):
    assert fmt_duration(s) == expected


# --- mutation checks: each LLM mistake is caught ---------------------------------

@pytest.mark.parametrize("mutate,where,expected", [
    (lambda d: d["milestones"].update(containment="EV999"), "milestones", "not a timeline event"),
    (lambda d: d["milestones"].update(first_detection=d["milestones"]["containment"],
                                      containment=d["milestones"]["first_detection"]), "milestones", "time order"),
    (lambda d: d["impact"]["systems_involved"].append("SAP-PROD-01"), "impact.systems_involved", "does not appear"),
    (lambda d: d["impact"]["accounts_involved"].append("ceo"), "impact.accounts_involved", "does not appear"),
    (lambda d: d["impact"]["accounts_involved"].append("j.pat"), "impact.accounts_involved", "does not appear"),
    (lambda d: d["impact"]["data_affected"].update(citations=[]), "impact.data_affected", "needs at least one"),
    (lambda d: d["immediate_cause"]["citations"][0].update(quote="clicked a link"), "immediate_cause", "not found"),
])
def test_validator_catches_phase8(pack, mutate, where, expected):
    d = phase8_draft(pack)
    mutate(d)
    issues = validate_draft(DraftReport.model_validate(d), pack)
    assert any(i.where == where and expected in i.problem for i in issues), issues


def test_bad_milestones_drop_timing_not_report(pack):
    d = phase8_draft(pack)
    d["milestones"]["containment"] = "EV999"
    pm = generate(pack, FakeClient([d, d]))
    assert pm.response is None
    assert any("response timing not computed" in x for x in pm.validation_log)
    assert pm.root_cause is not None
    assert "Not computed" in render_markdown(pm)


def test_invented_system_dropped_and_logged(pack):
    d = phase8_draft(pack)
    d["impact"]["systems_involved"].append("SAP-PROD-01")
    pm = generate(pack, FakeClient([d, d]))
    assert pm.impact.systems_involved == ["Exchange Online"]
    assert any("SAP-PROD-01" in x for x in pm.validation_log)


def test_unknown_impact_needs_no_citation(pack):
    issues = validate_draft(DraftReport.model_validate(phase8_draft(pack)), pack)
    assert not [i for i in issues if i.where == "impact.business_impact"]


def test_summary_point_can_cite_impact(pack):
    d = phase8_draft(pack)
    d["summary_points"].append({"text": "Mailbox contents were probably exposed.", "based_on": ["impact.data_affected"]})
    assert not validate_draft(DraftReport.model_validate(d), pack)


def test_old_drafts_without_phase8_fields_still_work(pack):
    pm = generate(pack, FakeClient([good_draft(pack)]))
    assert pm.validation_log == ["attempt 1: 0 validation problem(s)"]
    assert pm.immediate_cause is None and pm.impact.systems_involved == []


# --- scoring ---------------------------------------------------------------------

def test_score_perfect_phase8(pack):
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([phase8_draft(pack)])))
    assert s.milestone_accuracy == 1.0 and s.milestone_errors == []
    assert s.systems_recall == 1.0 and s.systems_precision == 1.0
    assert s.accounts_recall == 1.0 and s.scope_forbidden_hits == []


def test_score_catches_wrong_milestone_and_forbidden_account(pack):
    d = phase8_draft(pack)
    d["milestones"]["first_detection"] = ev(pack, "auth_logs.csv", "row 2")  # sign-in, not an alert
    d["impact"]["accounts_involved"].append("a.khan")                       # targeted, not compromised
    d["impact"]["systems_involved"].append("SharePoint")                    # only suspected
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([d])))
    assert s.milestone_accuracy == 0.75
    assert any(e.startswith("first_detection") for e in s.milestone_errors)
    assert sorted(s.scope_forbidden_hits) == ["a.khan", "sharepoint"]
    assert s.accounts_precision == 0.5


def test_score_missing_milestones(pack):
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([good_draft(pack)])))
    assert s.milestone_accuracy == 0.0 and len(s.milestone_errors) == 4
    assert s.systems_recall == 0.0 and s.systems_precision is None


def test_milestone_check_is_order_only_on_chosen(pack):
    from pmgen.schemas import DraftMilestones
    assert check_milestones(DraftMilestones(), pack) == []
