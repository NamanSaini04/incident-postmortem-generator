"""Phase 12: the evaluation suite. Each measure is checked on reports with known flaws."""

import pytest

from pmgen import evalsuite as ev
from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient
from pmgen.postmortem import generate
from pmgen.samples import DATA_DIR, load_ground_truth
from pmgen.schemas import Certainty, Severity

from .test_impact import phase8_draft

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def pack():
    return build_pack(ingest_folder(DATA_DIR / INC))


@pytest.fixture(scope="module")
def good(pack):
    return generate(pack, FakeClient([phase8_draft(pack)]))


def _save(folder, pm):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{pm.incident_id}_postmortem.json").write_text(pm.model_dump_json(), encoding="utf-8")


def test_extraction_recall_counts_every_case():
    found, total, misses = ev.extraction_recall(include_variants=False)
    assert total == sum(len(ev._gt_iocs(load_ground_truth(i))) for i in ("INC-2026-001", "INC-2026-002",
                                                                        "INC-2026-003", "INC-2026-004",
                                                                        "INC-2026-005", "INC-2026-006"))
    assert found == total and misses == []


def test_unsupported_claim_rate_counts_removals(pack):
    d = phase8_draft(pack)
    d["impact"]["systems_involved"].append("SAP-PROD-01")        # not in the evidence -> dropped
    d["indicators"].append("198.51.100.99")                       # not extracted -> dropped
    pm = generate(pack, FakeClient([d, d]))
    assert ev.removed_count(pm) >= 2
    e = ev.evaluate_report("r", pm)
    assert e.removed == ev.removed_count(pm) and e.claims > 0


def test_relevance_proxy_flags_action_tied_to_no_finding(good):
    assert ev.action_relevance(good) == 1.0
    pm = good.model_copy(deep=True)
    extra = pm.corrective_actions[0].model_copy(deep=True)
    extra.supporting_evidence[0].file, extra.supporting_evidence[0].locator = "email_gateway.csv", "row 3"
    pm.corrective_actions.append(extra)                           # cites the vendor newsletter: tied to nothing
    assert ev.action_relevance(pm) == 0.5
    pm.corrective_actions = []
    assert ev.action_relevance(pm) is None


def test_completeness_names_missing_sections(good):
    gt = load_ground_truth(INC)
    score, missing = ev.completeness(good, gt)
    assert missing == ["ATT&CK (if the answer key has techniques)"]   # the fixture maps no techniques
    pm = good.model_copy(deep=True)
    pm.response, pm.detection_gaps = None, []
    _, missing = ev.completeness(pm, gt)
    assert "response timing" in missing and "detection gaps" in missing


def test_consistency_compares_answers_not_correctness(pack, good):
    def with_sev(sev):
        pm = good.model_copy(deep=True)
        pm.severity = sev
        return ev.evaluate_report("r", pm)
    # SEV1 and SEV3 are both wrong (answer key: SEV2) but they are NOT consistent
    assert ev.consistency([with_sev(Severity.SEV1), with_sev(Severity.SEV3)])["severity"] == (0, 1)
    assert ev.consistency([with_sev(Severity.SEV3), with_sev(Severity.SEV3)])["severity"] == (1, 1)
    assert ev.consistency([with_sev(Severity.SEV2)])["severity"] == (0, 0)   # one run: nothing to compare


def test_citation_failures_are_counted(good):
    pm = good.model_copy(deep=True)
    pm.root_cause.evidence[0].excerpt = "MFA was enforced"
    pm.root_cause.certainty = Certainty.CONFIRMED
    e = ev.evaluate_report("r", pm)
    assert e.citations_failed == 1 and e.citations_checked > 1


def test_end_to_end_markdown(pack, good, tmp_path):
    d = phase8_draft(pack)
    d["severity"] = "SEV3"
    _save(tmp_path / "run1", good)
    _save(tmp_path / "run2", generate(pack, FakeClient([d])))
    (tmp_path / "run2" / f"{INC}_postmortem_norag.json").write_text("ignored", encoding="utf-8")
    out = tmp_path / "evaluation.md"
    assert ev.main([str(tmp_path / "run1"), str(tmp_path / "run2"), "--out", str(out)]) == 0
    md = out.read_text()
    for s in ("| 1 | Evidence extraction", "| 7 | Unsupported claim rate", "| 8 | Severity consistency | 0/1",
              "SEV2, SEV3 (**differs**)", "off by 1", "proxy", "synthetic"):
        assert s in md, s


def test_no_runs_is_a_usage_error(tmp_path):
    assert ev.main([str(tmp_path)]) == 2


def test_removed_count_handles_reports_from_before_the_logging_fix(good):
    pm = good.model_copy(deep=True)
    pm.validation_log = ["attempt 1: 1 validation problem(s)",
                         "attempt 1 problem: indicators: 'x' was not extracted from the evidence",
                         "attempt 2: 1 validation problem(s)",
                         "indicators: 'x' was not extracted from the evidence"]       # old style: no DROPPED line
    assert ev.removed_count(pm) == 1
    pm.validation_log += ["indicators: DROPPED 'x', not extracted from the evidence"]  # new style: counted once
    assert ev.removed_count(pm) == 1


def test_stage_the_report_predates_is_not_counted_as_zero(good):
    old = good.model_copy(deep=True)
    old.attack_catalog = ""                                   # made before Phase 7
    old.response, old.immediate_cause = None, None            # made before Phase 8
    old.impact = old.impact.model_copy(update={"systems_involved": [], "accounts_involved": [],
                                               "data_affected": None, "operational_impact": None,
                                               "business_impact": None})
    e = ev.evaluate_report("old", old)
    assert e.score.attack_recall_lenient is None and e.score.milestone_accuracy is None
    assert e.stages == "base" and e.complete == 1.0 and e.missing == []
    new = ev.evaluate_report("new", good)
    assert new.score.attack_recall_lenient == 0.0             # the stage existed and mapped nothing: a real 0
    assert "+ATT&CK" in new.stages and "+impact/timing" in new.stages


def test_first_draft_problems_are_counted(pack):
    d = phase8_draft(pack)
    bad = __import__("copy").deepcopy(d)
    bad["key_event_ids"].append("EV999")
    pm = generate(pack, FakeClient([bad, d]))                  # problem in draft 1, fixed by the retry
    assert ev.first_draft_problems(pm) == 1 and ev.removed_count(pm) == 0
