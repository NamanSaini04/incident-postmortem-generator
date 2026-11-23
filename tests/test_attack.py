"""Phase 7 tests: ATT&CK catalogue, ID validation, answer-key leakage, mapping
validation, rendering and scoring."""
import copy

import pytest

from pmgen.attack import check_id, full_name, load_catalog, lookup, related
from pmgen.evaluate import score_report
from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient, schema_instructions
from pmgen.postmortem import SYSTEM_PROMPT, build_user_prompt, generate, render_markdown
from pmgen.samples import DATA_DIR, list_incidents, load_ground_truth
from pmgen.schemas import DraftReport
from pmgen.validate import validate_draft

INC = "INC-2026-001"


def test_catalog_is_official_and_recorded():
    c = load_catalog()
    assert "MITRE" in c["notice"] and c["source_sha256"] and "2026-07-31" in c["version"]
    active = [t for t, v in c["techniques"].items() if not v["revoked"] and not v["deprecated"]]
    assert len(active) > 600


def test_every_answer_key_id_is_current():
    for inc in list_incidents():
        gt = load_ground_truth(inc)
        for t in [a.technique_id for a in gt.attack] + gt.attack_acceptable + gt.attack_forbidden:
            assert check_id(t) is None, (inc, t)


@pytest.mark.parametrize("tid,msg", [("T159", "format"), ("T9999", "does not exist"), ("T1003.999", "does not exist")])
def test_bad_ids_rejected(tid, msg):
    assert msg in check_id(tid)


def test_revoked_id_rejected():
    revoked = next(t for t, v in load_catalog()["techniques"].items() if v["revoked"])
    assert "revoked or deprecated" in check_id(revoked)


def test_related_is_parent_child_not_siblings():
    assert related("T1566", "T1566.002") and related("T1566.002", "T1566")
    assert not related("T1021.001", "T1021.002")


def test_names_come_from_catalog():
    assert full_name("T1059.001") == "Command and Scripting Interpreter: PowerShell"
    assert lookup("T1486")["tactics"] == ["impact"]


def test_answer_key_ids_never_appear_in_the_prompt():
    """The model must map from its own knowledge; no answer-key ID may leak via prompt or schema."""
    schema = schema_instructions(DraftReport.model_json_schema())
    for inc in list_incidents():
        gt = load_ground_truth(inc)
        prompt = SYSTEM_PROMPT + build_user_prompt(build_pack(ingest_folder(DATA_DIR / inc))) + schema
        for t in [a.technique_id for a in gt.attack] + gt.attack_acceptable + gt.attack_forbidden:
            assert t not in prompt, (inc, t)


# --- validation, building, rendering, scoring ------------------------------------------

@pytest.fixture(scope="module")
def pack():
    return build_pack(ingest_folder(DATA_DIR / INC))


def _draft(pack, attack):
    from tests.test_postmortem import good_draft
    d = good_draft(pack)
    d["attack"] = attack
    return d


def _map(pack, tid, file, loc, quote, certainty="confirmed"):
    rid = pack.by_location[(file, loc)]
    return {"technique_id": tid, "certainty": certainty, "rationale": "observed",
            "citations": [{"record_id": rid, "quote": quote}]}


def _good(pack):
    return [_map(pack, "T1566.002", "proxy_logs.csv", "row 1", "login-micros0ft.test"),
            _map(pack, "T1078.004", "auth_logs.csv", "row 2", "203.0.113.45"),
            _map(pack, "T1114.003", "siem_alerts.json", "alerts[1]", "forwarding rule")]


def test_good_mapping_passes_with_catalog_names(pack):
    pm = generate(pack, FakeClient([_draft(pack, _good(pack))]))
    assert [a.technique_id for a in pm.attack] == ["T1566.002", "T1078.004", "T1114.003"]
    assert pm.attack[2].technique_name == "Email Collection: Email Forwarding Rule"
    assert pm.attack[2].tactic == "collection"


@pytest.mark.parametrize("mutate,expected", [
    (lambda m: m.update(technique_id="T9999"), "does not exist"),
    (lambda m: m.update(certainty="possible"), "only map techniques"),
    (lambda m: m.update(citations=[]), "needs at least one valid citation"),
    (lambda m: m["citations"][0].update(quote="invented"), "not found in"),
])
def test_mapping_errors_caught(pack, mutate, expected):
    att = _good(pack)
    mutate(att[0])
    issues = validate_draft(DraftReport.model_validate(_draft(pack, att)), pack)
    assert any(i.where == "attack[0]" and expected in i.problem for i in issues), issues


def test_duplicate_and_kb_citation_caught(pack):
    att = _good(pack) + [_good(pack)[0]]
    kid = next(iter(pack.kb))
    att[1]["citations"].append({"record_id": kid, "quote": pack.kb[kid].text[:20]})
    issues = validate_draft(DraftReport.model_validate(_draft(pack, att)), pack)
    assert any("listed twice" in i.problem for i in issues)
    assert any("not the knowledge base" in i.problem for i in issues)


def test_invalid_mapping_dropped_after_retry(pack):
    att = _good(pack)
    att[0]["technique_id"] = "T9999"
    d = _draft(pack, att)
    pm = generate(pack, FakeClient([d, copy.deepcopy(d)]))
    assert "T9999" not in [a.technique_id for a in pm.attack]
    assert any(x.startswith("attack[0]: DROPPED") for x in pm.validation_log)


def test_attack_table_rendered(pack):
    md = render_markdown(generate(pack, FakeClient([_draft(pack, _good(pack))])))
    assert "## 5. MITRE ATT&CK mapping" in md and "| collection | Email Collection: Email Forwarding Rule | T1114.003" in md
    assert "registered trademark of The MITRE Corporation" in md


def test_attack_scoring_strict_lenient_forbidden(pack):
    att = [_map(pack, "T1566", "proxy_logs.csv", "row 1", "login-micros0ft.test"),        # parent of required
           _map(pack, "T1078.004", "auth_logs.csv", "row 2", "203.0.113.45"),              # exact
           _map(pack, "T1213", "analyst_notes.txt", "line 10", "SharePoint", "probable")]  # forbidden trap
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([_draft(pack, att)])))
    assert s.attack_recall_strict == pytest.approx(1 / 3)
    assert s.attack_recall_lenient == pytest.approx(2 / 3)
    assert s.attack_precision == pytest.approx(2 / 3)
    assert s.attack_forbidden_hits == ["T1213"]


def test_attack_review_lists_extras_and_misses(tmp_path, pack):
    from pmgen.abtest import attack_review
    att = _good(pack)[:2] + [_map(pack, "T1110", "auth_logs.csv", "row 2", "203.0.113.45", "probable")]
    pm = generate(pack, FakeClient([_draft(pack, att)]))
    (tmp_path / f"{INC}_postmortem.json").write_text(pm.model_dump_json())
    text = attack_review(tmp_path)
    assert "| T1114.003 |" in text                       # missed required technique
    assert "T1110" in text and "forbidden hits 1" in text  # forbidden trap counted
