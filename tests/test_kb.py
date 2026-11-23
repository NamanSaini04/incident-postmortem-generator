"""Phase 6 tests: knowledge base loading, leak guard, retrieval quality, and how
policy citations are validated and rendered."""
import copy

import pytest

from pmgen.evaluate import score_report
from pmgen.evidence_pack import build_pack
from pmgen.extract import extract_bundle
from pmgen.ingest import ingest_folder
from pmgen.kb import BM25, DEFAULT_K, load_chunks, retrieval_recall, retrieve, tokenize
from pmgen.llm import FakeClient
from pmgen.postmortem import generate, render_markdown
from pmgen.samples import DATA_DIR, list_incidents, load_ground_truth
from pmgen.schemas import DraftReport, EntityType
from pmgen.validate import validate_draft

CHUNKS = load_chunks()


def test_kb_loads_citable_sections():
    assert len(CHUNKS) >= 50
    keys = [c.key for c in CHUNKS]
    assert len(keys) == len(set(keys))
    assert "POL-07#3" in keys and all("#" in k for k in keys)


def test_no_incident_facts_leak_into_kb():
    """If the KB contained incident-specific names/IPs, retrieval could hand the model answers."""
    kb_text = " ".join(c.text + c.title for c in CHUNKS).lower()
    leak_types = {EntityType.IP, EntityType.DOMAIN, EntityType.URL, EntityType.EMAIL, EntityType.SHA256,
                  EntityType.USER, EntityType.HOST, EntityType.CLOUD_RESOURCE}
    for inc in list_incidents():
        for e in extract_bundle(ingest_folder(DATA_DIR / inc)):
            if e.entity_type in leak_types:
                assert e.value.lower() not in kb_text, f"{inc}: {e.value} appears in the knowledge base"


def test_bm25_ranks_the_obvious_section_first():
    assert BM25(CHUNKS).search("MFA exception expiry date owner")[0][0].key == "POL-07#3"
    assert BM25(CHUNKS).search("shadow copy deletion alert paging")[0][0].key == "POL-12#2"


def test_tokenizer_keeps_security_terms():
    assert "iam:*" in tokenize("grants iam:* to the group")
    assert "alert" in tokenize("Alerts")


def test_retrieval_recall_regression():
    """Locks in measured retrieval quality: mean recall@8 = 84.7% when this was written."""
    rs = [retrieval_recall(load_ground_truth(i).expected_kb_sections, retrieve(ingest_folder(DATA_DIR / i), CHUNKS))
          for i in list_incidents()]
    assert DEFAULT_K == 8
    assert sum(rs) / len(rs) >= 0.84, rs


def test_every_expected_section_exists():
    keys = {c.key for c in CHUNKS}
    for inc in list_incidents():
        for s in load_ground_truth(inc).expected_kb_sections:
            assert s in keys, (inc, s)


# --- pack, validation, rendering ---------------------------------------------------

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def pack():
    return build_pack(ingest_folder(DATA_DIR / INC))


def _kid(pack, key):
    return next(k for k, c in pack.kb.items() if c.key == key)


def _draft(pack):
    from tests.test_postmortem import good_draft
    d = good_draft(pack)
    k = _kid(pack, "POL-07#3")
    d["corrective_actions"][0]["citations"].append({"record_id": k, "quote": "expiry date no more than 90 days away"})
    return d


def test_pack_includes_kb_and_can_be_disabled():
    p = build_pack(ingest_folder(DATA_DIR / INC))
    assert list(p.kb)[0] == "K01" and "KNOWLEDGE BASE" in p.to_prompt()
    p2 = build_pack(ingest_folder(DATA_DIR / INC), use_kb=False)
    assert p2.kb == {} and "KNOWLEDGE BASE" not in p2.to_prompt()


def test_valid_policy_citation_is_kept_and_rendered(pack):
    pm = generate(pack, FakeClient([_draft(pack)]))
    refs = pm.corrective_actions[0].policy_refs
    assert [(r.doc_id, r.section) for r in refs] == [("POL-07", "3")]
    md = render_markdown(pm)
    assert "[P1]" in md and "## Policy and playbook references" in md and "POL-07 §3" in md


def test_action_citing_only_policy_is_dropped(pack):
    d = _draft(pack)
    d["corrective_actions"][0]["citations"] = [c for c in d["corrective_actions"][0]["citations"]
                                               if c["record_id"].startswith("K")]
    pm = generate(pack, FakeClient([d, copy.deepcopy(d)]))
    assert pm.corrective_actions == []
    assert any("corrective_actions[0]: DROPPED" in x for x in pm.validation_log)


@pytest.mark.parametrize("mutate,expected", [
    (lambda d, p: d["root_cause"]["citations"].append({"record_id": _kid(p, "POL-07#3"), "quote": "named owner"}),
     "not the knowledge base"),
    (lambda d, p: d["corrective_actions"][0]["citations"][-1].update(quote="MFA is optional"), "not found in"),
    (lambda d, p: d["corrective_actions"][0]["citations"][-1].update(record_id="K99"), "not a knowledge-base section"),
    (lambda d, p: d["open_questions"].append("See K99"), "was not given"),
])
def test_policy_citation_errors_caught(pack, mutate, expected):
    d = _draft(pack)
    mutate(d, pack)
    issues = validate_draft(DraftReport.model_validate(d), pack)
    assert any(expected in i.problem for i in issues), issues


def test_kb_ids_in_text_become_readable(pack):
    d = _draft(pack)
    d["remaining_risks"] = [f"Other exceptions may break {_kid(pack, 'POL-07#3')}."]
    pm = generate(pack, FakeClient([d]))
    assert pm.remaining_risks == ["Other exceptions may break POL-07 §3."]


def test_policy_recall_scored(pack):
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([_draft(pack)])))
    assert s.policy_recall == pytest.approx(1 / 3)   # cited POL-07#3 of 3 expected
    assert s.actions_with_policy == 1.0


def test_ab_summary_from_saved_reports(tmp_path, pack):
    from pmgen.abtest import load_scores, summary
    pm_rag = generate(pack, FakeClient([_draft(pack)]))
    nopack = build_pack(ingest_folder(DATA_DIR / INC), use_kb=False)
    from tests.test_postmortem import good_draft
    pm_norag = generate(nopack, FakeClient([good_draft(nopack)]))
    (tmp_path / f"{INC}_postmortem.json").write_text(pm_rag.model_dump_json())
    (tmp_path / f"{INC}_postmortem_norag.json").write_text(pm_norag.model_dump_json())
    text = summary(load_scores(tmp_path))
    assert f"| {INC} | actions_with_policy | 0% | 100% |" in text
    assert "Incidents compared: 1" in text
    assert "| claims_removed | 0.00 per report | 0.00 per report |" in text   # a count, not a percentage
