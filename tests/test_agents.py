"""Phase 13: reviewer agent and pipeline trace. LLM calls are scripted with FakeClient."""

import pytest

from pmgen import agents as ag
from pmgen.evidence_pack import build_pack
from pmgen.ingest import ingest_folder
from pmgen.llm import FakeClient
from pmgen.postmortem import generate
from pmgen.samples import DATA_DIR

from .test_impact import phase8_draft

INC = "INC-2026-001"


@pytest.fixture(scope="module")
def pm():
    pack = build_pack(ingest_folder(DATA_DIR / INC))
    return generate(pack, FakeClient([phase8_draft(pack)]))


@pytest.fixture
def claims(pm):
    return ag.collect_claims(pm, DATA_DIR / INC)


def reply_for(claims, verdict=lambda c: "supported", skip=()):
    return {"reviews": [{"claim_id": c.claim_id, "verdict": verdict(c), "reason": "test"}
                        for c in claims if c.claim_id not in skip]}


def test_claims_carry_full_cited_record_text(claims):
    rc = next(c for c in claims if c.where == "root_cause")
    assert rc.certainty == "confirmed"
    assert any("MFA was not enforced for j.patel" in text for _, _, text in rc.records)
    # uncited "possible" claims are not sent: there is nothing to check them against
    assert not any(c.where == "what_happened[1]" for c in claims)
    assert not any(c.where == "impact.business_impact" for c in claims)


def test_planted_errors_keep_real_citations(pm, claims):
    planted = ag.plant_errors(claims, pm)
    kinds = {p.planted for p in planted}
    assert {"certainty", "swap"} <= kinds
    real = {(f, loc) for c in claims for f, loc, _ in c.records}
    for p in planted:
        assert {(f, loc) for f, loc, _ in p.records} <= real   # code checks would all pass
    certainty = next(p for p in planted if p.planted == "certainty")
    assert certainty.certainty == "confirmed"


def test_entity_plant_uses_a_name_absent_from_the_records(pm, claims):
    names = ag.incident_names(DATA_DIR / INC)
    assert "j.patel" in names and "198.51.100.7" in names   # the VPN egress IP: a realistic wrong swap
    planted = [p for p in ag.plant_errors(claims, pm, names=names) if p.planted == "entity"]
    assert planted, "no entity swap was planted: this test would check nothing"
    for p in planted:
        text = " ".join(t for _, _, t in p.records).lower()
        orig = next(c for c in claims if c.where + " (planted)" == p.where)
        swapped_in = set(p.statement.lower().split()) - set(orig.statement.lower().split())
        assert swapped_in and not any(w in text for w in swapped_in)


def test_ids_are_shuffled_and_neutral(pm, claims):
    numbered = ag.number(claims + ag.plant_errors(claims, pm))
    assert [c.claim_id for c in numbered] == [f"C{i:02d}" for i in range(1, len(numbered) + 1)]
    assert all("planted" not in ag.review_prompt([c]) for c in numbered)   # the reviewer cannot see which


def test_review_retries_missing_claims_once_then_reports(claims):
    claims = ag.number(claims)
    first = reply_for(claims, skip={claims[0].claim_id})
    first["reviews"].append({"claim_id": "C99", "verdict": "supported", "reason": "x"})
    second = reply_for([claims[0]])
    reviews, problems, _ = ag.run_review(claims, FakeClient([first, second]))
    assert set(reviews) == {c.claim_id for c in claims}
    assert problems == ["review for unknown claim C99 ignored"]
    reviews, problems, _ = ag.run_review(claims, FakeClient([first, first]))
    assert any("not reviewed" in p for p in problems)


def test_bad_verdict_is_a_malformed_reply(claims):
    claims = ag.number(claims)
    bad = reply_for(claims, verdict=lambda c: "looks fine")
    _, problems, _ = ag.run_review(claims, FakeClient([bad, bad]))
    assert any("malformed" in p for p in problems)


def test_score_counts_caught_planted_and_flagged_originals(pm, claims):
    all_claims = ag.number(claims + ag.plant_errors(claims, pm))
    # a reviewer that flags every planted claim and one original
    an_original = next(c for c in all_claims if not c.planted)
    verdict = lambda c: "unsupported" if c.planted or c is an_original else "supported"  # noqa: E731
    reviews, _, _ = ag.run_review(all_claims, FakeClient([reply_for(all_claims, verdict)]))
    s = ag.score_review(all_claims, reviews)
    assert s.caught == s.planted > 0
    assert len(s.flagged_originals) == 1
    # a reviewer that approves everything catches nothing
    reviews, _, _ = ag.run_review(all_claims, FakeClient([reply_for(all_claims)]))
    assert ag.score_review(all_claims, reviews).caught == 0


def test_review_folder_end_to_end(pm, tmp_path):
    src = tmp_path / "run"
    src.mkdir()
    (src / f"{INC}_postmortem.json").write_text(pm.model_dump_json(), encoding="utf-8")
    originals = ag.collect_claims(pm, DATA_DIR / INC)
    expected = ag.number(originals + ag.plant_errors(originals, pm, names=ag.incident_names(DATA_DIR / INC)))
    client = FakeClient([reply_for(expected, lambda c: "unsupported" if c.planted else "supported")])
    md = ag.review_folder(src, client, True, DATA_DIR, tmp_path / "out")
    assert "Planted errors caught: **" in md and "Unmodified claims flagged: **0/" in md
    assert (tmp_path / "out" / f"{INC}_review.json").is_file()


def test_pipeline_trace_names_every_stage(pm):
    pack = build_pack(ingest_folder(DATA_DIR / INC))
    draft = phase8_draft(pack)
    claims = ag.number(ag.collect_claims(generate(pack, FakeClient([draft])), DATA_DIR / INC))
    client = FakeClient([draft, reply_for(claims)])
    out, review, trace = ag.run_pipeline(DATA_DIR / INC, client, client)
    assert [s.stage for s in trace.steps] == ["ingest", "extract", "timeline + KB retrieval", "draft + validate",
                                              "review", "verify"]
    assert [s.kind for s in trace.steps].count("LLM") == 2
    assert trace.steps[-1].detail == "PASS" and review["problems"] == []


def test_cost_estimate_only_for_known_prices():
    t = ag.Trace(model="claude-sonnet-5-5")
    t.steps.append(ag.TraceStep("review", "LLM", 1.0, "", 1_000_000, 100_000))
    assert t.cost() == pytest.approx(3.0)
    assert ag.Trace(model="other").cost() is None


def test_cli_dry_run_needs_no_key(pm, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / f"{INC}_postmortem.json").write_text(pm.model_dump_json(), encoding="utf-8")
    assert ag.main(["review", str(tmp_path), "--plant", "--dry-run"]) == 0
    assert "no API call made" in capsys.readouterr().out


def test_type_of_swaps_like_for_like():
    assert ag.type_of("203.0.113.45") == "ip" and ag.type_of("WS-FIN-022") == "host" and ag.type_of("j.patel") == "account"


def test_swapped_statement_never_keeps_its_own_evidence(pm, claims):
    """Otherwise the 'error' might be true, and a correct 'supported' would be scored as a miss."""
    swaps = [p for p in ag.plant_errors(claims, pm) if p.planted == "swap"]
    assert swaps
    for p in swaps:
        source = next(c for c in claims if c.statement == p.statement and not c.where.endswith("(planted)"))
        assert not ({(f, loc) for f, loc, _ in source.records} & {(f, loc) for f, loc, _ in p.records})


def test_swap_guard_with_claims_that_share_citations(pm):
    shared = [("auth_logs.csv", "row 2", "text")]
    made = [ag.Claim("", f"what_happened[{i}]", "confirmed", f"statement {i}", shared) for i in range(4)]
    assert not [p for p in ag.plant_errors(made, pm, names=[]) if p.planted == "swap"]


def test_understated_is_a_separate_verdict(pm, claims, tmp_path):
    """Over-hedging must be visible as its own verdict, not hidden inside 'overstated'."""
    numbered = ag.number(claims)
    first = numbered[0].claim_id
    reply = reply_for(numbered, lambda c: "understated" if c.claim_id == first else "supported")
    reviews, problems, _ = ag.run_review(numbered, FakeClient([reply]))
    assert problems == [] and reviews[first].verdict == "understated"
    src = tmp_path / "run"
    src.mkdir()
    (src / f"{INC}_postmortem.json").write_text(pm.model_dump_json(), encoding="utf-8")
    md = ag.review_folder(src, FakeClient([reply_for(ag.number(ag.collect_claims(pm, DATA_DIR / INC)),
                                                     lambda c: "understated" if c.claim_id == "C01" else "supported")]),
                          False, DATA_DIR, tmp_path / "out")
    assert "by verdict: understated 1" in md
