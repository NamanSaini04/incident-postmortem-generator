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
        "summary_points": [
            {"text": "The attacker signed in from 203.0.113.45.", "based_on": ["what_happened[0]"]},
            {"text": "MFA was not enforced for the account.", "based_on": ["root_cause"]},
            {"text": "SharePoint access may have occurred but is not confirmed.", "based_on": ["what_happened[1]"]},
        ],
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
    (lambda d: d["summary_points"][0].update(text="Attacker used evil-c2.example for exfiltration."), "not in the evidence"),
    (lambda d: d["summary_points"][2].update(text="The attacker accessed SharePoint."), "states a possible finding as fact"),
    (lambda d: d["summary_points"][0].update(based_on=[]), "not tied to any finding"),
    (lambda d: d["summary_points"][0].update(based_on=["what_happened[9]"]), "do not exist"),
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
    summaries = [x for x in pm.validation_log if x.startswith("attempt") and "validation problem" in x]
    assert summaries == ["attempt 1: 2 validation problem(s)", "attempt 2: 0 validation problem(s)"]


def test_still_bad_after_retry_drops_claim_and_logs_it(pack):
    bad = good_draft(pack)
    bad["root_cause"]["citations"] = []
    pm = generate(pack, FakeClient([bad, copy.deepcopy(bad)]))
    assert pm.root_cause is None
    assert any("root_cause: DROPPED" in x for x in pm.validation_log)
    assert "_Not determined" in render_markdown(pm)


def test_invented_indicator_is_redacted_from_text(pack):
    bad = good_draft(pack)
    bad["summary_points"][0]["text"] += " Data went to 198.51.100.250."
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


# --- real client request shape (SDK faked; no network) ------------------------------

from types import SimpleNamespace  # noqa: E402

from pmgen.llm import AnthropicClient, LLMOutputError, extract_json, strict_schema  # noqa: E402
from pmgen.postmortem import normalise_enums  # noqa: E402


class _FakeMessages:
    def __init__(self, reply):
        self.reply, self.kwargs = reply, None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self.reply


def _client_with(monkeypatch, reply, mode="prompt"):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    c = AnthropicClient(model="claude-sonnet-5-5", mode=mode)
    fake = _FakeMessages(reply)
    c._client = SimpleNamespace(messages=fake)
    return c, fake


def _reply(text, stop="end_turn"):
    return SimpleNamespace(stop_reason=stop, content=[SimpleNamespace(type="text", text=text)],
                           usage=SimpleNamespace(input_tokens=10, output_tokens=5))


def test_default_request_is_prompt_mode(monkeypatch, pack):
    """Default: schema in the prompt, no constrained decoding, no forced tools.
    (Structured outputs failed on the real API: 'compiled grammar is too large'.)"""
    c, fake = _client_with(monkeypatch, _reply("<json>" + json.dumps(good_draft(pack)) + "</json>"))
    out = c.generate_json("sys", "user", DraftReport.model_json_schema())
    assert out["title"].startswith("Credential")
    assert "tool_choice" not in fake.kwargs and "tools" not in fake.kwargs   # rejected by current models
    assert "output_config" not in fake.kwargs
    msg = fake.kwargs["messages"][0]["content"]
    assert "<json>" in msg and "JSON SCHEMA" in msg and '"root_cause"' in msg


def test_structured_mode_is_opt_in(monkeypatch, pack):
    c, fake = _client_with(monkeypatch, _reply(json.dumps(good_draft(pack))), mode="structured")
    c.generate_json("sys", "user", DraftReport.model_json_schema())
    assert fake.kwargs["output_config"]["format"]["type"] == "json_schema"
    assert "tool_choice" not in fake.kwargs


def test_strict_schema_meets_api_limits():
    s = strict_schema(DraftReport.model_json_schema())
    txt = json.dumps(s)
    assert "$ref" not in txt and "$defs" not in txt

    def objects(n):
        if isinstance(n, dict):
            if n.get("type") == "object" and "properties" in n:
                yield n
            for v in n.values():
                yield from objects(v)
        elif isinstance(n, list):
            for x in n:
                yield from objects(x)

    for o in objects(s):
        assert o["additionalProperties"] is False
        assert set(o["required"]) == set(o["properties"])  # nothing optional


@pytest.mark.parametrize("stop,msg", [("refusal", "declined"), ("max_tokens", "cut off")])
def test_bad_stop_reasons_raise_clear_errors(monkeypatch, stop, msg):
    c, _ = _client_with(monkeypatch, _reply("{}", stop=stop))
    with pytest.raises(LLMError, match=msg):
        c.generate_json("s", "u", DraftReport.model_json_schema())


def test_non_json_reply_raises(monkeypatch):
    c, _ = _client_with(monkeypatch, _reply("not json"))
    with pytest.raises(LLMOutputError, match="no JSON object"):
        c.generate_json("s", "u", DraftReport.model_json_schema())


@pytest.mark.parametrize("text", [
    'Here you go <json>{"a": 1}</json> thanks',
    'Sure:\n```json\n{"a": 1}\n```',
    'blah {"a": 1} blah',
])
def test_extract_json_formats(text):
    assert extract_json(text) == {"a": 1}


def test_broken_json_raises_output_error():
    with pytest.raises(LLMOutputError, match="could not be parsed"):
        extract_json('<json>{"a": 1,,}</json>')


def test_unparseable_reply_is_retried(pack):
    client = FakeClient([LLMOutputError("reply JSON could not be parsed: x"), good_draft(pack)])
    pm = generate(pack, client)
    assert len(client.calls) == 2
    assert "could not be parsed" in client.calls[1][1]
    assert pm.validation_log[0].startswith("attempt 1: reply could not be parsed")
    assert pm.root_cause is not None


def test_unparseable_twice_errors(pack):
    with pytest.raises(LLMError, match="no draft matched"):
        generate(pack, FakeClient([LLMOutputError("bad"), LLMOutputError("bad")]))


def test_enum_case_is_normalised(pack):
    d = good_draft(pack)
    d["category"], d["severity"] = "Credential_Compromise", "sev2"
    d["root_cause"]["certainty"] = "Confirmed"
    pm = generate(pack, FakeClient([d]))
    assert pm.category.value == "credential_compromise" and pm.severity.value == "SEV2"
    assert normalise_enums({"x": [{"priority": "HIGH"}]}) == {"x": [{"priority": "high"}]}


def test_precision_is_undefined_when_nothing_listed(pack):
    d = good_draft(pack)
    d["indicators"] = []
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([d])))
    assert s.indicator_precision is None and s.indicator_recall == 0.0


def test_ground_truth_iocs_are_all_listable():
    """A GT IOC the system can never list (e.g. a cloud bucket) would cap recall unfairly."""
    from pmgen.evidence_pack import INDICATOR_TYPES
    from pmgen.samples import list_incidents
    for inc in list_incidents():
        assert set(load_ground_truth(inc).iocs) <= INDICATOR_TYPES, inc


# --- fixes from the first real-model run (2026-11-23) ------------------------------

def test_record_ids_in_text_become_readable(pack):
    d = good_draft(pack)
    rid_notes = rid(pack, "analyst_notes.txt", "line 10")
    d["open_questions"] = [f"Was SharePoint accessed? ({rid_notes})"]
    pm = generate(pack, FakeClient([d]))
    assert pm.open_questions == ["Was SharePoint accessed? (analyst_notes.txt line 10)"]


def test_unknown_record_id_in_text_is_flagged(pack):
    d = good_draft(pack)
    d["remaining_risks"] = ["See R999"]
    issues = validate_draft(DraftReport.model_validate(d), pack)
    assert any("R999" in i.problem and "does not exist" in i.problem for i in issues)


def test_title_does_not_repeat_incident_id(pack):
    d = good_draft(pack)
    d["title"] = "INC-2026-001: Mailbox takeover"
    md = render_markdown(generate(pack, FakeClient([d])))
    assert md.splitlines()[0] == "# Incident Postmortem: INC-2026-001: Mailbox takeover"


def test_prompt_defines_severity_scale_and_category_rule():
    from pmgen.postmortem import SYSTEM_PROMPT
    for s in ("SEV1 critical", "SEV2 high", "SEV3 medium", "SEV4 low", "from CONFIRMED events",
              "must not say more than your findings"):
        assert s in SYSTEM_PROMPT


def test_severity_distance(pack):
    d = good_draft(pack)
    d["severity"] = "SEV4"
    s = score_report(load_ground_truth(INC), generate(pack, FakeClient([d])))
    assert s.severity_off_by == 2 and not s.severity_correct


# --- Phase 5b: summary points must be tied to findings and hedge non-confirmed ones ----

def test_summary_overclaim_is_dropped_and_logged(pack):
    """The INC-002 run-1 pattern: summary states as fact what the findings only call probable/possible."""
    bad = good_draft(pack)
    bad["summary_points"][2]["text"] = "The attacker accessed SharePoint."
    pm = generate(pack, FakeClient([bad, copy.deepcopy(bad)]))
    assert "SharePoint" not in pm.executive_summary
    assert any("summary_points[2]: DROPPED" in x and "as fact" in x for x in pm.validation_log)


def test_hedged_summary_point_passes(pack):
    pm = generate(pack, FakeClient([good_draft(pack)]))
    assert "may have occurred" in pm.executive_summary


def test_summary_point_dropped_when_its_finding_is_dropped(pack):
    bad = good_draft(pack)
    bad["root_cause"]["citations"] = []          # root cause will be dropped
    pm = generate(pack, FakeClient([bad, copy.deepcopy(bad)]))
    assert "MFA was not enforced" not in pm.executive_summary
    assert any("summary_points[1]: DROPPED" in x for x in pm.validation_log)


def test_acceptable_category_scored_correct():
    from pmgen.schemas import IncidentCategory
    gt = load_ground_truth("INC-2026-006")
    assert IncidentCategory.CREDENTIAL_COMPROMISE in gt.acceptable_categories
    assert load_ground_truth("INC-2026-002").acceptable_categories == []  # strict: run-1 miss stays a miss


def test_earlier_attempt_problems_are_kept_in_log(pack):
    bad = good_draft(pack)
    bad["root_cause"]["citations"][0]["quote"] = "invented quote"
    pm = generate(pack, FakeClient([bad, good_draft(pack)]))
    assert any(x.startswith("attempt 1 problem: root_cause:") and "invented quote" in x for x in pm.validation_log)


def test_quote_from_nested_json_value_is_accepted():
    """Phase 7 run: '"Principal":"*"' from a bucket policy (a JSON string inside a JSON record) was wrongly rejected."""
    from pmgen.schemas import Citation
    from pmgen.validate import check_citation
    p3 = build_pack(ingest_folder(DATA_DIR / "INC-2026-003"))
    rid = p3.by_location[("cloudtrail.json", "Records[1]")]
    assert '\\"Principal\\"' in p3.records[rid].text          # stored escaped
    assert check_citation(Citation(record_id=rid, quote='"Principal":"*"'), p3) is None
    assert check_citation(Citation(record_id=rid, quote='"Principal":"admin"'), p3) is not None
