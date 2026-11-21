"""The schema validators enforce the project's safety rules. Test each rule."""
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from pmgen.schemas import (
    AttackMapping,
    Certainty,
    CorrectiveAction,
    EventStatus,
    EvidenceRef,
    Finding,
    Priority,
    TimelineEvent,
)

REF = EvidenceRef(file="auth_logs.csv", locator="row 2", excerpt="203.0.113.45")
UTC_TS = datetime(2026, 10, 6, 9, 22, 15, tzinfo=timezone.utc)


def test_confirmed_event_requires_source():
    with pytest.raises(ValidationError, match="must cite at least one evidence source"):
        TimelineEvent(timestamp=UTC_TS, description="Attacker login", status=EventStatus.CONFIRMED, confidence=0.9)


def test_confirmed_event_with_source_is_valid():
    ev = TimelineEvent(timestamp=UTC_TS, description="Attacker login", status=EventStatus.CONFIRMED,
                       confidence=0.9, sources=[REF])
    assert ev.sources[0].locator == "row 2"


def test_naive_timestamp_rejected():
    with pytest.raises(ValidationError, match="timezone"):
        TimelineEvent(timestamp=datetime(2026, 10, 6, 9, 22), description="Login",
                      status=EventStatus.CONFIRMED, confidence=0.9, sources=[REF])


def test_inferred_event_requires_rationale():
    with pytest.raises(ValidationError, match="rationale"):
        TimelineEvent(timestamp=None, description="Credentials stolen via phishing page",
                      status=EventStatus.INFERRED, confidence=0.7)


def test_unknown_event_cannot_be_high_confidence():
    with pytest.raises(ValidationError, match="above 0.5"):
        TimelineEvent(timestamp=None, description="SharePoint accessed", status=EventStatus.UNKNOWN, confidence=0.8)


@pytest.mark.parametrize("bad_id", ["T156", "1566", "T1566.1", "t1566", "T1566.0001"])
def test_bad_attack_ids_rejected(bad_id):
    with pytest.raises(ValidationError, match="invalid ATT&CK"):
        AttackMapping(technique_id=bad_id, technique_name="Phishing", tactic="Initial Access",
                      evidence=[REF], confidence=0.8)


def test_attack_mapping_requires_evidence():
    with pytest.raises(ValidationError):
        AttackMapping(technique_id="T1566.002", technique_name="Spearphishing Link",
                      tactic="Initial Access", evidence=[], confidence=0.8)


@pytest.mark.parametrize("certainty", [Certainty.CONFIRMED, Certainty.PROBABLE])
def test_strong_findings_need_evidence(certainty):
    with pytest.raises(ValidationError, match="must cite evidence"):
        Finding(statement="MFA was not enforced on the account", certainty=certainty)


def test_possible_finding_may_lack_evidence():
    f = Finding(statement="Attacker may have accessed SharePoint", certainty=Certainty.POSSIBLE)
    assert f.evidence == []


def test_corrective_action_requires_evidence():
    with pytest.raises(ValidationError):
        CorrectiveAction(recommendation="Enable MFA", priority=Priority.CRITICAL,
                         reason="Account had no MFA", supporting_evidence=[],
                         owner_team="IAM", timeframe="7 days", expected_benefit="Blocks password-only logins")
