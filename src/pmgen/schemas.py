"""Core data contract for the Incident Postmortem Generator.

Every later phase (extraction, timeline, LLM report, evaluation) reads and
writes these models. The validators encode the project's safety rules, so a
rule like "a confirmed event must cite evidence" is enforced by code, not by
asking the LLM nicely.
"""
from __future__ import annotations

import re
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FileType(str, Enum):
    TXT = "txt"
    CSV = "csv"
    JSON = "json"
    PDF = "pdf"
    DOCX = "docx"


class EntityType(str, Enum):
    TIMESTAMP = "timestamp"
    USER = "user"
    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    FILE_PATH = "file_path"
    PROCESS = "process"
    APPLICATION = "application"
    CLOUD_RESOURCE = "cloud_resource"


class EventStatus(str, Enum):
    CONFIRMED = "confirmed"  # directly stated in evidence
    INFERRED = "inferred"    # reasoned from evidence, not stated
    UNKNOWN = "unknown"      # suspected but no supporting evidence


class TimeBasis(str, Enum):
    EXACT = "exact"                        # full timestamp with timezone in the evidence
    TIMEZONE_ASSUMED = "timezone_assumed"  # date+time in evidence, timezone assumed UTC
    DATE_INFERRED = "date_inferred"        # only HH:MM in evidence; date taken from other evidence


class Certainty(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


class IncidentCategory(str, Enum):
    PHISHING = "phishing"
    MALWARE = "malware"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXPOSURE = "data_exposure"
    NETWORK_INTRUSION = "network_intrusion"
    INSIDER_THREAT = "insider_threat"
    CLOUD_SECURITY = "cloud_security"
    RANSOMWARE = "ransomware"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class Severity(str, Enum):
    SEV1 = "SEV1"  # critical
    SEV2 = "SEV2"  # high
    SEV3 = "SEV3"  # medium
    SEV4 = "SEV4"  # low


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Evidence and provenance
# ---------------------------------------------------------------------------


class EvidenceRef(BaseModel):
    """Points at the exact place a fact came from."""

    file: str = Field(min_length=1)
    locator: str = Field(min_length=1, description="e.g. 'row 4', 'line 12', 'alerts[2]'")
    excerpt: str | None = Field(default=None, max_length=500)


class EvidenceRecord(BaseModel):
    """One citable unit of evidence: a CSV row, a text line, a JSON list item."""

    locator: str = Field(min_length=1)
    text: str
    fields: dict | None = None  # structured fields for CSV/JSON; None for TXT


class EvidenceDocument(BaseModel):
    source_id: str = Field(pattern=r"^E\d{2,}$")
    file_name: str
    file_type: FileType
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)
    encoding: str
    records: list[EvidenceRecord]
    warnings: list[str] = Field(default_factory=list)


class EvidenceBundle(BaseModel):
    incident_id: str
    documents: list[EvidenceDocument]
    skipped: list[str] = Field(default_factory=list, description="files not ingested, with reason")

    def get(self, file_name: str) -> EvidenceDocument:
        for d in self.documents:
            if d.file_name == file_name:
                return d
        raise KeyError(file_name)


class ExtractedEntity(BaseModel):
    """One observable found in one record. `value` is normalised (e.g. UTC
    timestamp); `source.excerpt` is the exact text it came from."""

    entity_type: EntityType
    value: str = Field(min_length=1)
    source: EvidenceRef
    method: str = Field(pattern=r"^(regex|field|known_entity)$")
    attributes: dict[str, str] = Field(default_factory=dict)


def _require_aware(ts: datetime) -> datetime:
    # Naive timestamps make timeline ordering across log sources unreliable.
    if ts.tzinfo is None or ts.utcoffset() is None:
        raise ValueError("timestamp must include a timezone (use UTC 'Z')")
    return ts


# ---------------------------------------------------------------------------
# Analysis outputs
# ---------------------------------------------------------------------------


class TimelineEvent(BaseModel):
    event_id: str = ""
    timestamp: datetime | None
    time_basis: TimeBasis = TimeBasis.EXACT
    description: str = Field(min_length=3)
    status: EventStatus
    confidence: float = Field(ge=0.0, le=1.0)
    sources: list[EvidenceRef] = Field(default_factory=list)
    rationale: str | None = None

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        return _require_aware(v) if v is not None else v

    @model_validator(mode="after")
    def _provenance_rules(self) -> "TimelineEvent":
        if self.status is EventStatus.CONFIRMED:
            if not self.sources:
                raise ValueError("confirmed event must cite at least one evidence source")
            if self.timestamp is None:
                raise ValueError("confirmed event must have a timestamp")
        if self.status is EventStatus.INFERRED and not self.rationale:
            raise ValueError("inferred event must explain its rationale")
        if self.status is EventStatus.UNKNOWN and self.confidence > 0.5:
            raise ValueError("unknown event cannot have confidence above 0.5")
        return self


class UndatedNote(BaseModel):
    text: str
    source: EvidenceRef
    reason: str


class Timeline(BaseModel):
    incident_id: str
    events: list[TimelineEvent]
    undated: list[UndatedNote] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class Classification(BaseModel):
    category: IncidentCategory
    secondary: list[IncidentCategory] = Field(default_factory=list)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    severity_rationale: str = Field(min_length=10)


_ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class AttackMapping(BaseModel):
    technique_id: str
    technique_name: str = Field(min_length=3)
    tactic: str = Field(min_length=3)
    evidence: list[EvidenceRef] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    certainty: Certainty = Certainty.PROBABLE
    rationale: str = ""

    @field_validator("technique_id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ATTACK_ID.match(v):
            raise ValueError(f"invalid ATT&CK technique id: {v!r}")
        return v


class Finding(BaseModel):
    """Used for root cause, contributing factors and detection gaps."""

    statement: str = Field(min_length=10)
    certainty: Certainty
    evidence: list[EvidenceRef] = Field(default_factory=list)

    @model_validator(mode="after")
    def _confirmed_needs_evidence(self) -> "Finding":
        if self.certainty in (Certainty.CONFIRMED, Certainty.PROBABLE) and not self.evidence:
            raise ValueError(f"{self.certainty.value} finding must cite evidence")
        return self


class KBRef(BaseModel):
    """A citation of a company policy/playbook section (knowledge base), never of incident evidence."""

    doc_id: str
    section: str
    title: str
    excerpt: str


class CorrectiveAction(BaseModel):
    recommendation: str = Field(min_length=5)
    priority: Priority
    reason: str = Field(min_length=10)
    supporting_evidence: list[EvidenceRef] = Field(min_length=1)
    owner_team: str
    timeframe: str
    expected_benefit: str
    policy_refs: list[KBRef] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Ground truth for synthetic incidents (used by tests and Phase 12 evaluation)
# ---------------------------------------------------------------------------


class GroundTruthEvent(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9_]+$")
    timestamp: datetime
    description: str
    status: EventStatus
    source: EvidenceRef

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        return _require_aware(v)


class GroundTruthAttack(BaseModel):
    technique_id: str
    technique_name: str

    @field_validator("technique_id")
    @classmethod
    def _valid_id(cls, v: str) -> str:
        if not _ATTACK_ID.match(v):
            raise ValueError(f"invalid ATT&CK technique id: {v!r}")
        return v


class GroundTruth(BaseModel):
    incident_id: str = Field(pattern=r"^INC-\d{4}-\d{3}$")
    title: str
    category: IncidentCategory
    acceptable_categories: list[IncidentCategory] = Field(
        default_factory=list, description="Other categories a reasonable analyst could choose; scored as correct.")
    severity: Severity
    timeline: list[GroundTruthEvent] = Field(min_length=3)
    iocs: dict[EntityType, list[str]]
    attack: list[GroundTruthAttack]
    attack_acceptable: list[str] = Field(
        default_factory=list, description="Defensible extra technique IDs: not required, not penalised.")
    attack_forbidden: list[str] = Field(
        default_factory=list, description="Plausible-sounding but unsupported technique IDs (hallucination traps). "
                                          "A parent ID also forbids its sub-techniques.")
    root_cause: Finding
    contributing_factors: list[Finding]
    expected_kb_sections: list[str] = Field(
        default_factory=list,
        description='Knowledge-base sections a good report should rely on, e.g. "POL-07#3". Written before retrieval was run.')
    must_not_claim: list[str] = Field(
        default_factory=list,
        description="Statements a correct report must NOT present as confirmed (hallucination traps).",
    )

    @model_validator(mode="after")
    def _timeline_sorted(self) -> "GroundTruth":
        ts = [e.timestamp for e in self.timeline]
        if ts != sorted(ts):
            raise ValueError("ground-truth timeline must be in chronological order")
        keys = [e.key for e in self.timeline]
        if len(keys) != len(set(keys)):
            raise ValueError("ground-truth event keys must be unique")
        return self


# ---------------------------------------------------------------------------
# Phase 5: what the LLM must return (validated by code before use)
# ---------------------------------------------------------------------------
# These models are deliberately permissive: a draft that breaks the rules
# must still parse, so the validator can report exactly what is wrong.


class Citation(BaseModel):
    record_id: str = Field(description="ID of an evidence record (R007) or a knowledge-base section (K03)")
    quote: str = Field(description="Exact text copied from that record (3-200 chars) that supports the claim")


class DraftFinding(BaseModel):
    statement: str
    certainty: Certainty
    citations: list[Citation] = Field(default_factory=list)


class DraftLesson(BaseModel):
    area: str = Field(description="One of: people, process, technology, governance")
    lesson: str
    citations: list[Citation] = Field(default_factory=list)


class DraftAction(BaseModel):
    recommendation: str
    priority: Priority
    reason: str
    citations: list[Citation] = Field(default_factory=list)
    owner_team: str
    timeframe: str
    expected_benefit: str


class SummaryPoint(BaseModel):
    text: str
    based_on: list[str] = Field(
        default_factory=list,
        description='Findings this point restates, e.g. "what_happened[2]", "root_cause", "contributing_factors[0]", "detection_gaps[1]"')


class DraftAttack(BaseModel):
    technique_id: str = Field(description="Enterprise ATT&CK technique or sub-technique ID, e.g. T1012")
    certainty: Certainty
    rationale: str = Field(description="One sentence: which observed behaviour this is")
    citations: list[Citation] = Field(default_factory=list)


class DraftReport(BaseModel):
    title: str
    category: IncidentCategory
    severity: Severity
    severity_rationale: str
    classification_confidence: float = Field(ge=0.0, le=1.0)
    summary_points: list[SummaryPoint] = Field(description="Executive summary as 3-7 short points, each tied to findings")
    what_happened: list[DraftFinding]
    key_event_ids: list[str] = Field(default_factory=list, description="Timeline event IDs (EV001...) that matter most")
    indicators: list[str] = Field(default_factory=list, description="Malicious indicators, copied exactly from the observables list")
    attack: list[DraftAttack] = Field(default_factory=list, description="MITRE ATT&CK techniques the evidence shows")
    root_cause: DraftFinding
    contributing_factors: list[DraftFinding] = Field(default_factory=list)
    detection_gaps: list[DraftFinding] = Field(default_factory=list)
    lessons: list[DraftLesson] = Field(default_factory=list)
    corrective_actions: list[DraftAction] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    remaining_risks: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Phase 5: the validated postmortem (only built from claims that passed checks)
# ---------------------------------------------------------------------------


class Lesson(BaseModel):
    area: str = Field(pattern=r"^(people|process|technology|governance)$")
    lesson: str
    evidence: list[EvidenceRef] = Field(min_length=1)
    policy_refs: list[KBRef] = Field(default_factory=list)


class Indicator(BaseModel):
    value: str
    entity_type: EntityType
    first_seen: EvidenceRef


class Postmortem(BaseModel):
    incident_id: str
    title: str
    category: IncidentCategory
    severity: Severity
    severity_rationale: str
    classification_confidence: float
    executive_summary: str
    what_happened: list[Finding]
    key_event_ids: list[str]
    indicators: list[Indicator]
    attack: list[AttackMapping] = Field(default_factory=list)
    attack_catalog: str = ""
    root_cause: Finding | None
    contributing_factors: list[Finding]
    detection_gaps: list[Finding]
    lessons: list[Lesson]
    corrective_actions: list[CorrectiveAction]
    open_questions: list[str]
    remaining_risks: list[str]
    timeline: Timeline
    validation_log: list[str]
    kb_used: list[str] = Field(default_factory=list, description="Knowledge-base sections given to the model")
    model: str
    generated_at: datetime
    file_hashes: dict[str, str]
