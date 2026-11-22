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


class CorrectiveAction(BaseModel):
    recommendation: str = Field(min_length=5)
    priority: Priority
    reason: str = Field(min_length=10)
    supporting_evidence: list[EvidenceRef] = Field(min_length=1)
    owner_team: str
    timeframe: str
    expected_benefit: str


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
    severity: Severity
    timeline: list[GroundTruthEvent] = Field(min_length=3)
    iocs: dict[EntityType, list[str]]
    attack: list[GroundTruthAttack]
    root_cause: Finding
    contributing_factors: list[Finding]
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
