from datetime import datetime

from pydantic import BaseModel

class InvestigationEvidence(BaseModel):
    category: str
    impact: int
    description: str

class RelatedSecurityEvent(BaseModel):
    event_id: int
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str | None
    username: str | None
    correlation_reasons: list[str]

class InvestigationTimelineEvent(BaseModel):
    event_id: int
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: str | None
    username: str | None
    is_current_event: bool
    correlation_reasons: list[str]

class PrioritizedSecurityEvent(BaseModel):
    event_id: int
    priority_score: int
    priority_level: str
    priority_reasons: list[str]


class InvestigationFinding(BaseModel):
    category: str
    severity: str
    description: str

class SecurityInvestigationResponse(BaseModel):
    event_id: int
    summary: str
    risk_score: int
    risk_level: str
    threat_type: str
    evidence: list[InvestigationEvidence]
    related_events: list[RelatedSecurityEvent]
    timeline: list[InvestigationTimelineEvent]
    prioritized_events: list[PrioritizedSecurityEvent]
    findings: list[InvestigationFinding]
    recommended_actions: list[str]