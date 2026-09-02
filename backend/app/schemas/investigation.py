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


class SecurityInvestigationResponse(BaseModel):
    event_id: int
    summary: str
    risk_score: int
    risk_level: str
    threat_type: str
    evidence: list[InvestigationEvidence]
    related_events: list[RelatedSecurityEvent]
    recommended_actions: list[str]