from datetime import datetime

from pydantic import BaseModel

from app.schemas.investigation import (
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationTimelineEvent,
    PrioritizedSecurityEvent,
    RelatedSecurityEvent,
)
from app.schemas.security_event import RiskFactor


class AIInvestigationEvent(BaseModel):
    event_id: int
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    source_ip: str | None
    username: str | None
    message: str
    description: str | None


class AIRiskAssessment(BaseModel):
    risk_score: int
    risk_level: str
    threat_type: str
    risk_factors: list[RiskFactor]


class AIInvestigationContext(BaseModel):
    event: AIInvestigationEvent
    risk_assessment: AIRiskAssessment
    evidence: list[InvestigationEvidence]
    related_events: list[RelatedSecurityEvent]
    timeline: list[InvestigationTimelineEvent]
    prioritized_events: list[PrioritizedSecurityEvent]
    findings: list[InvestigationFinding]
    recommended_actions: list[str]