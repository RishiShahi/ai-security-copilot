from pydantic import BaseModel


class InvestigationEvidence(BaseModel):
    category: str
    impact: int
    description: str


class SecurityInvestigationResponse(BaseModel):
    event_id: int
    summary: str
    risk_score: int
    risk_level: str
    threat_type: str
    evidence: list[InvestigationEvidence]
    recommended_actions: list[str]