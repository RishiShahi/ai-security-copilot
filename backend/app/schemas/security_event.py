from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SecurityEventCreate(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    source_ip: str | None = None
    username: str | None = None
    message: str
    description: str | None = None

class SecurityEventResponse(BaseModel):
    id: int
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    source_ip: str | None = None
    username: str | None = None
    message: str
    description: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class RiskFactor(BaseModel):
    factor: str
    impact: int
    description: str


class SecurityAnalysisResponse(BaseModel):
    event_id: int
    risk_score: int
    risk_level: str
    threat_type: str
    risk_factors: list[RiskFactor]
    recommendation: str