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