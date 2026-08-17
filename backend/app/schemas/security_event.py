from datetime import datetime

from pydantic import BaseModel


class SecurityEventCreate(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    source_ip: str | None = None
    username: str | None = None
    message: str