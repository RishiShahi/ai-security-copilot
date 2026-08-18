from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import (
    create_event,
    get_events,
    get_event_by_id,
)
from app.schemas.security_event import SecurityEventCreate


def create_security_event(
    db: Session,
    event_data: SecurityEventCreate,
) -> SecurityEvent:
    event = SecurityEvent(
        timestamp=event_data.timestamp,
        source=event_data.source,
        event_type=event_data.event_type,
        severity=event_data.severity,
        source_ip=event_data.source_ip,
        username=event_data.username,
        message=event_data.message,
        description=event_data.description,
    )

    return create_event(db, event)

def get_security_events(
    db: Session,
) -> list[SecurityEvent]:
    return get_events(db)

def get_security_event(
    db: Session,
    event_id: int,
) -> SecurityEvent | None:
    return get_event_by_id(
        db=db,
        event_id=event_id,
    )