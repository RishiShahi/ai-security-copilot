from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import (
    count_events_by_source_ip,
    count_recent_events_by_source_ip,
    create_event,
    get_events,
    get_event_by_id,
)
from app.schemas.security_event import SecurityEventCreate
from app.services.security_analyzer import analyze_security_event


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

def analyze_security_event_by_id(
    db: Session,
    event_id: int,
) -> dict | None:
    event = get_event_by_id(
        db=db,
        event_id=event_id,
    )

    if event is None:
        return None

    event_count = 0
    recent_event_count = 0

    if event.source_ip:
        event_count = count_events_by_source_ip(
            db=db,
            source_ip=event.source_ip,
        )

        recent_event_count = count_recent_events_by_source_ip(
            db=db,
            source_ip=event.source_ip,
            timestamp=event.timestamp,
        )

    return analyze_security_event(
        event=event,
        event_count=event_count,
        recent_event_count=recent_event_count,
    )