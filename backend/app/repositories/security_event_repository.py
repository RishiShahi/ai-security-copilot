from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent


def create_event(
    db: Session,
    event: SecurityEvent,
) -> SecurityEvent:
    db.add(event)
    db.commit()
    db.refresh(event)

    return event

def get_events(
    db: Session,
) -> list[SecurityEvent]:
    return (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.created_at.desc())
        .all()
    )

def get_event_by_id(
    db: Session,
    event_id: int,
) -> SecurityEvent | None:
    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id)
        .first()
    )