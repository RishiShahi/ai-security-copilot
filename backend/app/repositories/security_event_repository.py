from sqlalchemy.orm import Session
from datetime import datetime, timedelta

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


def count_recent_events_by_source_ip(
    db: Session,
    source_ip: str,
    timestamp: datetime,
    minutes: int = 10,
) -> int:
    start_time = timestamp - timedelta(minutes=minutes)

    return (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.source_ip == source_ip,
            SecurityEvent.timestamp >= start_time,
            SecurityEvent.timestamp < timestamp,
        )
        .count()
    )

def get_events_by_source_ip(
    db: Session,
    source_ip: str,
) -> list[SecurityEvent]:
    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.source_ip == source_ip)
        .order_by(SecurityEvent.timestamp.desc())
        .all()
    )


def get_events_by_username(
    db: Session,
    username: str,
) -> list[SecurityEvent]:
    return (
        db.query(SecurityEvent)
        .filter(SecurityEvent.username == username)
        .order_by(SecurityEvent.timestamp.desc())
        .all()
    )