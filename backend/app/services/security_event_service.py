from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import (
    get_events_by_source_ip,
    get_events_by_username,
    count_recent_events_by_source_ip,
    create_event,
    get_events,
    get_event_by_id,
)
from app.schemas.investigation import (
    SecurityInvestigationResponse,
)
from app.schemas.security_event import (
    SecurityAnalysisResponse,
    SecurityEventCreate,
)
from app.services.event_context_builder import (
    build_event_context,
)
from app.services.investigation_service import (
    build_investigation_response,
)
from app.services.event_correlation_service import (
    find_related_events,
)
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
) -> SecurityAnalysisResponse | None:
    event = get_event_by_id(
        db=db,
        event_id=event_id,
    )

    if event is None:
        return None

    related_events = []
    recent_event_count = 0

    if event.source_ip:
        related_events = get_events_by_source_ip(
            db=db,
            source_ip=event.source_ip,
        )

        recent_event_count = count_recent_events_by_source_ip(
            db=db,
            source_ip=event.source_ip,
            timestamp=event.timestamp,
        )

    context = build_event_context(
        event=event,
        related_events=related_events,
        recent_event_count=recent_event_count,
    )

    return analyze_security_event(
        event=event,
        context=context,
    )


def investigate_security_event_by_id(
    db: Session,
    event_id: int,
) -> SecurityInvestigationResponse | None:
    """
    Build an analyst-oriented investigation for a
    security event using deterministic analysis and
    event correlation.
    """

    event = get_event_by_id(
        db=db,
        event_id=event_id,
    )

    if event is None:
        return None

    analysis = analyze_security_event_by_id(
        db=db,
        event_id=event_id,
    )

    if analysis is None:
        return None

    candidate_events = []

    if event.source_ip:
        candidate_events.extend(
            get_events_by_source_ip(
                db=db,
                source_ip=event.source_ip,
            )
        )

    if event.username:
        candidate_events.extend(
            get_events_by_username(
                db=db,
                username=event.username,
            )
        )

    related_events = find_related_events(
        event=event,
        candidate_events=candidate_events,
    )

    return build_investigation_response(
        event=event,
        analysis=analysis,
        related_events=related_events,
    )