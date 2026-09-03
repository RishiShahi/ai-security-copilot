from datetime import UTC, datetime, timedelta

from app.models.security_event import SecurityEvent
from app.schemas.investigation import RelatedSecurityEvent
from app.services.investigation_timeline_service import (
    build_investigation_timeline,
)


def create_security_event(
    event_id: int,
    timestamp: datetime,
) -> SecurityEvent:
    """
    Create a SecurityEvent instance for timeline tests.
    """

    return SecurityEvent(
        id=event_id,
        timestamp=timestamp,
        source="firewall",
        event_type="failed_login",
        severity="medium",
        source_ip="185.23.45.10",
        username="admin",
        message="Failed login attempt",
        description="A failed login attempt was detected.",
    )


def create_related_event(
    event_id: int,
    timestamp: datetime,
    correlation_reasons: list[str],
) -> RelatedSecurityEvent:
    """
    Create a RelatedSecurityEvent instance for timeline tests.
    """

    return RelatedSecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type="failed_login",
        severity="medium",
        source_ip="185.23.45.10",
        username="admin",
        correlation_reasons=correlation_reasons,
    )


def test_timeline_includes_current_event():
    current_timestamp = datetime.now(UTC)

    event = create_security_event(
        event_id=1,
        timestamp=current_timestamp,
    )

    timeline = build_investigation_timeline(
        event=event,
        related_events=[],
    )

    assert len(timeline) == 1
    assert timeline[0].event_id == event.id
    assert timeline[0].is_current_event is True
    assert timeline[0].correlation_reasons == []


def test_timeline_includes_related_events():
    current_timestamp = datetime.now(UTC)

    event = create_security_event(
        event_id=1,
        timestamp=current_timestamp,
    )

    related_event = create_related_event(
        event_id=2,
        timestamp=current_timestamp - timedelta(minutes=5),
        correlation_reasons=["Same source IP"],
    )

    timeline = build_investigation_timeline(
        event=event,
        related_events=[related_event],
    )

    assert len(timeline) == 2

    related_timeline_event = next(
        timeline_event
        for timeline_event in timeline
        if timeline_event.event_id == related_event.event_id
    )

    assert related_timeline_event.is_current_event is False
    assert related_timeline_event.correlation_reasons == [
        "Same source IP"
    ]


def test_timeline_is_sorted_chronologically():
    current_timestamp = datetime.now(UTC)

    event = create_security_event(
        event_id=1,
        timestamp=current_timestamp,
    )

    older_related_event = create_related_event(
        event_id=2,
        timestamp=current_timestamp - timedelta(minutes=10),
        correlation_reasons=["Same source IP"],
    )

    newer_related_event = create_related_event(
        event_id=3,
        timestamp=current_timestamp + timedelta(minutes=5),
        correlation_reasons=["Same username"],
    )

    timeline = build_investigation_timeline(
        event=event,
        related_events=[
            newer_related_event,
            older_related_event,
        ],
    )

    assert [
        timeline_event.event_id
        for timeline_event in timeline
    ] == [2, 1, 3]


def test_timeline_preserves_multiple_correlation_reasons():
    current_timestamp = datetime.now(UTC)

    event = create_security_event(
        event_id=1,
        timestamp=current_timestamp,
    )

    related_event = create_related_event(
        event_id=2,
        timestamp=current_timestamp - timedelta(minutes=5),
        correlation_reasons=[
            "Same source IP",
            "Same username",
        ],
    )

    timeline = build_investigation_timeline(
        event=event,
        related_events=[related_event],
    )

    assert timeline[0].correlation_reasons == [
        "Same source IP",
        "Same username",
    ]