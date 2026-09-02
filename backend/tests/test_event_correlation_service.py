from datetime import UTC, datetime

from app.models.security_event import SecurityEvent
from app.services.event_correlation_service import (
    find_related_events,
)


def create_event(
    event_id: int,
    source_ip: str | None = None,
    username: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        id=event_id,
        timestamp=datetime.now(UTC),
        source="firewall",
        event_type="failed_login",
        severity="medium",
        source_ip=source_ip,
        username=username,
        message="Test security event",
        description="Test description",
    )


def test_find_related_events_with_same_source_ip():
    event = create_event(
        event_id=1,
        source_ip="185.23.45.10",
        username="admin",
    )

    candidate_event = create_event(
        event_id=2,
        source_ip="185.23.45.10",
        username="different-user",
    )

    related_events = find_related_events(
        event=event,
        candidate_events=[candidate_event],
    )

    assert len(related_events) == 1
    assert related_events[0].event_id == 2
    assert related_events[0].correlation_reasons == [
        "Same source IP",
    ]


def test_find_related_events_with_same_username():
    event = create_event(
        event_id=1,
        source_ip="185.23.45.10",
        username="admin",
    )

    candidate_event = create_event(
        event_id=2,
        source_ip="10.0.0.5",
        username="admin",
    )

    related_events = find_related_events(
        event=event,
        candidate_events=[candidate_event],
    )

    assert len(related_events) == 1
    assert related_events[0].event_id == 2
    assert related_events[0].correlation_reasons == [
        "Same username",
    ]


def test_find_related_events_with_same_source_ip_and_username():
    event = create_event(
        event_id=1,
        source_ip="185.23.45.10",
        username="admin",
    )

    candidate_event = create_event(
        event_id=2,
        source_ip="185.23.45.10",
        username="admin",
    )

    related_events = find_related_events(
        event=event,
        candidate_events=[candidate_event],
    )

    assert len(related_events) == 1

    assert related_events[0].correlation_reasons == [
        "Same source IP",
        "Same username",
    ]


def test_find_related_events_with_no_correlation():
    event = create_event(
        event_id=1,
        source_ip="185.23.45.10",
        username="admin",
    )

    candidate_event = create_event(
        event_id=2,
        source_ip="10.0.0.5",
        username="guest",
    )

    related_events = find_related_events(
        event=event,
        candidate_events=[candidate_event],
    )

    assert related_events == []


def test_find_related_events_excludes_current_event():
    event = create_event(
        event_id=1,
        source_ip="185.23.45.10",
        username="admin",
    )

    related_events = find_related_events(
        event=event,
        candidate_events=[event],
    )

    assert related_events == []


def test_find_related_events_excludes_duplicate_candidates():
    event = create_event(
        event_id=1,
        source_ip="185.23.45.10",
        username="admin",
    )

    candidate_event = create_event(
        event_id=2,
        source_ip="185.23.45.10",
        username="admin",
    )

    related_events = find_related_events(
        event=event,
        candidate_events=[
            candidate_event,
            candidate_event,
        ],
    )

    assert len(related_events) == 1
    assert related_events[0].event_id == 2
    