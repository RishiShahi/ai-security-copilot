from app.models.security_event import SecurityEvent
from app.schemas.investigation import RelatedSecurityEvent


def build_correlation_reasons(
    event: SecurityEvent,
    candidate_event: SecurityEvent,
) -> list[str]:
    """
    Determine why a candidate event is correlated
    with the investigated security event.
    """

    reasons = []

    if (
        event.source_ip
        and event.source_ip == candidate_event.source_ip
    ):
        reasons.append("Same source IP")

    if (
        event.username
        and event.username == candidate_event.username
    ):
        reasons.append("Same username")

    return reasons


def find_related_events(
    event: SecurityEvent,
    candidate_events: list[SecurityEvent],
) -> list[RelatedSecurityEvent]:
    """
    Identify events related to the investigated event
    and return structured correlation results.

    The investigated event itself is excluded and
    duplicate candidate events are ignored.
    """

    related_events = []
    processed_event_ids = set()

    for candidate_event in candidate_events:

        if candidate_event.id == event.id:
            continue

        if candidate_event.id in processed_event_ids:
            continue

        processed_event_ids.add(
            candidate_event.id
        )

        correlation_reasons = build_correlation_reasons(
            event=event,
            candidate_event=candidate_event,
        )

        if not correlation_reasons:
            continue

        related_events.append(
            RelatedSecurityEvent(
                event_id=candidate_event.id,
                timestamp=candidate_event.timestamp,
                event_type=candidate_event.event_type,
                severity=candidate_event.severity,
                source_ip=candidate_event.source_ip,
                username=candidate_event.username,
                correlation_reasons=correlation_reasons,
            )
        )

    return related_events