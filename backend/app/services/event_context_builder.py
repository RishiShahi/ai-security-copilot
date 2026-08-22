from app.models.security_event import SecurityEvent
from app.services.event_context import EventContext


def build_event_context(
    event: SecurityEvent,
    related_events: list[SecurityEvent],
    recent_event_count: int,
) -> EventContext:

    failed_login_count = sum(
        1
        for related_event in related_events
        if related_event.event_type.lower() == "failed_login"
    )

    unique_usernames = {
        related_event.username.lower()
        for related_event in related_events
        if related_event.username
    }

    return EventContext(
        event_count=len(related_events),
        recent_event_count=recent_event_count,
        failed_login_count=failed_login_count,
        unique_username_count=len(unique_usernames),
    )