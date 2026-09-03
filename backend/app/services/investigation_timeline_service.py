from app.models.security_event import SecurityEvent
from app.schemas.investigation import (
    InvestigationTimelineEvent,
    RelatedSecurityEvent,
    )

def build_investigation_timeline(
    event: SecurityEvent,
    related_events: list[RelatedSecurityEvent],
    ) -> list[InvestigationTimelineEvent]:
    """
    Build a chronological investigation timeline containing
    the current security event and all related security events.
    """

    timeline = [
        InvestigationTimelineEvent(
            event_id=event.id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            severity=event.severity,
            source_ip=event.source_ip,
            username=event.username,
            is_current_event=True,
            correlation_reasons=[],
        )
    ]

    timeline.extend(
        InvestigationTimelineEvent(
            event_id=related_event.event_id,
            timestamp=related_event.timestamp,
            event_type=related_event.event_type,
            severity=related_event.severity,
            source_ip=related_event.source_ip,
            username=related_event.username,
            is_current_event=False,
            correlation_reasons=related_event.correlation_reasons,
        )
        for related_event in related_events
    )

    return sorted(
        timeline,
        key=lambda timeline_event: timeline_event.timestamp,
    )
