from app.schemas.investigation import (
    PrioritizedSecurityEvent,
    RelatedSecurityEvent,
)

SEVERITY_PRIORITY_IMPACTS = {
    "critical": 70,
    "high": 50,
    "medium": 30,
    "low": 10,
}

CORRELATION_PRIORITY_IMPACT = 10


def determine_priority_level(score: int) -> str:
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    return "low"


def get_correlation_priority_impact(
    correlation_reasons: list[str],
) -> int:
    return len(correlation_reasons) * CORRELATION_PRIORITY_IMPACT

def get_severity_priority_impact(severity: str) -> int:
    return SEVERITY_PRIORITY_IMPACTS.get(
        severity.lower(),
        0,
    )


def calculate_priority_score(
    severity: str,
    correlation_reasons: list[str],
) -> int:
    severity_impact = get_severity_priority_impact(
        severity=severity,
    )

    correlation_impact = get_correlation_priority_impact(
        correlation_reasons=correlation_reasons,
    )

    return severity_impact + correlation_impact


def build_priority_reasons(
    severity: str,
    correlation_reasons: list[str],
) -> list[str]:
    reasons = []

    if severity.lower() in {"critical", "high", "medium", "low"}:
        reasons.append(
            f"{severity.capitalize()} severity"
        )

    if len(correlation_reasons) == 1:
        reasons.append(
            f"Matched {correlation_reasons[0]}"
        )

    elif len(correlation_reasons) > 1:
        reasons.append(
            "Matched "
            + " and ".join(correlation_reasons)
        )

    return reasons


def build_prioritized_event(
    event_id: int,
    severity: str,
    correlation_reasons: list[str],
) -> PrioritizedSecurityEvent:
    priority_score = calculate_priority_score(
        severity=severity,
        correlation_reasons=correlation_reasons,
    )

    priority_level = determine_priority_level(
        score=priority_score,
    )

    priority_reasons = build_priority_reasons(
        severity=severity,
        correlation_reasons=correlation_reasons,
    )

    return PrioritizedSecurityEvent(
        event_id=event_id,
        priority_score=priority_score,
        priority_level=priority_level,
        priority_reasons=priority_reasons,
    )


def prioritize_related_events(
    related_events: list[RelatedSecurityEvent],
) -> list[PrioritizedSecurityEvent]:
    prioritized_events = [
        build_prioritized_event(
            event_id=event.event_id,
            severity=event.severity,
            correlation_reasons=event.correlation_reasons,
        )
        for event in related_events
    ]

    return sorted(
        prioritized_events,
        key=lambda event: event.priority_score,
        reverse=True,
    )