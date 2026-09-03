from datetime import UTC, datetime
from app.models.security_event import SecurityEvent

from app.schemas.investigation import (
    RelatedSecurityEvent,
)

from app.schemas.security_event import (
    RiskFactor,
    SecurityAnalysisResponse,
)
from app.services.investigation_service import (
    build_investigation_evidence,
    build_investigation_response,
    build_investigation_summary,
)

def create_security_event() -> SecurityEvent:
    """
    Create a SecurityEvent instance for investigation tests.
    """

    return SecurityEvent(
        id=1,
        timestamp=datetime.now(UTC),
        source="firewall",
        event_type="failed_login",
        severity="high",
        source_ip="185.23.45.10",
        username="admin",
        message="Failed login attempt",
        description="A failed login attempt was detected.",
    )

def create_analysis(
    risk_factors: list[RiskFactor] | None = None,
) -> SecurityAnalysisResponse:
    """
    Create a reusable deterministic analysis object
    for investigation service tests.
    """

    if risk_factors is None:
        risk_factors = [
            RiskFactor(
                factor="high_severity",
                impact=30,
                description=(
                    "The event has a high severity level, "
                    "indicating significant security impact."
                ),
            ),
            RiskFactor(
                factor="external_source",
                impact=5,
                description=(
                    "The event originated from an external source."
                ),
            ),
        ]

    return SecurityAnalysisResponse(
        event_id=1,
        risk_score=35,
        risk_level="medium",
        threat_type="suspicious_activity",
        risk_factors=risk_factors,
        recommendation="Review the event and investigate the source.",
    )


def test_build_investigation_evidence():
    analysis = create_analysis()

    evidence = build_investigation_evidence(
        analysis=analysis,
    )

    assert len(evidence) == 2

    assert evidence[0].category == "high_severity"
    assert evidence[0].impact == 30

    assert evidence[1].category == "external_source"
    assert evidence[1].impact == 5


def test_build_investigation_summary():
    analysis = create_analysis()

    summary = build_investigation_summary(
        analysis=analysis,
        related_events=[],
    )

    assert analysis.threat_type in summary
    assert analysis.risk_level in summary
    assert str(analysis.risk_score) in summary
    assert "2 risk factor(s)" in summary
    assert "0 related security event(s)" in summary


def test_build_investigation_response():
    event = create_security_event()

    analysis = create_analysis()

    investigation = build_investigation_response(
        event=event,
        analysis=analysis,
        related_events=[],
    )

    assert investigation.event_id == analysis.event_id
    assert investigation.related_events == []
    assert investigation.risk_score == analysis.risk_score
    assert investigation.risk_level == analysis.risk_level
    assert investigation.threat_type == analysis.threat_type

    assert len(investigation.evidence) == 2

    assert investigation.timeline[0].event_id == event.id
    assert investigation.timeline[0].is_current_event is True

    assert (
        investigation.recommended_actions
        == [analysis.recommendation]
    )


def test_build_investigation_summary_with_related_events():
    analysis = create_analysis()

    related_events = [
        RelatedSecurityEvent(
            event_id=2,
            timestamp=datetime.now(UTC),
            event_type="failed_login",
            severity="medium",
            source_ip="185.23.45.10",
            username="admin",
            correlation_reasons=[
                "Same source IP",
            ],
        ),
        RelatedSecurityEvent(
            event_id=3,
            timestamp=datetime.now(UTC),
            event_type="failed_login",
            severity="medium",
            source_ip="185.23.45.10",
            username="different-user",
            correlation_reasons=[
                "Same source IP",
            ],
        ),
    ]

    summary = build_investigation_summary(
        analysis=analysis,
        related_events=related_events,
    )

    assert "2 related security event(s)" in summary


def test_build_investigation_response_prioritizes_related_events():
    event = create_security_event()

    analysis = create_analysis()

    related_events = [
        RelatedSecurityEvent(
            event_id=2,
            timestamp=datetime.now(UTC),
            event_type="failed_login",
            severity="low",
            source_ip="185.23.45.10",
            username="admin",
            correlation_reasons=[
                "Same source IP",
            ],
        ),
        RelatedSecurityEvent(
            event_id=3,
            timestamp=datetime.now(UTC),
            event_type="privilege_escalation",
            severity="critical",
            source_ip="185.23.45.10",
            username="admin",
            correlation_reasons=[
                "Same source IP",
                "Same username",
            ],
        ),
        RelatedSecurityEvent(
            event_id=4,
            timestamp=datetime.now(UTC),
            event_type="failed_login",
            severity="medium",
            source_ip="185.23.45.10",
            username="admin",
            correlation_reasons=[
                "Same username",
            ],
        ),
    ]

    investigation = build_investigation_response(
        event=event,
        analysis=analysis,
        related_events=related_events,
    )

    assert [
        prioritized_event.event_id
        for prioritized_event in investigation.prioritized_events
    ] == [
        3,
        4,
        2,
    ]

    assert [
        prioritized_event.priority_score
        for prioritized_event in investigation.prioritized_events
    ] == [
        90,
        40,
        20,
    ]

    assert [
        prioritized_event.priority_level
        for prioritized_event in investigation.prioritized_events
    ] == [
        "critical",
        "medium",
        "low",
    ]