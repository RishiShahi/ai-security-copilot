from datetime import UTC, datetime
from app.models.security_event import SecurityEvent

from app.schemas.investigation import (
    PrioritizedSecurityEvent,
    RelatedSecurityEvent,
)

from app.schemas.security_event import (
    RiskFactor,
    SecurityAnalysisResponse,
)
from app.services.investigation_service import (
    build_investigation_evidence,
    build_investigation_findings,
    build_investigation_response,
    build_investigation_summary,
    build_priority_evidence,
    build_correlation_evidence,
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


def test_build_investigation_findings_for_critical_risk():
    analysis = create_analysis()
    analysis.risk_level = "critical"

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=[],
    )

    assert len(findings) == 1

    assert findings[0].category == "risk"
    assert findings[0].severity == "critical"
    assert "critical-risk" in findings[0].description


def test_build_investigation_findings_for_high_risk():
    analysis = create_analysis()
    analysis.risk_level = "high"

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=[],
    )

    assert len(findings) == 1

    assert findings[0].category == "risk"
    assert findings[0].severity == "high"
    assert "high-risk" in findings[0].description


def test_build_investigation_findings_for_critical_event():
    analysis = create_analysis()

    prioritized_events = [
        PrioritizedSecurityEvent(
            event_id=2,
            priority_score=90,
            priority_level="critical",
            priority_reasons=[
                "Critical severity",
                "Strong correlation",
            ],
        ),
    ]

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=prioritized_events,
    )

    assert len(findings) == 1

    assert findings[0].category == "priority"
    assert findings[0].severity == "critical"
    assert "1 critical-priority" in findings[0].description


def test_build_investigation_findings_for_high_priority_events():
    analysis = create_analysis()

    prioritized_events = [
        PrioritizedSecurityEvent(
            event_id=2,
            priority_score=70,
            priority_level="high",
            priority_reasons=[
                "High severity",
            ],
        ),
        PrioritizedSecurityEvent(
            event_id=3,
            priority_score=60,
            priority_level="high",
            priority_reasons=[
                "Strong correlation",
            ],
        ),
    ]

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=prioritized_events,
    )

    assert len(findings) == 1

    assert findings[0].category == "priority"
    assert findings[0].severity == "high"
    assert "2 high-priority" in findings[0].description


def test_build_investigation_findings_for_multiple_related_events():
    analysis = create_analysis()

    prioritized_events = [
        PrioritizedSecurityEvent(
            event_id=2,
            priority_score=20,
            priority_level="low",
            priority_reasons=[
                "Low severity",
            ],
        ),
        PrioritizedSecurityEvent(
            event_id=3,
            priority_score=40,
            priority_level="medium",
            priority_reasons=[
                "Medium severity",
            ],
        ),
        PrioritizedSecurityEvent(
            event_id=4,
            priority_score=60,
            priority_level="high",
            priority_reasons=[
                "High severity",
            ],
        ),
    ]

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=prioritized_events,
    )

    assert len(findings) == 2

    assert findings[0].category == "priority"
    assert findings[0].severity == "high"

    assert findings[1].category == "correlation"
    assert findings[1].severity == "medium"
    assert "Multiple related security events" in findings[1].description


def test_build_investigation_findings_with_no_significant_activity():
    analysis = create_analysis()
    analysis.risk_level = "low"

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=[],
    )

    assert len(findings) == 1

    assert findings[0].category == "activity"
    assert findings[0].severity == "low"
    assert findings[0].description == (
        "No significant security activity was "
        "identified during the investigation."
    )
    assert findings[0].evidence == []


def test_build_priority_evidence():
    prioritized_events = [
        PrioritizedSecurityEvent(
            event_id=2,
            priority_score=90,
            priority_level="critical",
            priority_reasons=[
                "Critical severity",
                "Strong correlation",
            ],
        ),
    ]

    evidence = build_priority_evidence(
        events=prioritized_events,
    )

    assert len(evidence) == 3

    assert evidence[0].category == "priority_score"
    assert evidence[0].impact == 90
    assert evidence[0].description == (
        "Related event 2 received a priority score of 90."
    )

    assert evidence[1].category == "priority_reason"
    assert evidence[1].impact == 0
    assert evidence[1].description == (
        "Related event 2: Critical severity"
    )

    assert evidence[2].category == "priority_reason"
    assert evidence[2].impact == 0
    assert evidence[2].description == (
        "Related event 2: Strong correlation"
    )


def test_build_priority_evidence_with_no_events():
    evidence = build_priority_evidence(
        events=[],
    )

    assert evidence == []


def test_build_correlation_evidence():
    related_events = [
        RelatedSecurityEvent(
            event_id=2,
            timestamp=datetime.now(UTC),
            event_type="failed_login",
            severity="high",
            source_ip="185.23.45.10",
            username="admin",
            correlation_reasons=[
                "Same source IP",
                "Same username",
            ],
        ),
    ]

    evidence = build_correlation_evidence(
        related_events=related_events,
    )

    assert len(evidence) == 2

    assert evidence[0].category == "correlation_reason"
    assert evidence[0].impact == 0
    assert evidence[0].description == (
        "Related event 2: Same source IP"
    )

    assert evidence[1].category == "correlation_reason"
    assert evidence[1].impact == 0
    assert evidence[1].description == (
        "Related event 2: Same username"
    )

def test_build_correlation_evidence_with_no_events():
    evidence = build_correlation_evidence(
        related_events=[],
    )

    assert evidence == []


def test_build_investigation_findings_uses_correct_priority_evidence():

    analysis = create_analysis()
    analysis.risk_level = "low"

    prioritized_events = [
        PrioritizedSecurityEvent(
            event_id=2,
            priority_score=95,
            priority_level="critical",
            priority_reasons=[
                "Critical severity",
            ],
        ),
        PrioritizedSecurityEvent(
            event_id=3,
            priority_score=80,
            priority_level="high",
            priority_reasons=[
                "High severity",
                "Same source IP",
            ],
        ),
    ]

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=prioritized_events,
    )

    assert len(findings) == 2

    critical_finding = findings[0]
    high_finding = findings[1]

    assert critical_finding.category == "priority"
    assert critical_finding.severity == "critical"

    assert high_finding.category == "priority"
    assert high_finding.severity == "high"

    assert critical_finding.evidence[0].category == "priority_score"
    assert critical_finding.evidence[0].impact == 95
    assert critical_finding.evidence[0].description == (
        "Related event 2 received a priority score of 95."
    )

    assert critical_finding.evidence[1].category == "priority_reason"
    assert critical_finding.evidence[1].description == (
        "Related event 2: Critical severity"
    )

    assert high_finding.evidence[0].category == "priority_score"
    assert high_finding.evidence[0].impact == 80
    assert high_finding.evidence[0].description == (
        "Related event 3 received a priority score of 80."
    )

    assert high_finding.evidence[1].category == "priority_reason"
    assert high_finding.evidence[1].description == (
        "Related event 3: High severity"
    )

    assert high_finding.evidence[2].category == "priority_reason"
    assert high_finding.evidence[2].description == (
        "Related event 3: Same source IP"
    )


def test_build_investigation_summary_for_critical_risk():
    analysis = create_analysis()
    analysis.risk_level = "critical"

    summary = build_investigation_summary(
        analysis=analysis,
        related_events=[],
    )

    assert "Critical-risk activity requires immediate attention." in summary


def test_build_investigation_summary_for_high_risk():
    analysis = create_analysis()
    analysis.risk_level = "high"

    summary = build_investigation_summary(
        analysis=analysis,
        related_events=[],
    )

    assert "High-risk activity requires prompt investigation." in summary


def test_build_investigation_summary_with_correlated_activity():
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
    ]

    summary = build_investigation_summary(
        analysis=analysis,
        related_events=related_events,
    )

    assert (
        "Related activity should be reviewed for "
        "potentially correlated behavior."
    ) in summary