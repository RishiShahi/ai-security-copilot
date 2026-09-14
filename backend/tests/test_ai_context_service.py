from datetime import datetime

from app.models.security_event import SecurityEvent
from app.schemas.investigation import (
    InvestigationEvidence,
    InvestigationFinding,
    InvestigationTimelineEvent,
    PrioritizedSecurityEvent,
    RelatedSecurityEvent,
    SecurityInvestigationResponse,
)
from app.schemas.security_event import (
    RiskFactor,
    SecurityAnalysisResponse,
)
from app.services.ai_context_service import (
    build_ai_investigation_context,
    build_ai_investigation_context_by_id,
)


def test_build_ai_investigation_context():
    event = SecurityEvent(
        id=1,
        timestamp=datetime(2026, 9, 10, 10, 0, 0),
        source="firewall",
        event_type="failed_login",
        severity="high",
        source_ip="192.168.1.10",
        username="admin",
        message="Multiple failed login attempts",
        description="Repeated failed login attempts detected.",
    )

    risk_factor = RiskFactor(
        factor="failed_login",
        impact=10,
        description="Multiple failed login attempts detected.",
    )

    analysis = SecurityAnalysisResponse(
        event_id=1,
        risk_score=80,
        risk_level="high",
        threat_type="brute_force",
        risk_factors=[risk_factor],
        recommendation="Investigate the source IP.",
    )

    evidence = InvestigationEvidence(
        category="failed_login",
        impact=10,
        description="Multiple failed login attempts detected.",
    )

    related_event = RelatedSecurityEvent(
        event_id=2,
        timestamp=datetime(2026, 9, 10, 9, 55, 0),
        event_type="failed_login",
        severity="medium",
        source_ip="192.168.1.10",
        username="admin",
        correlation_reasons=["same source IP"],
    )

    timeline_event = InvestigationTimelineEvent(
        event_id=1,
        timestamp=datetime(2026, 9, 10, 10, 0, 0),
        event_type="failed_login",
        severity="high",
        source_ip="192.168.1.10",
        username="admin",
        is_current_event=True,
        correlation_reasons=[],
    )

    prioritized_event = PrioritizedSecurityEvent(
        event_id=2,
        priority_score=40,
        priority_level="medium",
        priority_reasons=["medium severity"],
    )

    finding = InvestigationFinding(
        category="risk",
        severity="high",
        description="High-risk security activity identified.",
        evidence=[evidence],
    )

    investigation = SecurityInvestigationResponse(
        event_id=1,
        summary="High-risk brute-force activity detected.",
        risk_score=80,
        risk_level="high",
        threat_type="brute_force",
        evidence=[evidence],
        related_events=[related_event],
        timeline=[timeline_event],
        prioritized_events=[prioritized_event],
        findings=[finding],
        recommended_actions=["Investigate the source IP."],
    )

    context = build_ai_investigation_context(
        event=event,
        analysis=analysis,
        investigation=investigation,
    )

    assert context.event.event_id == 1
    assert context.event.source == "firewall"
    assert context.event.event_type == "failed_login"
    assert context.event.source_ip == "192.168.1.10"
    assert context.event.username == "admin"

    assert context.risk_assessment.risk_score == 80
    assert context.risk_assessment.risk_level == "high"
    assert context.risk_assessment.threat_type == "brute_force"
    assert context.risk_assessment.risk_factors == [risk_factor]

    assert context.evidence == [evidence]
    assert context.related_events == [related_event]
    assert context.timeline == [timeline_event]
    assert context.prioritized_events == [prioritized_event]
    assert context.findings == [finding]
    assert context.recommended_actions == [
        "Investigate the source IP."
    ]
