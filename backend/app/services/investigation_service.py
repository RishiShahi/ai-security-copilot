from app.models.security_event import SecurityEvent
from app.schemas.investigation import (
    InvestigationEvidence,
    InvestigationFinding,
    PrioritizedSecurityEvent,
    RelatedSecurityEvent,
    SecurityInvestigationResponse,
)
from app.schemas.security_event import (
    SecurityAnalysisResponse,
)
from app.services.investigation_timeline_service import (
    build_investigation_timeline,
)

from app.services.investigation_prioritization_service import (
    prioritize_related_events,
)

def build_investigation_evidence(
    analysis: SecurityAnalysisResponse,
) -> list[InvestigationEvidence]:
    """
    Convert deterministic risk factors into structured
    investigation evidence.
    """
    return [
        InvestigationEvidence(
            category=risk_factor.factor,
            impact=risk_factor.impact,
            description=risk_factor.description,
        )
        for risk_factor in analysis.risk_factors
    ]


def build_investigation_summary(
    analysis: SecurityAnalysisResponse,
    related_events: list[RelatedSecurityEvent],
) -> str:
    """
    Build a deterministic analyst-oriented summary
    from the existing security analysis and correlated
    security events.
    """

    evidence_count = len(
        analysis.risk_factors
    )

    related_event_count = len(
        related_events
    )

    summary = (
        f"The event was classified as {analysis.threat_type} "
        f"with a {analysis.risk_level} risk level and a risk "
        f"score of {analysis.risk_score}. "
        f"The investigation identified {evidence_count} "
        f"risk factor(s) contributing to the assessment and "
        f"{related_event_count} related security event(s)."
    )

    if analysis.risk_level == "critical":
        summary += (
            " Critical-risk activity requires immediate attention."
        )

    elif analysis.risk_level == "high":
        summary += (
            " High-risk activity requires prompt investigation."
        )

    elif related_event_count > 0:
        summary += (
            " Related activity should be reviewed for "
            "potentially correlated behavior."
        )

    return summary


def build_investigation_findings(
    analysis: SecurityAnalysisResponse,
    prioritized_events: list,
) -> list[InvestigationFinding]:
    """
    Build deterministic investigation findings from
    security analysis and event prioritization results.
    """

    findings: list[InvestigationFinding] = []

    if analysis.risk_level == "critical":
        findings.append(
            InvestigationFinding(
                category="risk",
                severity="critical",
                description=(
                    "The investigation contains critical-risk "
                    "security activity requiring immediate attention."
                ),
            )
        )

    elif analysis.risk_level == "high":
        findings.append(
            InvestigationFinding(
                category="risk",
                severity="high",
                description=(
                    "The investigation contains high-risk "
                    "security activity requiring prompt investigation."
                ),
            )
        )

    critical_events = [
        event
        for event in prioritized_events
        if event.priority_level == "critical"
    ]

    high_events = [
        event
        for event in prioritized_events
        if event.priority_level == "high"
    ]

    if critical_events:
        findings.append(
            InvestigationFinding(
                category="priority",
                severity="critical",
                description=(
                    f"{len(critical_events)} critical-priority "
                    "related event(s) were identified."
                ),
            )
        )

    if high_events:
        findings.append(
            InvestigationFinding(
                category="priority",
                severity="high",
                description=(
                    f"{len(high_events)} high-priority "
                    "related event(s) were identified."
                ),
            )
        )

    if len(prioritized_events) >= 3:
        findings.append(
            InvestigationFinding(
                category="correlation",
                severity="medium",
                description=(
                    "Multiple related security events were "
                    "identified, indicating correlated activity."
                ),
            )
        )

    return findings


def build_investigation_response(
    event: SecurityEvent,
    analysis: SecurityAnalysisResponse,
    related_events: list[RelatedSecurityEvent],
) -> SecurityInvestigationResponse:
    """
    Build a structured security investigation response
    from deterministic security analysis results and
    correlated security events.
    """

    evidence = build_investigation_evidence(
        analysis=analysis,
    )

    summary = build_investigation_summary(
        analysis=analysis,
        related_events=related_events,
    )

    timeline = build_investigation_timeline(
        event=event,
        related_events=related_events,
    )

    prioritized_events = prioritize_related_events(
        related_events=related_events,
    )

    findings = build_investigation_findings(
        analysis=analysis,
        prioritized_events=prioritized_events,
    )

    return SecurityInvestigationResponse(
        event_id=analysis.event_id,
        summary=summary,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        threat_type=analysis.threat_type,
        evidence=evidence,
        related_events=related_events,
        timeline=timeline,
        prioritized_events=prioritized_events,
        findings=findings,
        recommended_actions=[
            analysis.recommendation,
        ],
    )