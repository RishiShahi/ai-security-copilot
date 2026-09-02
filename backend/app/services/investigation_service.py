from app.schemas.investigation import (
    InvestigationEvidence,
    RelatedSecurityEvent,
    SecurityInvestigationResponse,
)
from app.schemas.security_event import (
    SecurityAnalysisResponse,
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

    return (
        f"The event was classified as {analysis.threat_type} "
        f"with a {analysis.risk_level} risk level and a risk "
        f"score of {analysis.risk_score}. "
        f"The investigation identified {evidence_count} "
        f"risk factor(s) contributing to the assessment and "
        f"{related_event_count} related security event(s)."
    )


def build_investigation_response(
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

    return SecurityInvestigationResponse(
        event_id=analysis.event_id,
        summary=summary,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        threat_type=analysis.threat_type,
        evidence=evidence,
        related_events=related_events,
        recommended_actions=[
            analysis.recommendation,
        ],
    )