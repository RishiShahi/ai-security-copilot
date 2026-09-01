from app.schemas.investigation import (
    InvestigationEvidence,
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
) -> str:
    """
    Build a deterministic analyst-oriented summary
    from the existing security analysis.
    """

    evidence_count = len(
        analysis.risk_factors
    )

    return (
        f"The event was classified as {analysis.threat_type} "
        f"with a {analysis.risk_level} risk level and a risk "
        f"score of {analysis.risk_score}. "
        f"The investigation identified {evidence_count} "
        f"risk factor(s) contributing to the assessment."
    )


def build_investigation_response(
    analysis: SecurityAnalysisResponse,
) -> SecurityInvestigationResponse:
    """
    Build a structured security investigation response
    from deterministic security analysis results.
    """

    evidence = build_investigation_evidence(
        analysis=analysis,
    )

    summary = build_investigation_summary(
        analysis=analysis,
    )

    return SecurityInvestigationResponse(
        event_id=analysis.event_id,
        summary=summary,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        threat_type=analysis.threat_type,
        evidence=evidence,
        recommended_actions=[
            analysis.recommendation,
        ],
    )