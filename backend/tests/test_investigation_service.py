from app.schemas.security_event import (
    RiskFactor,
    SecurityAnalysisResponse,
)
from app.services.investigation_service import (
    build_investigation_evidence,
    build_investigation_response,
    build_investigation_summary,
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
    )

    assert analysis.threat_type in summary
    assert analysis.risk_level in summary
    assert str(analysis.risk_score) in summary
    assert "2 risk factor(s)" in summary


def test_build_investigation_response():
    analysis = create_analysis()

    investigation = build_investigation_response(
        analysis=analysis,
    )

    assert investigation.event_id == analysis.event_id
    assert investigation.risk_score == analysis.risk_score
    assert investigation.risk_level == analysis.risk_level
    assert investigation.threat_type == analysis.threat_type

    assert len(investigation.evidence) == 2

    assert (
        investigation.recommended_actions
        == [analysis.recommendation]
    )