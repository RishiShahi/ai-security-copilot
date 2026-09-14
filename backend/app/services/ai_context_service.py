from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent
from app.repositories.security_event_repository import (
    get_event_by_id,
)
from app.schemas.ai_investigation import (
    AIInvestigationContext,
    AIInvestigationEvent,
    AIRiskAssessment,
)
from app.schemas.investigation import (
    SecurityInvestigationResponse,
)
from app.schemas.security_event import (
    SecurityAnalysisResponse,
)
from app.services.security_event_service import (
    analyze_security_event_by_id,
    build_security_investigation,
)


def build_ai_investigation_context(
    event: SecurityEvent,
    analysis: SecurityAnalysisResponse,
    investigation: SecurityInvestigationResponse,
) -> AIInvestigationContext:
    """
    Build a structured AI investigation context
    from deterministic security analysis and
    investigation results.
    """

    ai_event = AIInvestigationEvent(
        event_id=event.id,
        timestamp=event.timestamp,
        source=event.source,
        event_type=event.event_type,
        severity=event.severity,
        source_ip=event.source_ip,
        username=event.username,
        message=event.message,
        description=event.description,
    )

    risk_assessment = AIRiskAssessment(
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        threat_type=analysis.threat_type,
        risk_factors=analysis.risk_factors,
    )

    return AIInvestigationContext(
        event=ai_event,
        risk_assessment=risk_assessment,
        evidence=investigation.evidence,
        related_events=investigation.related_events,
        timeline=investigation.timeline,
        prioritized_events=investigation.prioritized_events,
        findings=investigation.findings,
        recommended_actions=investigation.recommended_actions,
    )


def build_ai_investigation_context_by_id(
    db: Session,
    event_id: int,
) -> AIInvestigationContext | None:
    """
    Build an AI-ready investigation context for a
    security event using deterministic analysis and
    investigation results.
    """

    event = get_event_by_id(
        db=db,
        event_id=event_id,
    )

    if event is None:
        return None

    analysis = analyze_security_event_by_id(
        db=db,
        event_id=event_id,
    )

    if analysis is None:
        return None

    investigation = build_security_investigation(
        db=db,
        event=event,
        analysis=analysis,
    )

    return build_ai_investigation_context(
        event=event,
        analysis=analysis,
        investigation=investigation,
    )