from app.core.security_config import (
    EVENT_RISK_DESCRIPTIONS,
    EVENT_RISK_MODIFIERS,
    PRIVILEGED_USERNAMES,
    RECOMMENDATIONS,
    SEVERITY_SCORES,
    THREAT_TYPES,
)
from app.models.security_event import SecurityEvent
from app.services.event_context import EventContext
from app.schemas.security_event import (
    RiskFactor,
    SecurityAnalysisResponse,
)


def is_privileged_user(event: SecurityEvent) -> bool:
    """
    Check whether the event involves a privileged account.
    """

    if not event.username:
        return False

    return event.username.lower() in PRIVILEGED_USERNAMES

def is_external_ip(event: SecurityEvent) -> bool:
    """
    Determine whether the source IP appears to be external.
    """

    if not event.source_ip:
        return False

    private_prefixes = (
        "10.",
        "192.168.",
    )

    if event.source_ip.startswith(private_prefixes):
        return False

    if event.source_ip.startswith("172."):
        parts = event.source_ip.split(".")

        if len(parts) >= 2:
            try:
                second_octet = int(parts[1])

                if 16 <= second_octet <= 31:
                    return False

            except ValueError:
                pass

    return True

def get_severity_risk_factor(
    event: SecurityEvent,
) -> RiskFactor | None:

    severity = event.severity.lower()

    impact = SEVERITY_SCORES.get(
        severity,
        0,
    )

    if impact == 0:
        return None

    return RiskFactor(
        factor=f"{severity}_severity",
        impact=impact,
        description=(
            f"The event has a {severity} severity level, indicating a "
            "significant potential security impact."
        ),
    )


def get_event_type_risk_factor(
    event: SecurityEvent,
) -> RiskFactor | None:
    """
    Create an explainable risk factor for the event type.
    """

    event_type = event.event_type.lower()

    impact = EVENT_RISK_MODIFIERS.get(
        event_type,
        0,
    )

    if impact == 0:
        return None

    return RiskFactor(
        factor=event_type,
        impact=impact,
        description=EVENT_RISK_DESCRIPTIONS.get(
            event_type,
            f"The event type '{event_type}' contributes additional risk.",
        ),
    )


def get_privileged_account_risk_factor(
    event: SecurityEvent,
) -> RiskFactor | None:
    """
    Create an explainable risk factor when the event
    involves a privileged account.
    """

    if not is_privileged_user(event):
        return None

    return RiskFactor(
        factor="privileged_account",
        impact=10,
        description=(
            "The event targets a privileged account, increasing the potential "
            "impact of unauthorized access."
        ),
    )

def get_external_ip_risk_factor(
    event: SecurityEvent,
) -> RiskFactor | None:
    """
    Create an explainable risk factor when the event
    originates from an external IP address.
    """

    if not is_external_ip(event):
        return None

    return RiskFactor(
        factor="external_source",
        impact=5,
        description=(
           "The event originated from an external source, increasing exposure "
           "to internet-based attacks."
        ),
    )


def calculate_historical_modifier(event_count: int) -> int:
    """
    Calculate additional risk based on repeated activity
    from the same source.
    """

    if event_count >= 6:
        return 20

    if event_count >= 4:
        return 10

    if event_count >= 2:
        return 5

    return 0

def calculate_recent_activity_modifier(
    recent_event_count: int,
) -> int:
    """
    Calculate additional risk based on recent activity
    within a short time window.
    """

    if recent_event_count >= 6:
        return 20

    if recent_event_count >= 4:
        return 15

    if recent_event_count >= 2:
        return 5

    return 0


def calculate_failed_login_modifier(
    failed_login_count: int,
) -> int:
    """
    Calculate additional risk based on repeated
    failed-login activity.
    """

    if failed_login_count >= 6:
        return 15

    if failed_login_count >= 4:
        return 10

    if failed_login_count >= 2:
        return 5

    return 0


def calculate_multiple_usernames_modifier(
    unique_username_count: int,
) -> int:
    """
    Calculate additional risk based on activity
    targeting multiple usernames.
    """

    if unique_username_count >= 4:
        return 10

    if unique_username_count >= 2:
        return 5

    return 0


def get_historical_risk_factor(
    context: EventContext,
) -> RiskFactor | None:
    """
    Create an explainable risk factor for repeated
    historical activity from the same source.
    """

    impact = calculate_historical_modifier(
        context.event_count
    )

    if impact == 0:
        return None

    return RiskFactor(
        factor="historical_activity",
        impact=impact,
        description=(
            f"The source has generated {context.event_count} related events, "
            "indicating repeated activity from the same source."
        ),
    )


def get_recent_activity_risk_factor(
    context: EventContext,
) -> RiskFactor | None:
    """
    Create an explainable risk factor for recent
    activity from the same source.
    """

    impact = calculate_recent_activity_modifier(
        context.recent_event_count
    )

    if impact == 0:
        return None

    return RiskFactor(
        factor="recent_activity",
        impact=impact,
        description=(
            f"The source has generated {context.recent_event_count} related "
            "events within the recent activity window, indicating "
            "concentrated activity."
        ),
    )

def get_failed_login_risk_factor(
    context: EventContext,
) -> RiskFactor | None:
    """
    Create an explainable risk factor for repeated
    failed-login activity.
    """

    impact = calculate_failed_login_modifier(
        context.failed_login_count
    )

    if impact == 0:
        return None

    return RiskFactor(
        factor="failed_login_activity",
        impact=impact,
        description=(
            f"The source has generated {context.failed_login_count} "
            "failed-login events, indicating repeated authentication activity."
        ),
    )


def get_multiple_usernames_risk_factor(
    context: EventContext,
) -> RiskFactor | None:
    """
    Create an explainable risk factor when activity
    targets multiple usernames.
    """

    impact = calculate_multiple_usernames_modifier(
        context.unique_username_count
    )

    if impact == 0:
        return None

    return RiskFactor(
        factor="multiple_usernames",
        impact=impact,
        description=(
            f"The source has targeted {context.unique_username_count} unique "
            "usernames, which may indicate account enumeration or "
            "credential attacks."
        ),
    )



def determine_risk_level(risk_score: int) -> str:

    if risk_score <= 25:
        return "low"

    if risk_score <= 50:
        return "medium"

    if risk_score <= 75:
        return "high"

    return "critical"


def classify_threat(event: SecurityEvent) -> str:
    """
    Classify the security event into a known threat category.
    """

    event_type = event.event_type.lower()

    return THREAT_TYPES.get(event_type, "unknown")


def get_recommendation(threat_type: str) -> str:
    """
    Return a security recommendation based on the threat type.
    """

    return RECOMMENDATIONS.get(
        threat_type,
        RECOMMENDATIONS["unknown"],
    )


def calculate_risk_score(
    factors: list[RiskFactor],
) -> int:
    """
    Calculate the final risk score from risk factors.
    """

    risk_score = sum(
        factor.impact
        for factor in factors
    )

    return min(risk_score, 100)


def build_analysis_response(
    event: SecurityEvent,
    risk_factors: list[RiskFactor],
) -> SecurityAnalysisResponse:
    """
    Build the final deterministic security analysis response
    from the calculated risk factors.
    """

    risk_score = calculate_risk_score(
        factors=risk_factors,
    )

    risk_level = determine_risk_level(
        risk_score
    )

    threat_type = classify_threat(event)

    recommendation = get_recommendation(
        threat_type
    )

    return SecurityAnalysisResponse(
        event_id=event.id,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_type=threat_type,
        risk_factors=risk_factors,
        recommendation=recommendation,
    )



def build_risk_factors(
    event: SecurityEvent,
    context: EventContext,
) -> list[RiskFactor]:
    """
    Build all explainable risk factors for a security event.
    """

    possible_factors = [
        get_severity_risk_factor(event),
        get_event_type_risk_factor(event),
        get_privileged_account_risk_factor(event),
        get_external_ip_risk_factor(event),
        get_historical_risk_factor(context),
        get_recent_activity_risk_factor(context),
        get_failed_login_risk_factor(context),
        get_multiple_usernames_risk_factor(context),
    ]

    return [
        factor
        for factor in possible_factors
        if factor is not None
    ]



def analyze_security_event(
    event: SecurityEvent,
    context: EventContext,
) -> SecurityAnalysisResponse:
    """
    Perform complete security analysis for an event.
    """

    risk_factors = build_risk_factors(
        event=event,
        context=context,
    )

    return build_analysis_response(
        event=event,
        risk_factors=risk_factors,
    )