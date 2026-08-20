from app.models.security_event import SecurityEvent


SEVERITY_SCORES = {
    "low": 20,
    "medium": 40,
    "high": 70,
    "critical": 90,
}


EVENT_RISK_MODIFIERS = {
    "failed_login": 10,
    "brute_force": 15,
    "port_scan": 5,
    "malware_detected": 15,
    "unauthorized_access": 20,
}

PRIVILEGED_USERNAMES = {
    "admin",
    "administrator",
    "root",
}


THREAT_TYPES = {
    "failed_login": "authentication_attack",
    "port_scan": "reconnaissance",
    "malware_detected": "malware",
    "brute_force": "authentication_attack",
    "unauthorized_access": "unauthorized_access",
}


RECOMMENDATIONS = {
    "authentication_attack": (
        "Investigate repeated authentication failures and verify "
        "whether the source IP is suspicious."
    ),
    "reconnaissance": (
        "Investigate the source IP for scanning activity and "
        "check whether multiple systems were targeted."
    ),
    "malware": (
        "Isolate the affected system and investigate the detected "
        "malware activity."
    ),
    "unauthorized_access": (
        "Investigate the affected account and verify whether "
        "the access was authorized."
    ),
    "unknown": (
        "Review the event details and investigate the source "
        "for suspicious activity."
    ),
}


def calculate_risk_score(
    event: SecurityEvent,
    event_count: int,
    recent_event_count: int,
) -> int:
    """
    Calculate risk score using severity, event type,
    contextual signals, and historical activity.
    """

    severity = event.severity.lower()
    event_type = event.event_type.lower()

    base_score = SEVERITY_SCORES.get(
        severity,
        0,
    )

    event_modifier = EVENT_RISK_MODIFIERS.get(
        event_type,
        0,
    )

    contextual_modifier = calculate_contextual_modifier(
        event
    )

    historical_modifier = calculate_historical_modifier(
        event_count
    )

    recent_activity_modifier = calculate_recent_activity_modifier(
        recent_event_count
    )

    risk_score = (
        base_score
        + event_modifier
        + contextual_modifier
        + historical_modifier
        + recent_activity_modifier
    )

    return min(risk_score, 100)


def determine_risk_level(risk_score: int) -> str:
    """
    Convert a numeric risk score into a risk level.
    """

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

def calculate_contextual_modifier(event: SecurityEvent) -> int:
    """
    Calculate additional risk based on event context.
    """

    modifier = 0

    if is_privileged_user(event):
        modifier += 10

    if is_external_ip(event):
        modifier += 5

    return modifier

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

def analyze_security_event(
    event: SecurityEvent,
    event_count: int,
    recent_event_count: int,
) -> dict:
    """
    Perform complete security analysis for an event.
    """

    risk_score = calculate_risk_score(
        event=event,
        event_count=event_count,
        recent_event_count=recent_event_count,
    )

    risk_level = determine_risk_level(
        risk_score
    )

    threat_type = classify_threat(event)

    recommendation = get_recommendation(
        threat_type
    )

    return {
        "event_id": event.id,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "threat_type": threat_type,
        "recommendation": recommendation,
    }