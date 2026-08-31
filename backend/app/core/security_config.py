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


EVENT_RISK_DESCRIPTIONS = {
    "failed_login": (
        "The event represents a failed authentication attempt, "
        "which may indicate an authentication attack."
    ),
    "brute_force": (
        "The event indicates brute-force activity, which may represent "
        "repeated attempts to gain unauthorized access."
    ),
    "port_scan": (
        "The event indicates port-scanning activity, which may represent "
        "reconnaissance against the target system."
    ),
    "malware_detected": (
        "The event indicates detected malware activity, which may "
        "represent a compromise of the affected system."
    ),
    "unauthorized_access": (
        "The event indicates unauthorized access, which may represent "
        "a compromise of the affected account or system."
    ),
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