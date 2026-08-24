from datetime import datetime, UTC

from app.services.event_context import EventContext
from app.models.security_event import SecurityEvent
from app.services.security_analyzer import (
    calculate_risk_score,
    determine_risk_level,
    get_severity_risk_factor,
    get_event_type_risk_factor,
    get_privileged_account_risk_factor,
    get_external_ip_risk_factor,
    get_historical_risk_factor,
    get_recent_activity_risk_factor,
    get_failed_login_risk_factor,
    get_multiple_usernames_risk_factor,
    build_risk_factors,
)
from app.schemas.security_event import RiskFactor

def create_test_event(
    severity="low",
    event_type="unknown",
    username=None,
    source_ip=None,
):
    return SecurityEvent(
        id=1,
        timestamp=datetime.now(UTC),
        source="test",
        event_type=event_type,
        severity=severity,
        source_ip=source_ip,
        username=username,
        message="Test security event",
    )

def create_test_context(
    event_count=0,
    recent_event_count=0,
    failed_login_count=0,
    unique_username_count=0,
):
    return EventContext(
        event_count=event_count,
        recent_event_count=recent_event_count,
        failed_login_count=failed_login_count,
        unique_username_count=unique_username_count,
    )

def test_low_severity_event_has_low_risk():
    event = create_test_event(
        severity="low",
        event_type="unknown",
    )
    context = create_test_context()

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 20

def test_high_severity_failed_login():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    context = create_test_context()

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 80

def test_privileged_user_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        username="admin",
    )

    context = create_test_context()

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 90

def test_external_ip_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        source_ip="185.23.45.10",
    )

    context = create_test_context()

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 85

def test_historical_activity_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    context = create_test_context(
        event_count=4,
    )

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 90

def test_recent_activity_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    context = create_test_context(
        recent_event_count=4,
    )

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 95

def test_risk_score_is_capped_at_100():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        username="admin",
        source_ip="185.23.45.10",
    )

    context = create_test_context(
        event_count=10,
        recent_event_count=10,
    )

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 100

def test_private_ip_does_not_add_external_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        source_ip="192.168.1.20",
    )

    context = create_test_context()

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    score = calculate_risk_score(
        factors=factors,
    )

    assert score == 80


def test_repeated_failed_logins_increase_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    base_context = create_test_context()

    repeated_login_context = create_test_context(
        failed_login_count=6,
    )

    base_factors = build_risk_factors(
        event=event,
        context=base_context,
    )

    repeated_login_factors = build_risk_factors(
        event=event,
        context=repeated_login_context,
    )

    base_score = calculate_risk_score(
        factors=base_factors,
    )

    repeated_login_score = calculate_risk_score(
        factors=repeated_login_factors,
    )

    assert repeated_login_score > base_score


def test_multiple_usernames_increase_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    base_context = create_test_context()

    multiple_users_context = create_test_context(
        unique_username_count=4,
    )

    base_factors = build_risk_factors(
        event=event,
        context=base_context,
    )

    multiple_users_factors = build_risk_factors(
        event=event,
        context=multiple_users_context,
    )

    base_score = calculate_risk_score(
        factors=base_factors,
    )

    multiple_users_score = calculate_risk_score(
        factors=multiple_users_factors,
    )

    assert multiple_users_score > base_score

def test_get_severity_risk_factor():
    event = SecurityEvent(
        severity="high",
        event_type="failed_login",
        source="auth-server",
        message="Failed login attempt",
    )

    factor = get_severity_risk_factor(event)

    assert factor is not None
    assert factor.factor == "high_severity"
    assert factor.impact == 70
    assert factor.description == (
        "The event has a high severity level."
    )


def test_get_event_type_risk_factor():
    event = SecurityEvent(
        severity="medium",
        event_type="brute_force",
        source="auth-server",
        message="Multiple failed login attempts",
    )

    factor = get_event_type_risk_factor(event)

    assert factor is not None
    assert factor.factor == "brute_force"
    assert factor.impact == 15
    assert factor.description == (
        "The event type 'brute_force' contributes "
        "additional risk."
    )

def test_get_privileged_account_risk_factor():
    event = SecurityEvent(
        severity="high",
        event_type="failed_login",
        source="auth-server",
        message="Failed login",
        username="admin",
    )

    factor = get_privileged_account_risk_factor(event)

    assert factor is not None
    assert factor.factor == "privileged_account"
    assert factor.impact == 10

def test_get_privileged_account_risk_factor_for_normal_user():
    event = SecurityEvent(
        severity="high",
        event_type="failed_login",
        source="auth-server",
        message="Failed login",
        username="john",
    )

    factor = get_privileged_account_risk_factor(event)

    assert factor is None

def test_get_external_ip_risk_factor():
    event = SecurityEvent(
        severity="high",
        event_type="failed_login",
        source="auth-server",
        message="Failed login",
        source_ip="185.23.45.10",
    )

    factor = get_external_ip_risk_factor(event)

    assert factor is not None
    assert factor.factor == "external_source"
    assert factor.impact == 5

def test_get_external_ip_risk_factor_for_private_ip():
    event = SecurityEvent(
        severity="high",
        event_type="failed_login",
        source="auth-server",
        message="Failed login",
        source_ip="192.168.1.10",
    )

    factor = get_external_ip_risk_factor(event)

    assert factor is None

def test_get_historical_risk_factor():
    context = EventContext(
        event_count=5,
        recent_event_count=0,
        failed_login_count=0,
        unique_username_count=0,
    )

    factor = get_historical_risk_factor(context)

    assert factor is not None
    assert factor.factor == "historical_activity"
    assert factor.impact == 10


def test_get_recent_activity_risk_factor():
    context = EventContext(
        event_count=0,
        recent_event_count=6,
        failed_login_count=0,
        unique_username_count=0,
    )

    factor = get_recent_activity_risk_factor(context)

    assert factor is not None
    assert factor.factor == "recent_activity"
    assert factor.impact == 20

def test_get_failed_login_risk_factor():
    context = EventContext(
        event_count=0,
        recent_event_count=0,
        failed_login_count=6,
        unique_username_count=0,
    )

    factor = get_failed_login_risk_factor(context)

    assert factor is not None
    assert factor.factor == "failed_login_activity"
    assert factor.impact == 15


def test_get_failed_login_risk_factor_with_low_activity():
    context = EventContext(
        event_count=0,
        recent_event_count=0,
        failed_login_count=1,
        unique_username_count=0,
    )

    factor = get_failed_login_risk_factor(context)

    assert factor is None

def test_get_multiple_usernames_risk_factor():
    context = EventContext(
        event_count=0,
        recent_event_count=0,
        failed_login_count=0,
        unique_username_count=4,
    )

    factor = get_multiple_usernames_risk_factor(context)

    assert factor is not None
    assert factor.factor == "multiple_usernames"
    assert factor.impact == 10

def test_build_risk_factors():
    event = SecurityEvent(
        severity="high",
        event_type="brute_force",
        source="auth-server",
        message="Multiple failed login attempts",
        username="admin",
        source_ip="203.0.113.10",
    )

    context = EventContext(
        event_count=5,
        recent_event_count=6,
        failed_login_count=6,
        unique_username_count=4,
    )

    factors = build_risk_factors(
        event=event,
        context=context,
    )

    factor_names = {
        factor.factor
        for factor in factors
    }

    assert factor_names == {
        "high_severity",
        "brute_force",
        "privileged_account",
        "external_source",
        "historical_activity",
        "recent_activity",
        "failed_login_activity",
        "multiple_usernames",
    }

def test_calculate_risk_score():
    factors = [
        RiskFactor(
            factor="high_severity",
            impact=70,
            description="High severity",
        ),
        RiskFactor(
            factor="brute_force",
            impact=15,
            description="Brute force activity",
        ),
        RiskFactor(
            factor="external_source",
            impact=5,
            description="External source",
        ),
    ]

    score = calculate_risk_score(factors=factors)

    assert score == 90

def test_calculate_risk_score_caps_at_100():
    factors = [
        RiskFactor(
            factor="severity",
            impact=90,
            description="Critical severity",
        ),
        RiskFactor(
            factor="behavior",
            impact=20,
            description="Repeated activity",
        ),
    ]

    score = calculate_risk_score(factors=factors)

    assert score == 100