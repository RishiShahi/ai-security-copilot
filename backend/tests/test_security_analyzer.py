from datetime import datetime, UTC

from app.services.event_context import EventContext
from app.models.security_event import SecurityEvent
from app.services.security_analyzer import (
    calculate_risk_score,
)

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
    event_count=1,
    recent_event_count=1,
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

    score = calculate_risk_score(
        event=event,
        context=context,
    )

    assert score == 20

def test_high_severity_failed_login():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    context = create_test_context()

    score = calculate_risk_score(
        event=event,
        context=context,
    )

    assert score == 80

def test_privileged_user_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        username="admin",
    )

    context = create_test_context()

    score = calculate_risk_score(
        event=event,
        context=context,
    )

    assert score == 90

def test_external_ip_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        source_ip="185.23.45.10",
    )

    context = create_test_context()

    score = calculate_risk_score(
        event=event,
        context=context,
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

    score = calculate_risk_score(
        event=event,
        context=context,
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

    score = calculate_risk_score(
        event=event,
        context=context,
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

    score = calculate_risk_score(
        event=event,
        context=context,
    )

    assert score == 100

def test_private_ip_does_not_add_external_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        source_ip="192.168.1.20",
    )

    context = create_test_context()

    score = calculate_risk_score(
        event=event,
        context=context,
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

    base_score = calculate_risk_score(
        event=event,
        context=base_context,
    )

    repeated_login_score = calculate_risk_score(
        event=event,
        context=repeated_login_context,
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

    base_score = calculate_risk_score(
        event=event,
        context=base_context,
    )

    multiple_users_score = calculate_risk_score(
        event=event,
        context=multiple_users_context,
    )

    assert multiple_users_score > base_score