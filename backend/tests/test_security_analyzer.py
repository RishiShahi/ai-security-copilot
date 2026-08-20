from datetime import datetime, UTC

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

def test_low_severity_event_has_low_risk():
    event = create_test_event(
        severity="low",
        event_type="unknown",
    )

    score = calculate_risk_score(
        event=event,
        event_count=1,
        recent_event_count=1,
    )

    assert score == 20

def test_high_severity_failed_login():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    score = calculate_risk_score(
        event=event,
        event_count=1,
        recent_event_count=1,
    )

    assert score == 80

def test_privileged_user_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        username="admin",
    )

    score = calculate_risk_score(
        event=event,
        event_count=1,
        recent_event_count=1,
    )

    assert score == 90

def test_external_ip_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        source_ip="185.23.45.10",
    )

    score = calculate_risk_score(
        event=event,
        event_count=1,
        recent_event_count=1,
    )

    assert score == 85

def test_historical_activity_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    score = calculate_risk_score(
        event=event,
        event_count=4,
        recent_event_count=1,
    )

    assert score == 90

def test_recent_activity_increases_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
    )

    score = calculate_risk_score(
        event=event,
        event_count=1,
        recent_event_count=4,
    )

    assert score == 95

def test_risk_score_is_capped_at_100():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        username="admin",
        source_ip="185.23.45.10",
    )

    score = calculate_risk_score(
        event=event,
        event_count=10,
        recent_event_count=10,
    )

    assert score == 100

def test_private_ip_does_not_add_external_risk():
    event = create_test_event(
        severity="high",
        event_type="failed_login",
        source_ip="192.168.1.20",
    )

    score = calculate_risk_score(
        event=event,
        event_count=1,
        recent_event_count=1,
    )

    assert score == 80