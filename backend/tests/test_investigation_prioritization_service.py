from datetime import UTC, datetime

from app.schemas.investigation import RelatedSecurityEvent

from app.services.investigation_prioritization_service import (
    build_priority_reasons,
    build_prioritized_event,
    calculate_priority_score,
    determine_priority_level,
    get_correlation_priority_impact,
    get_severity_priority_impact,
    prioritize_related_events,
)


def test_get_severity_priority_impact():
    assert get_severity_priority_impact("critical") == 70
    assert get_severity_priority_impact("high") == 50
    assert get_severity_priority_impact("medium") == 30
    assert get_severity_priority_impact("low") == 10


def test_get_severity_priority_impact_is_case_insensitive():
    assert get_severity_priority_impact("CRITICAL") == 70
    assert get_severity_priority_impact("High") == 50


def test_get_severity_priority_impact_unknown_severity():
    assert get_severity_priority_impact("unknown") == 0


def test_get_correlation_priority_impact():
    assert get_correlation_priority_impact([]) == 0

    assert get_correlation_priority_impact(
        ["Same source IP"],
    ) == 10

    assert get_correlation_priority_impact(
        [
            "Same source IP",
            "Same username",
        ],
    ) == 20


def test_calculate_priority_score():
    assert calculate_priority_score(
        severity="critical",
        correlation_reasons=[
            "Same source IP",
            "Same username",
        ],
    ) == 90

    assert calculate_priority_score(
        severity="high",
        correlation_reasons=[
            "Same source IP",
        ],
    ) == 60

    assert calculate_priority_score(
        severity="medium",
        correlation_reasons=[],
    ) == 30

    assert calculate_priority_score(
        severity="low",
        correlation_reasons=[
            "Same username",
        ],
    ) == 20


def test_determine_priority_level():
    assert determine_priority_level(90) == "critical"
    assert determine_priority_level(80) == "critical"

    assert determine_priority_level(79) == "high"
    assert determine_priority_level(60) == "high"

    assert determine_priority_level(59) == "medium"
    assert determine_priority_level(30) == "medium"

    assert determine_priority_level(29) == "low"
    assert determine_priority_level(0) == "low"


def test_build_priority_reasons():
    assert build_priority_reasons(
        severity="critical",
        correlation_reasons=[
            "Same source IP",
            "Same username",
        ],
    ) == [
        "Critical severity",
        "Matched Same source IP and Same username",
    ]

    assert build_priority_reasons(
        severity="high",
        correlation_reasons=[
            "Same source IP",
        ],
    ) == [
        "High severity",
        "Matched Same source IP",
    ]

    assert build_priority_reasons(
        severity="low",
        correlation_reasons=[],
    ) == [
        "Low severity",
    ]


def test_build_prioritized_event():
    result = build_prioritized_event(
        event_id=12,
        severity="critical",
        correlation_reasons=[
            "Same source IP",
            "Same username",
        ],
    )

    assert result.event_id == 12
    assert result.priority_score == 90
    assert result.priority_level == "critical"
    assert result.priority_reasons == [
        "Critical severity",
        "Matched Same source IP and Same username",
    ]

def test_prioritize_related_events():
    related_events = [
        RelatedSecurityEvent(
            event_id=1,
            timestamp=datetime(2026, 1, 1, 10, 0, tzinfo=UTC),
            event_type="failed_login",
            severity="low",
            source_ip="10.0.0.1",
            username="alice",
            correlation_reasons=[
                "Same source IP",
            ],
        ),
        RelatedSecurityEvent(
            event_id=2,
            timestamp=datetime(2026, 1, 1, 10, 5, tzinfo=UTC),
            event_type="failed_login",
            severity="critical",
            source_ip="10.0.0.1",
            username="alice",
            correlation_reasons=[
                "Same source IP",
                "Same username",
            ],
        ),
        RelatedSecurityEvent(
            event_id=3,
            timestamp=datetime(2026, 1, 1, 10, 10, tzinfo=UTC),
            event_type="privilege_escalation",
            severity="medium",
            source_ip="10.0.0.1",
            username="alice",
            correlation_reasons=[
                "Same username",
            ],
        ),
    ]

    result = prioritize_related_events(
        related_events=related_events,
    )

    assert [event.event_id for event in result] == [
        2,
        3,
        1,
    ]

    assert [event.priority_score for event in result] == [
        90,
        40,
        20,
    ]