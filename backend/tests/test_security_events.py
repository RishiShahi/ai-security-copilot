from datetime import UTC, datetime, timedelta


def create_test_event(
    source_ip: str | None = "185.23.45.10",
    username: str | None = "admin",
):
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "firewall",
        "event_type": "failed_login",
        "severity": "high",
        "source_ip": source_ip,
        "username": username,
        "message": "Failed login attempt",
        "description": "Authentication failure from external source",
    }


def test_create_security_event(client):
    response = client.post(
        "/api/security/events",
        json=create_test_event(),
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] is not None
    assert data["source"] == "firewall"
    assert data["event_type"] == "failed_login"
    assert data["severity"] == "high"
    assert data["username"] == "admin"


def test_get_security_events(client):
    client.post(
        "/api/security/events",
        json=create_test_event(),
    )

    response = client.get(
        "/api/security/events",
    )

    assert response.status_code == 200

    data = response.json()

    assert len(data) == 1
    assert data[0]["event_type"] == "failed_login"


def test_get_security_event_by_id(client):
    create_response = client.post(
        "/api/security/events",
        json=create_test_event(),
    )

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/security/events/{event_id}",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == event_id
    assert data["event_type"] == "failed_login"


def test_get_nonexistent_security_event(client):
    response = client.get(
        "/api/security/events/9999",
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Security event not found"


def test_analyze_security_event(client):
    create_response = client.post(
        "/api/security/events",
        json=create_test_event(),
    )

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/security/events/{event_id}/analysis",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == event_id
    assert data["risk_score"] == 95
    assert data["risk_level"] == "critical"
    assert data["threat_type"] == "authentication_attack"
    assert "authentication failures" in data["recommendation"]

    assert "risk_factors" in data
    assert isinstance(data["risk_factors"], list)

    factor_names = {
        factor["factor"]
        for factor in data["risk_factors"]
    }

    assert factor_names == {
        "high_severity",
        "failed_login",
        "privileged_account",
        "external_source",
    }

    factor_impacts = {
        factor["factor"]: factor["impact"]
        for factor in data["risk_factors"]
    }

    assert factor_impacts == {
        "high_severity": 70,
        "failed_login": 10,
        "privileged_account": 10,
        "external_source": 5,
    }

def test_analyze_security_event_without_source_ip(client):
    event = create_test_event(source_ip=None)

    create_response = client.post(
        "/api/security/events",
        json=event,
    )

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/security/events/{event_id}/analysis",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == event_id
    assert data["risk_score"] == 90
    assert data["risk_level"] == "critical"
    assert data["threat_type"] == "authentication_attack"

    factor_names = {
        factor["factor"]
        for factor in data["risk_factors"]
    }

    assert factor_names == {
        "high_severity",
        "failed_login",
        "privileged_account",
    }

def test_analyze_nonexistent_security_event(client):
    response = client.get(
        "/api/security/events/9999/analysis",
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Security event not found"


def test_analyze_security_event_with_repeated_activity(client):

    base_time = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=UTC,
    )

    for minutes_ago in [9, 8, 7, 6, 5, 4]:
        event = create_test_event()
        event["timestamp"] = (
            base_time - timedelta(minutes=minutes_ago)
        ).isoformat()

        client.post(
            "/api/security/events",
            json=event,
        )

    current_event = create_test_event()
    current_event["timestamp"] = base_time.isoformat()

    create_response = client.post(
        "/api/security/events",
        json=current_event,
    )

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/security/events/{event_id}/analysis",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == event_id
    assert data["risk_score"] == 100
    assert data["risk_level"] == "critical"

    factor_names = {
        factor["factor"]
        for factor in data["risk_factors"]
    }

    assert "historical_activity" in factor_names
    assert "recent_activity" in factor_names

def test_analyze_security_event_with_multiple_usernames(client):
    base_time = datetime(
        2026,
        8,
        22,
        12,
        0,
        tzinfo=UTC,
    )

    usernames = [
        "admin",
        "john",
        "alice",
        "bob",
    ]

    for index, username in enumerate(usernames):
        event = create_test_event()
        event["username"] = username
        event["timestamp"] = (
            base_time - timedelta(minutes=index + 1)
        ).isoformat()

        client.post(
            "/api/security/events",
            json=event,
        )

    current_event = create_test_event()
    current_event["timestamp"] = base_time.isoformat()

    create_response = client.post(
        "/api/security/events",
        json=current_event,
    )

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/security/events/{event_id}/analysis",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == event_id
    assert data["risk_level"] == "critical"

    factor_names = {
        factor["factor"]
        for factor in data["risk_factors"]
    }

    assert "multiple_usernames" in factor_names


def test_investigate_security_event(client):

    create_response = client.post(
        "/api/security/events",
        json=create_test_event(),
    )

    assert create_response.status_code == 200

    event_id = create_response.json()["id"]

    response = client.get(
        f"/api/security/events/{event_id}/investigation",
    )

    assert response.status_code == 200

    data = response.json()

    assert data["event_id"] == event_id
    assert "summary" in data
    assert "risk_score" in data
    assert "risk_level" in data
    assert "threat_type" in data
    assert "evidence" in data
    assert "recommended_actions" in data

    assert isinstance(
        data["evidence"],
        list,
    )

    assert isinstance(
        data["recommended_actions"],
        list,
    )


def test_investigation_response_contains_timeline(client):
    create_response = client.post(
        "/api/security/events",
        json=create_test_event(),
    )

    assert create_response.status_code == 200

    event_id = create_response.json()["id"]

    investigation_response = client.get(
        f"/api/security/events/{event_id}/investigation",
    )

    assert investigation_response.status_code == 200

    data = investigation_response.json()

    assert "timeline" in data
    assert isinstance(data["timeline"], list)
    assert len(data["timeline"]) == 1

    timeline_event = data["timeline"][0]

    assert timeline_event["event_id"] == event_id
    assert timeline_event["is_current_event"] is True
    assert timeline_event["correlation_reasons"] == []


def test_investigation_timeline_contains_related_events(client):
    first_event = create_test_event(
        source_ip="185.23.45.10",
        username="admin",
    )

    first_event["timestamp"] = datetime(
        2026,
        9,
        3,
        10,
        0,
        tzinfo=UTC,
    ).isoformat()

    first_response = client.post(
        "/api/security/events",
        json=first_event,
    )

    assert first_response.status_code == 200

    second_event = create_test_event(
        source_ip="185.23.45.10",
        username="different-user",
    )

    second_event["timestamp"] = datetime(
        2026,
        9,
        3,
        10,
        10,
        tzinfo=UTC,
    ).isoformat()

    second_response = client.post(
        "/api/security/events",
        json=second_event,
    )

    assert second_response.status_code == 200

    event_id = second_response.json()["id"]
    first_event_id = first_response.json()["id"]

    investigation_response = client.get(
        f"/api/security/events/{event_id}/investigation",
    )

    assert investigation_response.status_code == 200

    data = investigation_response.json()

    assert len(data["timeline"]) == 2

    timeline_event_ids = [
        timeline_event["event_id"]
        for timeline_event in data["timeline"]
    ]

    assert first_event_id in timeline_event_ids
    assert event_id in timeline_event_ids

    related_timeline_event = next(
        timeline_event
        for timeline_event in data["timeline"]
        if timeline_event["event_id"] == first_event_id
    )

    assert related_timeline_event["is_current_event"] is False

    assert related_timeline_event["correlation_reasons"] == [
        "Same source IP",
    ]

def test_investigation_timeline_is_sorted_chronologically(client):
    base_time = datetime(
        2026,
        9,
        3,
        12,
        0,
        tzinfo=UTC,
    )

    older_event = create_test_event(
        source_ip="185.23.45.10",
        username="admin",
    )

    older_event["timestamp"] = (
        base_time - timedelta(minutes=10)
    ).isoformat()

    older_response = client.post(
        "/api/security/events",
        json=older_event,
    )

    assert older_response.status_code == 200

    current_event = create_test_event(
        source_ip="185.23.45.10",
        username="different-user",
    )

    current_event["timestamp"] = base_time.isoformat()

    current_response = client.post(
        "/api/security/events",
        json=current_event,
    )

    assert current_response.status_code == 200

    newer_event = create_test_event(
        source_ip="185.23.45.10",
        username="another-user",
    )

    newer_event["timestamp"] = (
        base_time + timedelta(minutes=10)
    ).isoformat()

    newer_response = client.post(
        "/api/security/events",
        json=newer_event,
    )

    assert newer_response.status_code == 200

    current_event_id = current_response.json()["id"]

    investigation_response = client.get(
        f"/api/security/events/{current_event_id}/investigation",
    )

    assert investigation_response.status_code == 200

    data = investigation_response.json()

    timeline_event_ids = [
        timeline_event["event_id"]
        for timeline_event in data["timeline"]
    ]

    assert timeline_event_ids == [
        older_response.json()["id"],
        current_event_id,
        newer_response.json()["id"],
    ]


def test_investigate_nonexistent_security_event(client):
    response = client.get(
        "/api/security/events/99999/investigation",
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Security event not found",
    }


def test_investigate_security_event_with_related_source_ip(
    client,
):
    first_event = create_test_event(
        source_ip="185.23.45.10",
         username="admin",
    )

    first_response = client.post(
        "/api/security/events",
        json=first_event,
    )

    assert first_response.status_code == 200

    second_event = create_test_event(
        source_ip="185.23.45.10",
        username="different-user",
    )

    second_response = client.post(
        "/api/security/events",
        json=second_event,
    )

    assert second_response.status_code == 200

    event_id = second_response.json()["id"]

    investigation_response = client.get(
        f"/api/security/events/{event_id}/investigation",
    )

    assert investigation_response.status_code == 200

    data = investigation_response.json()

    assert len(data["related_events"]) == 1

    related_event = data["related_events"][0]

    assert related_event["event_id"] == (
        first_response.json()["id"]
    )

    assert related_event["correlation_reasons"] == [
        "Same source IP",
    ]


def test_investigate_security_event_with_related_username(
    client,
):
    first_event = create_test_event(
        source_ip="185.23.45.10",
        username="admin",
    )

    first_response = client.post(
        "/api/security/events",
        json=first_event,
    )

    assert first_response.status_code == 200

    second_event = create_test_event(
        source_ip="10.0.0.5",
        username="admin",
    )

    second_response = client.post(
        "/api/security/events",
        json=second_event,
    )

    assert second_response.status_code == 200

    event_id = second_response.json()["id"]

    investigation_response = client.get(
        f"/api/security/events/{event_id}/investigation",
    )

    assert investigation_response.status_code == 200

    data = investigation_response.json()

    assert len(data["related_events"]) == 1

    related_event = data["related_events"][0]

    assert related_event["event_id"] == (
        first_response.json()["id"]
    )

    assert related_event["correlation_reasons"] == [
        "Same username",
    ]


def test_investigate_security_event_with_related_ip_and_username(
    client,
):
    first_event = create_test_event(
        source_ip="185.23.45.10",
        username="admin",
    )

    first_response = client.post(
        "/api/security/events",
        json=first_event,
    )

    assert first_response.status_code == 200

    second_event = create_test_event(
        source_ip="185.23.45.10",
        username="admin",
    )

    second_response = client.post(
        "/api/security/events",
        json=second_event,
    )

    assert second_response.status_code == 200

    event_id = second_response.json()["id"]

    investigation_response = client.get(
        f"/api/security/events/{event_id}/investigation",
    )

    assert investigation_response.status_code == 200

    data = investigation_response.json()

    assert len(data["related_events"]) == 1

    related_event = data["related_events"][0]

    assert related_event["event_id"] == (
        first_response.json()["id"]
    )

    assert related_event["correlation_reasons"] == [
        "Same source IP",
        "Same username",
    ]