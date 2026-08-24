from datetime import UTC, datetime, timedelta


def create_test_event():
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "firewall",
        "event_type": "failed_login",
        "severity": "high",
        "source_ip": "185.23.45.10",
        "username": "admin",
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