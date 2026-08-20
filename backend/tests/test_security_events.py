from datetime import UTC, datetime


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


def test_analyze_nonexistent_security_event(client):
    response = client.get(
        "/api/security/events/9999/analysis",
    )

    assert response.status_code == 404

    data = response.json()

    assert data["detail"] == "Security event not found"