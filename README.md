# AI Security Copilot

AI Security Copilot is an intelligent security-event analysis platform designed to help security teams ingest, analyze, and prioritize security events.

The project combines a FastAPI backend, persistent security-event storage, deterministic risk analysis, and automated testing as the foundation for future AI-powered security investigation and recommendations.

---

## Project Status

### Week 1 — Security Analysis Foundation ✅

- FastAPI backend
- Security event ingestion
- Pydantic request/response validation
- SQLite persistence
- SQLAlchemy ORM
- Repository layer
- Service layer
- Deterministic risk scoring
- Threat classification
- Security recommendations
- Historical activity analysis
- Recent activity analysis
- Unit tests
- API integration tests
- 14 automated tests passing

---

# What is AI Security Copilot?

Security systems generate large numbers of events such as:

- Failed login attempts
- Brute-force attacks
- Port scans
- Malware detections
- Unauthorized access attempts

Security analysts need to determine which events deserve immediate attention.

AI Security Copilot aims to assist analysts by:

1. Ingesting security events
2. Persisting events for historical analysis
3. Calculating a risk score
4. Determining the risk level
5. Identifying the likely threat type
6. Providing an initial recommendation
7. Eventually using AI to explain, correlate, and investigate security incidents

---

## Architecture

The backend follows a layered architecture.

````text
                         Client
                           │
                           ▼
                    FastAPI Router
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
      Security Event API         Analysis API
              │                         │
              ▼                         ▼
       Service Layer           Security Analyzer
              │                         │
              ▼                 ┌───────┼────────┐
       Repository Layer         │       │        │
              │              Severity Context Activity
              │                 │       │        │
              │                 └───────┼────────┘
              │                         │
              │                         ▼
              │                    Risk Score
              │                         │
              │                ┌────────┴────────┐
              │                ▼                 ▼
              │           Risk Level       Threat Type
              │                                  │
              │                                  ▼
              │                           Recommendation
              │
              ▼
          SQLAlchemy
              │
              ▼
            SQLite

# Tech Stack

## Backend

- Python
- FastAPI
- Pydantic
- SQLAlchemy
- SQLite

## Testing

- pytest
- FastAPI TestClient
- In-memory SQLite
- pytest fixtures

## Development

- Uvicorn
- Git
- GitHub

# API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/security/events` | Create a security event |
| GET | `/api/security/events` | Get all security events |
| GET | `/api/security/events/{id}` | Get a security event |
| GET | `/api/security/events/{id}/analysis` | Analyze a security event |

## Example Analysis Response

```json
{
  "event_id": 5,
  "risk_score": 95,
  "risk_level": "critical",
  "threat_type": "authentication_attack",
  "recommendation": "Investigate repeated authentication failures and verify whether the source IP is suspicious."
}

## Risk Scoring

The current risk engine uses deterministic rules to calculate a security-event risk score.

## Base Severity

| Severity | Score |
| -------- | ----- |
| Low      | 20    |
| Medium   | 40    |
| High     | 70    |
| Critical | 90    |

## Event Modifiers

| Event Type          | Modifier |
| ------------------- | -------- |
| failed_login        | +10      |
| brute_force         | +15      |
| port_scan           | +5       |
| malware_detected    | +15      |
| unauthorized_access | +20      |

## Recent Activity

| Recent Events | Modifier |
| ------------- | -------- |
| 1             | +0       |
| 2–3           | +5       |
| 4–5           | +15      |
| 6+            | +20      |

```markdown
The final risk score is capped at 100:

```python
risk_score = min(calculated_score, 100)

# Testing

## Running Tests

From the `backend` directory:

```bash
pytest

The project currently contains 14 automated tests.

## Unit Tests

`tests/test_security_analyzer.py`

Tests the deterministic risk-analysis logic including:

- Severity scoring
- Event-type modifiers
- Privileged users
- External IP detection
- Private IP handling
- Historical activity
- Recent activity
- Risk-score capping

## API Integration Tests

`tests/test_security_events.py`

Tests the complete FastAPI flow:

```text
HTTP Request
     ↓
FastAPI Router
     ↓
Service
     ↓
Repository
     ↓
SQLite
     ↓
HTTP Response

# Running Locally

## 1. Clone the repository

```bash
git clone https://github.com/RishiShahi/ai-security-copilot.git
cd ai-security-copilot


And:

```markdown
## 2. Navigate to backend

```bash
cd backend

## 3. Create Virtual Environment

python -m venv venv

## 4. Activate virtual Environment

venv\Scripts\activate

## 5. Install Dependencies

pip install -r requirements.txt

## 6. Start the server

uvicorn app.main:app --reload

The API will be available at:

```text
http://127.0.0.1:8000

Swagger documentation:

```text
http://127.0.0.1:8000/docs

```markdown
# Project Structure

```text
ai-security-copilot/
│
├── backend/
│ ├── app/
│ │ ├── api/
│ │ │ └── routes/
│ │ ├── core/
│ │ ├── models/
│ │ ├── repositories/
│ │ ├── schemas/
│ │ ├── services/
│ │ ├── database.py
│ │ └── main.py
│ │
│ ├── tests/
│ │ ├── conftest.py
│ │ ├── test_security_analyzer.py
│ │ └── test_security_events.py
│ │
│ └── requirements.txt
│
├── README.md
└── .gitignore
````
