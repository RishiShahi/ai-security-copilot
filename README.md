# AI Security Copilot

AI Security Copilot is an intelligent security-event analysis platform designed to help security teams ingest, analyze, and prioritize security events.

The project combines a FastAPI backend, persistent security-event storage, deterministic risk analysis, and automated testing as the foundation for future AI-powered security investigation and recommendations.

---

## Project Status

### Weeks 1–2 — Security Analysis Foundation ✅

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
- Context-aware risk analysis
- Behavioral analysis
- Explainable risk factors
- Security-focused risk-factor explanations
- Boundary-tested behavioral risk thresholds
- Unit tests
- API integration tests
- 40 automated tests passing

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
3. Building context from related security events
4. Identifying behavioral patterns across events
5. Calculating a deterministic risk score
6. Explaining the risk score through structured risk factors
7. Determining the risk level
8. Identifying the likely threat type
9. Providing an initial recommendation
10. Eventually using AI to explain, correlate, and investigate security incidents

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
              ▼                         ▼
       Repository Layer         Context Builder
              │                         │
              ▼                         ▼
          SQLAlchemy             EventContext
              │                         │
              ▼                         ▼
            SQLite            Risk Factor Engine
                                      │
                         ┌────────────┼────────────┐
                         ▼            ▼            ▼
                     Severity     Historical   Behavioral
                      Factors      Activity     Activity
                         │            │            │
                         └────────────┼────────────┘
                                      ▼
                                RiskFactor[]
                                      │
                         ┌────────────┴────────────┐
                         ▼                         ▼
                  Risk Score                 Explanations
                         │                         │
                         ▼                         │
                    Risk Level                    │
                         │                         │
                         ├── Threat Type           │
                         │                         │
                         └── Recommendation        │
                                      │            │
                                      └──────┬─────┘
                                             ▼
                                      Analysis Response
```

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
  "recommendation": "Investigate repeated authentication failures and verify whether the source IP is suspicious.",
  "risk_factors": [
    {
      "factor": "high_severity",
      "impact": 70,
      "description": "The event has a high severity level, indicating a significant potential security impact."
    },
    {
      "factor": "failed_login",
      "impact": 10,
      "description": "The event represents a failed authentication attempt, which may indicate an authentication attack."
    },
    {
      "factor": "privileged_account",
      "impact": 10,
      "description": "The event targets a privileged account, increasing the potential impact of unauthorized access."
    },
    {
      "factor": "external_source",
      "impact": 5,
      "description": "The event originated from an external source, increasing exposure to internet-based attacks."
    }
  ]
}
```

## Risk Scoring

The current risk engine uses deterministic rules to calculate a security-event risk score.

The analyzer first generates structured risk factors from the event and its surrounding context. Each risk factor contains:

- A factor name
- A risk impact
- A human-readable explanation

The final score is calculated by summing the impacts of the generated risk factors and is capped at 100.This ensures that the final risk score is directly traceable to the structured risk factors returned by the analyzer.

In other words, the security evidence used to explain the score is the
same evidence used to calculate it.

risk_score = min(
    sum(factor.impact for factor in factors),
    100,
)

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

## Explainable Risk Factors

The analyzer generates structured risk factors that explain why an event received its risk score.

Current risk factors include:

| Risk Factor | Description |
| ----------- | ----------- |
| `high_severity` | Risk contribution from event severity |
| `failed_login` | Risk contribution from the event type |
| `privileged_account` | Event involves a privileged account |
| `external_source` | Event originated from an external IP |
| `historical_activity` | Repeated activity from the same source |
| `recent_activity` | High activity within a recent time window |
| `failed_login_activity` | Repeated failed-login behavior |
| `multiple_usernames` | Source has targeted multiple usernames |

Each factor contributes an explicit risk impact and contains a human-readable explanation.

## Recent Activity

| Recent Events | Modifier |
| ------------- | -------- |
| 1             | +0       |
| 2–3           | +5       |
| 4–5           | +15      |
| 6+            | +20      |


| Failed-Login Events | Modifier |
| ------------------- | -------- |
| 1 or fewer          | +0       |
| 2–3                 | +5       |
| 4–5                 | +10      |
| 6+                  | +15      |


| Unique Usernames | Modifier |
| ---------------- | -------- |
| 1 or fewer       | +0       |
| 2–3              | +5       |
| 4+               | +10      |



## Behavioral Analysis

The analyzer evaluates related events from the same source to identify suspicious behavioral patterns.

Current behavioral signals include:

- Repeated failed-login activity
- Multiple targeted usernames
- Repeated historical activity
- High recent activity

These signals allow the analyzer to increase risk when an isolated event becomes more suspicious when viewed in context.

The final risk score is calculated from the generated risk factors and capped at 100:

```python
risk_score = min(
    sum(factor.impact for factor in factors),
    100,
)
```


# Testing

## Running Tests

From the `backend` directory:

```bash
pytest
```

The project currently contains 40 automated tests.

## Unit Tests

`tests/test_security_analyzer.py`

Tests the deterministic risk-analysis logic including:

- Severity risk factors
- Event-type risk factors
- Privileged-account risk factors
- External IP detection
- Private IP handling
- Historical activity risk factors
- Recent activity risk factors
- Failed-login behavioral analysis
- Multiple-username behavioral analysis
- Risk-factor aggregation
- Risk-score calculation
- Risk-score capping
- Historical activity threshold boundaries
- Recent activity threshold boundaries
- Failed-login activity threshold boundaries
- Multiple-username threshold boundaries
- Behavioral modifier calculations
- Risk-score explainability contract

## API Integration Tests

`tests/test_security_events.py`

Tests the complete FastAPI flow:

```text
HTTP Request
     ↓
FastAPI Router
     ↓
Security Service
     ↓
Repository
     ↓
SQLite
     ↓
EventContext
     ↓
Security Analyzer
     ↓
Risk Factors
     ↓
Risk Score + Explanation
     ↓
HTTP Response
```

# Running Locally

## 1. Clone the repository

```bash
git clone https://github.com/RishiShahi/ai-security-copilot.git
cd ai-security-copilot
```


And:

```markdown
## 2. Navigate to backend
```

```bash
cd backend
```

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
```

Swagger documentation:

```text
http://127.0.0.1:8000/docs
```


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
