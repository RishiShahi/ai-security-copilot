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
- Risk-factor generation separated from final analysis construction
- Deterministic analysis response builder
- Security configuration separated from analysis logic
- Centralized deterministic security rules
- Direct unit tests for analysis response construction
- Unit tests
- API integration tests
- 47 automated tests passing

### Week 3 — Investigation Layer (In Progress) 🚧

- Analyst-oriented security investigations
- Structured investigation evidence
- Investigation summaries
- Recommended security actions
- Related security-event correlation
- Source IP correlation
- Username correlation
- Explainable correlation reasons
- Duplicate related-event protection
- Investigation timeline generation
- Chronological investigation context
- Current-event timeline identification
- Deterministic event prioritization
- Severity-based priority scoring
- Correlation-strength priority scoring
- Human-readable priority levels
- Explainable priority reasons
- Prioritized related-event sorting
- Event correlation unit tests
- Investigation timeline unit tests
- Event prioritization unit tests
- Investigation service integration tests
- Investigation API integration tests
- Deterministic investigation findings
- Risk-based investigation findings
- Priority-based investigation findings
- Correlated-activity findings
- Analyst-oriented investigation summaries
- 83 automated tests passing

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

The backend follows a layered architecture with separate deterministic analysis, correlation, investigation, timeline, and prioritization layers.

```text
                              Client
                                │
                                ▼
                           FastAPI Router
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
   Security Event API      Analysis API       Investigation API
          │                     │                     │
          ▼                     ▼                     ▼
   Security Event Service ──────┴──────────────► Retrieve Event
          │                                           │
          ▼                                           │
      Repository                                      │
          │                                           │
          ▼                                           ▼
     SQLAlchemy                              ┌───────────────────┐
          │                                  │ Event Context     │
          ▼                                  │ Builder           │
       SQLite                                └─────────┬─────────┘
                                                       │
                                                       ▼
                                                 EventContext
                                                       │
                                                       ▼
                                               Security Analyzer
                                                       │
                                                       ▼
                                                Risk Factor Engine
                                                       │
                    ┌──────────────────────────┬───────┴────────┬──────────────────────────┐
                    ▼                          ▼                ▼                          ▼
              Severity Factors         Historical Activity  Behavioral Activity     Event-Type Factors
                    │                          │                │                          │
                    └──────────────────────────┴───────┬────────┴──────────────────────────┘
                                                       │
                                                       ▼
                                                 RiskFactor[]
                                                       │
                                                       ▼
                                          Analysis Response Builder
                                                       │
                              ┌────────────────────────┼────────────────────────┐
                              ▼                        ▼                        ▼
                         Risk Score               Threat Type             Recommendation
                              │                        │                        │
                              └────────────────────────┼────────────────────────┘
                                                       │
                                                       ▼
                                            SecurityAnalysisResponse


                     Retrieve Event
                           │
                           ▼
                    Candidate Retrieval
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
           Source IP               Username
                │                     │
                └──────────┬──────────┘
                           │
                           ▼
                 Event Correlation Service
                           │
                           ▼
                     Related Events
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
     Timeline Service          Prioritization Service
              │                         │
              ▼                         ├── Severity Impact
       Investigation Timeline            │
                                        ├── Correlation Impact
                                        │
                                        ├── Priority Score
                                        │
                                        ├── Priority Level
                                        │
                                        └── Priority Reasons
                                                  │
                                                  ▼
                                           Prioritized Events


SecurityAnalysisResponse + Related Events + Timeline + Prioritized Events

                         │
                         ▼

                  Investigation Service

             ┌───────────────┼────────────────────────────┐
             ▼               ▼                ▼           ▼

          Evidence        Summary      Investigation   Recommended
                                      Findings           Actions
             │               │                │              │
             └───────────────┴────────────────┴──────────────┘
                             │
                             ▼

                  SecurityInvestigationResponse
                             │
                             ▼
                      Investigation API Response


Security Configuration
        │
        └──────────────────────────────► Security Analyzer
```

### Security Analysis Configuration

The deterministic security rules used by the analyzer are centralized in:

````text
app/core/security_config.py

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
| GET | `/api/security/events/{event_id}/investigation` | Generate an analyst-oriented investigation using deterministic risk analysis and related-event correlation |

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
````

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

| Risk Factor             | Description                               |
| ----------------------- | ----------------------------------------- |
| `high_severity`         | Risk contribution from event severity     |
| `failed_login`          | Risk contribution from the event type     |
| `privileged_account`    | Event involves a privileged account       |
| `external_source`       | Event originated from an external IP      |
| `historical_activity`   | Repeated activity from the same source    |
| `recent_activity`       | High activity within a recent time window |
| `failed_login_activity` | Repeated failed-login behavior            |
| `multiple_usernames`    | Source has targeted multiple usernames    |

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

# Event Correlation

The investigation layer correlates related security events to provide additional context beyond the risk analysis of a single event.

The current correlation engine identifies related events using deterministic signals:

- Same source IP address
- Same username
- Same source IP address and username

The investigated event itself is excluded from its related-event results.

# Event Prioritization

After related security events are identified, the investigation layer prioritizes them to help analysts determine which related events should be investigated first.

The currently investigated event is not included in prioritization because it is already the primary focus of the investigation.

The prioritization service operates only on related security events.

## Priority Scoring

Priority is calculated using two deterministic factors:

```text
Priority Score
      =
Severity Impact
      +
Correlation Impact
```

### Severity Impact

| Severity | Priority Impact |
| -------- | --------------- |
| Critical | 70              |
| High     | 50              |
| Medium   | 30              |
| Low      | 10              |

### Correlation Impact

Each correlation reason contributes:

```text
+10 priority points
```

Examples:

| Correlation Reasons     | Priority Impact |
| ----------------------- | --------------- |
| No correlation reasons  | 0               |
| One correlation reason  | +10             |
| Two correlation reasons | +20             |

Example:

```text
Severity: Critical

Correlation:
- Same source IP
- Same username

Priority Score:

70 + 20 = 90
```

## Priority Levels

| Priority Score | Priority Level |
| -------------- | -------------- |
| 80+            | Critical       |
| 60–79          | High           |
| 30–59          | Medium         |
| Below 30       | Low            |

## Explainable Prioritization

Each prioritized event includes explanations describing why it received its priority.

Example:

```json
{
  "event_id": 12,
  "priority_score": 90,
  "priority_level": "critical",
  "priority_reasons": [
    "Critical severity",
    "Matched Same source IP and Same username"
  ]
}
```

This allows analysts to understand both the priority assigned to an event and the deterministic factors that contributed to that priority.

## Prioritization Flow

```text
RelatedSecurityEvent
        │
        ▼
Prioritization Service
        │
        ├── Determine Severity Impact
        │
        ├── Determine Correlation Impact
        │
        ├── Calculate Priority Score
        │
        ├── Determine Priority Level
        │
        ├── Build Priority Reasons
        │
        ▼
PrioritizedSecurityEvent
        │
        ▼
Sort by Priority Score
        │
        ▼
Highest Priority → Lowest Priority
```

## Investigation Findings

The investigation layer derives deterministic, analyst-oriented findings from the existing security analysis and event prioritization results.

Investigation findings provide an additional interpretation layer without duplicating the underlying risk-analysis logic.

### Investigation Finding Structure

Each investigation finding contains:

- **Category** — Identifies the source of the finding, such as risk, priority, or correlation
- **Severity** — Indicates the importance of the finding
- **Description** — Provides a human-readable explanation

### Finding Categories

The investigation layer currently generates findings for:

| Category      | Description                                                  |
| ------------- | ------------------------------------------------------------ |
| `risk`        | Highlights critical or high-risk investigation results       |
| `priority`    | Identifies critical or high-priority related events          |
| `correlation` | Highlights investigations containing multiple related events |

### Deterministic Finding Rules

Investigation findings are generated from existing structured data.

| Condition                              | Finding                                             |
| -------------------------------------- | --------------------------------------------------- |
| Risk level = `critical`                | Critical-risk activity requires immediate attention |
| Risk level = `high`                    | High-risk activity requires prompt investigation    |
| Critical-priority related events exist | Critical-priority activity is highlighted           |
| High-priority related events exist     | High-priority activity is highlighted               |
| 3 or more prioritized related events   | Correlated activity is highlighted                  |
| No significant activity                | No additional finding is generated                  |

The findings layer does not independently calculate risk. It interprets the outputs produced by the deterministic analysis and prioritization layers.

### Analyst-Oriented Investigation Summary

The investigation summary combines:

- Threat classification
- Risk level
- Risk score
- Number of risk factors
- Number of related events
- Significant investigation findings

The summary adds contextual interpretation for high- and critical-risk investigations and correlated activity while remaining deterministic and explainable.

This provides a structured foundation for the future AI investigation layer, where an LLM can consume the existing evidence, timeline, prioritized events, and findings rather than independently determining security risk.

## Correlation Reasons

Each related event includes structured correlation reasons explaining why it is connected to the investigated event.

Example:

```json
{
  "event_id": 12,
  "timestamp": "2026-09-02T10:30:00Z",
  "event_type": "failed_login",
  "severity": "medium",
  "source_ip": "185.23.45.10",
  "username": "admin",
  "correlation_reasons": ["Same source IP", "Same username"]
}
```

### Deterministic Analysis Pipeline

The security analyzer separates risk-factor generation from final analysis construction.

````text
Security Configuration
            │
            ▼
Security Event + EventContext
            │
            ▼
     Risk Factor Engine
            │
            ▼
       RiskFactor[]
            │
            ▼
 Analysis Response Builder
            │
     ┌──────┼──────────┐
     ▼      ▼          ▼
Risk Score Risk Level Threat Type
                       │
                       ▼
                Recommendation
                       │
                       ▼
          SecurityAnalysisResponse
```text

```python
risk_score = min(
    sum(factor.impact for factor in factors),
    100,
)
````

# Testing

## Running Tests

From the `backend` directory:

```bash
pytest
```

The project currently contains 83 automated tests.

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
- Deterministic analysis response construction
- Analysis response risk-score calculation
- Analysis response risk-score capping

`tests/test_event_correlation_service.py`

Tests deterministic event correlation logic including:

- Same source IP correlation
- Same username correlation
- Source IP and username correlation
- No-correlation scenarios
- Current-event exclusion
- Duplicate candidate-event exclusion

`tests/test_investigation_service.py`

Tests investigation response construction including:

- Risk-factor conversion into investigation evidence
- Deterministic investigation summary generation
- Investigation response construction
- Related-event inclusion
- Correlation context in investigation summaries
- Investigation finding generation
- Critical-risk investigation findings
- High-risk investigation findings
- Critical-priority event findings
- High-priority event findings
- Correlated-activity findings
- No-significant-activity handling
- Analyst-oriented summary generation

`tests/test_investigation_timeline_service.py`

Tests investigation timeline generation including:

- Current-event timeline inclusion
- Related-event timeline inclusion
- Chronological event sorting
- Current-event identification
- Correlation-reason preservation

`tests/test_investigation_prioritization_service.py`

Tests deterministic event prioritization including:

- Severity priority impacts
- Case-insensitive severity handling
- Unknown severity handling
- Correlation priority impacts
- Priority-score calculation
- Priority-level classification
- Priority-reason generation
- Single-event prioritization
- Related-event prioritization
- Descending priority sorting

`tests/test_investigation_service.py`

Also verifies:

- Investigation timeline inclusion
- Prioritized-event inclusion
- Prioritized-event ordering
- Priority scores in investigation responses
- Priority levels in investigation responses

## API Integration Tests

`tests/test_security_events.py`

Tests the complete FastAPI flow:

```text
HTTP Request
    │
    ▼
FastAPI Router
    │
    ▼
Security Event Service
    │
    ▼
Repository
    │
    ▼
SQLite
    │
    ▼
Security Event
    │
    ├── EventContext Builder
    │         │
    │         ▼
    │   Security Analyzer
    │         │
    │         ▼
    │   Risk Factors
    │         │
    │         ▼
    │ SecurityAnalysisResponse
    │
    └── Candidate Retrieval
              │
       ┌──────┴──────┐
       ▼             ▼
   Source IP      Username
       │             │
       └──────┬──────┘
              ▼
   Event Correlation Service
              │
              ▼
        Related Events
              │
       ┌──────┴───────────────┐
       ▼                      ▼
Timeline Service      Prioritization Service
       │                      │
       ▼                      ▼
Investigation Timeline   Prioritized Events
       │                      │
       └───────────┬──────────┘
                   ▼
        Investigation Service
                   │
                   ▼
    SecurityInvestigationResponse
                   │
                   ▼
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
| ├── app/
| |   ├── api/
| |   |   └── routes/
| |   |   └── security_events.py
│ │   |── core/
| |   |  ├── config.py
| |   |  └── security_config.py
│ │   ├── models/
| |   |  └── security_event.py
│ │   ├── repositories/
| |   |  └── security_event_repository.py
│ │   ├── schemas/
| |   |   └── investigation.py
| |   |   └── security_event.py
│ │   |── services/
| |   |    ├── event_context.py
| |   |    ├── event_context_builder.py
| |   |    ├── event_correlation_service.py
| |   |    ├── investigation_prioritization_service.py
| |   |    ├── investigation_service.py
| |   |    ├── investigation_timeline_service.py
| |   |    ├── security_analyzer.py
| |   |    └── security_event_service.py
│ │   |── database.py
│ │   |── main.py
│ │
│ ├── tests/
| |   ├── conftest.py
│ |   ├── test_event_correlation_service.py
| |   ├── test_investigation_prioritization_service.py
| |   ├── test_investigation_timeline_service.py
| |   ├── test_investigation_service.py
| |   ├── test_security_analyzer.py
| |   └── test_security_events.py
│ │
│ └── requirements.txt
│
├── README.md
└── .gitignore
```
