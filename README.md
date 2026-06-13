# threat-correlation-engine

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-pytest-orange)

The **threat-correlation-engine** is the intelligence layer of a security portfolio.
It consumes raw JSON alerts produced by upstream collectors, applies declarative YAML
rules to detect attack patterns, correlates temporally related events, and
automatically dispatches incidents to `incident-tracker-api`.

---

## Role in the Ecosystem

```
┌──────────────────────┐
│   pcap-analyzer      │ ─────────────┐
└──────────────────────┘             │  JSON alerts
                                     ▼
┌──────────────────────┐   ┌──────────────────────────────┐
│ security-audit-logger│──►│  threat-correlation-engine   │
└──────────────────────┘   │                              │
                           │  • Load YAML rules           │
                           │  • Filter & time-window      │
                           │  • Correlate → CorrelatedEvent│
                           │  • Dispatch (retry + backoff) │
                           └──────────────┬───────────────┘
                                          │ POST /api/v1/incidents
                                          ▼
                           ┌──────────────────────────────┐
                           │    incident-tracker-api      │
                           └──────────────────────────────┘
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/vincent-p-essy/threat-correlation-engine.git
cd threat-correlation-engine

# Create and activate a virtual environment (Python 3.11+)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install runtime dependencies
pip install -r requirements.txt

# (Optional) install as a package with the CLI entry point
pip install -e .
```

---

## Configuration

All runtime configuration is provided via environment variables:

| Variable | Default | Description |
|---|---|---|
| `INCIDENT_TRACKER_URL` | `http://localhost:8000` | Base URL of the incident-tracker-api |
| `INCIDENT_TRACKER_API_KEY` | _(empty)_ | Bearer token for API authentication |
| `DRY_RUN` | `false` | Set to `true` to log events without HTTP calls |

Example `.env`:

```dotenv
INCIDENT_TRACKER_URL=https://tracker.internal
INCIDENT_TRACKER_API_KEY=secret-token
DRY_RUN=false
```

---

## Usage

### CLI

```bash
# Basic usage
python -m src.engine --input alerts.json

# Custom rules directory and dry-run mode
python -m src.engine --input alerts.json --rules-dir rules/ --dry-run

# Specify incident tracker URL explicitly
python -m src.engine --input alerts.json \
  --incident-tracker-url https://tracker.internal

# Verbose (DEBUG) logging
python -m src.engine --input alerts.json --verbose

# If installed as a package
threat-engine --input alerts.json --rules-dir rules/
```

### Python API

```python
from src.engine import Engine

engine = Engine(
    rules_dir="rules/",
    incident_tracker_url="https://tracker.internal",
    dry_run=True,
)

# From a file
result = engine.run_from_file("alerts.json")
print(result)
# {
#   "processed": 5,
#   "correlated": 2,
#   "dispatched": 2,
#   "events": [...]
# }

# From an in-memory list
alerts = [
    {"type": "PORT_SCAN", "timestamp": "2024-06-01T10:00:00+00:00",
     "source_ip": "1.2.3.4", "port_count": 20},
]
result = engine.run(alerts)
```

---

## Input Format (pcap-analyzer JSON)

The engine accepts either a bare JSON array or an object with an `"alerts"` key:

```json
[
  {
    "id": "alert-001",
    "type": "PORT_SCAN",
    "timestamp": "2024-06-01T10:00:00+00:00",
    "source_ip": "192.168.1.50",
    "destination_ip": "10.0.0.1",
    "port_count": 20,
    "severity": "HIGH",
    "description": "Port scan detected"
  }
]
```

Required fields per alert: `type`, `timestamp`, `source_ip`.

---

## Output Format

```json
{
  "processed": 5,
  "correlated": 2,
  "dispatched": 2,
  "events": [
    {
      "rule_name": "repeated-port-scan",
      "severity": "HIGH",
      "first_seen": "2024-06-01T10:00:00+00:00",
      "last_seen": "2024-06-01T10:00:50+00:00",
      "source_ips": ["192.168.1.50", "192.168.1.51"],
      "alert_count": 3
    }
  ]
}
```

---

## Writing a Custom YAML Rule

Drop a `.yml` file in the `rules/` directory:

```yaml
name: my-custom-rule          # unique identifier (required)
type: MY_ALERT_TYPE           # must match the "type" field in alerts (required)
severity: HIGH                # LOW | MEDIUM | HIGH | CRITICAL (required)
description: "What this detects"  # optional
conditions:                   # required – use {} for no extra filters
  min_port_count: 10          # alert["port_count"] >= 10
time_window_sec: 120          # correlation window in seconds (required)
threshold: 3                  # min alerts per window to fire an event (default 1)
tags: [custom, network]       # optional classification tags
```

### Supported Conditions

| Condition key | Applicable type | Meaning |
|---|---|---|
| `min_port_count` | `PORT_SCAN` | `alert["port_count"] >= value` |
| `min_query_length` | `DNS_TUNNEL` | `alert["query_length"] >= value` |

---

## Architecture

```
src/
├── loader.py      # YAML rule loader + Rule dataclass
├── correlator.py  # Time-window correlation + CorrelatedEvent dataclass
├── dispatcher.py  # HTTP dispatch to incident-tracker-api (retry + backoff)
└── engine.py      # Orchestrator + CLI (argparse)
```

See [docs/architecture.md](docs/architecture.md) for a detailed breakdown.

---

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run a specific test file
pytest tests/test_correlator.py -v
```

---

## Roadmap

- **ML-based anomaly detection** – integrate an anomaly scoring model (Isolation Forest / Autoencoder) to surface statistical outliers alongside rule-based events.
- **Redis pub/sub integration** – consume alerts in real-time from a Redis channel instead of (or in addition to) file-based input.
- **Webhook support** – configurable outbound webhooks (Slack, PagerDuty, Teams) as an alternative or complement to incident-tracker-api.
- **Rule hot-reload** – watch the `rules/` directory and reload rules without restarting the engine.
- **Metric export** – Prometheus `/metrics` endpoint exposing processed/correlated/dispatched counters.

---

## Author

**Vincent Plessy** – [vincent.plessy12@gmail.com](mailto:vincent.plessy12@gmail.com)

Part of a personal cybersecurity portfolio showcasing end-to-end detection and response tooling.
