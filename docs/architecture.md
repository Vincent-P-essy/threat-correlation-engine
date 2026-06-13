# Threat Correlation Engine – Architecture

## Overview

The **threat-correlation-engine** is a Python service that sits between raw network alert producers (e.g. `pcap-analyzer`, `security-audit-logger`) and downstream incident management (e.g. `incident-tracker-api`). Its responsibility is to:

1. Ingest raw, atomic security alerts in JSON format.
2. Load and evaluate YAML-defined correlation rules.
3. Group temporally related alerts into higher-level `CorrelatedEvent` objects.
4. Dispatch those events to the incident-tracker-api via authenticated HTTP.

---

## Data Flow

```
┌──────────────────────┐      JSON alerts        ┌─────────────────────────────┐
│   pcap-analyzer      │ ──────────────────────► │                             │
├──────────────────────┤                         │   threat-correlation-engine  │
│ security-audit-logger│ ──────────────────────► │                             │
└──────────────────────┘                         │  ┌─────────┐  ┌──────────┐  │
                                                 │  │ Loader  │  │Correlator│  │
                                                 │  └────┬────┘  └────┬─────┘  │
                                                 │       │ Rules      │Events  │
                                                 │  ┌────▼────────────▼─────┐  │
                                                 │  │       Engine          │  │
                                                 │  └───────────┬───────────┘  │
                                                 │              │              │
                                                 │  ┌───────────▼───────────┐  │
                                                 │  │      Dispatcher       │  │
                                                 │  └───────────────────────┘  │
                                                 └──────────────┬──────────────┘
                                                                │ POST /api/v1/incidents
                                                                ▼
                                                 ┌──────────────────────────────┐
                                                 │    incident-tracker-api      │
                                                 └──────────────────────────────┘
```

---

## Components

### `src/loader.py` – Rule Loader

**Responsibility:** Discover, parse, and validate YAML rule files.

- Scans a configurable directory for `*.yml` files.
- Each file is parsed with `PyYAML` and validated against a required-field schema: `name`, `type`, `severity`, `conditions`, `time_window_sec`.
- Valid rules are converted into `Rule` dataclass instances and returned as a list.
- Invalid or malformed files are logged and skipped (fail-open per file).

**Rule dataclass fields:**

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Unique human-readable identifier |
| `type` | `str` | Alert type this rule applies to (e.g. `PORT_SCAN`) |
| `severity` | `str` | Resulting event severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) |
| `conditions` | `dict` | Optional filter conditions (e.g. `min_port_count`) |
| `time_window_sec` | `int` | Duration of the correlation window in seconds |
| `threshold` | `int` | Minimum number of matching alerts in a window to emit an event |
| `description` | `str` | Human-readable description |
| `tags` | `list[str]` | Arbitrary classification tags |

---

### `src/correlator.py` – Correlator

**Responsibility:** Apply rules to a list of raw alerts and produce `CorrelatedEvent` objects.

**Algorithm:**

1. For each rule, filter alerts whose `type` matches and whose fields satisfy `conditions`.
2. Sort the matched alerts by `timestamp` (ISO-8601 or Unix epoch).
3. Apply a **non-overlapping sliding window** of `time_window_sec` duration:
   - Start a new window when the first alert arrives.
   - Add subsequent alerts whose timestamp falls within `window_start + time_window_sec`.
   - When an alert falls outside the current window, flush the window and start a new one.
4. Flush each window: if `len(window) >= threshold`, emit a `CorrelatedEvent`.

**CorrelatedEvent fields:**

| Field | Type | Description |
|---|---|---|
| `rule_name` | `str` | Name of the rule that triggered the event |
| `severity` | `str` | Severity from the rule |
| `first_seen` | `datetime` | Timestamp of earliest alert in the group |
| `last_seen` | `datetime` | Timestamp of latest alert in the group |
| `source_ips` | `list[str]` | Deduplicated source IPs from alerts in the group |
| `alert_count` | `int` | Number of alerts in the correlated group |
| `raw_alerts` | `list[dict]` | Original alert dicts |

---

### `src/dispatcher.py` – Dispatcher

**Responsibility:** POST `CorrelatedEvent` payloads to the incident-tracker-api.

- Reads `INCIDENT_TRACKER_API_KEY` from environment for Bearer token auth.
- Reads `DRY_RUN=true` from environment (or constructor arg) to suppress HTTP calls.
- **Retry logic:** up to 3 attempts with exponential backoff (1 s, 2 s, 4 s).
- Logs each attempt outcome at appropriate levels (`INFO` for success, `WARNING` for transient failure, `ERROR` for final failure).

**Incident payload format (POST `/api/v1/incidents`):**

```json
{
  "title": "[HIGH] repeated-port-scan",
  "severity": "HIGH",
  "rule_name": "repeated-port-scan",
  "first_seen": "2024-06-01T10:00:00+00:00",
  "last_seen": "2024-06-01T10:00:50+00:00",
  "source_ips": ["192.168.1.50", "192.168.1.51"],
  "alert_count": 3,
  "source": "threat-correlation-engine"
}
```

---

### `src/engine.py` – Engine

**Responsibility:** Orchestrate the full pipeline and expose both a Python API and a CLI.

**`Engine.run(alerts)`** returns:

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

## YAML Rule Format

```yaml
name: <unique-rule-name>          # required
type: <ALERT_TYPE>                # required – must match alert["type"]
severity: LOW|MEDIUM|HIGH|CRITICAL  # required
description: "Human readable"    # optional
conditions:                      # required (may be empty {})
  min_port_count: 15             # example condition
  min_query_length: 100          # example condition
time_window_sec: 60              # required – positive integer
threshold: 2                     # optional, default 1
tags: [network, reconnaissance]  # optional
```

### Supported Conditions

| Key | Applies to type | Description |
|---|---|---|
| `min_port_count` | `PORT_SCAN` | Alert's `port_count` must be ≥ this value |
| `min_query_length` | `DNS_TUNNEL` | Alert's `query_length` must be ≥ this value |

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `INCIDENT_TRACKER_URL` | `http://localhost:8000` | Base URL of the incident-tracker-api |
| `INCIDENT_TRACKER_API_KEY` | _(empty)_ | Bearer token for API authentication |
| `DRY_RUN` | `false` | Set to `true` to suppress HTTP dispatches |
