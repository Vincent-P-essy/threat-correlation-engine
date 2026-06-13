"""Tests for src.engine."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import responses as responses_lib

from src.engine import Engine


FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_ALERTS = FIXTURES_DIR / "sample_alerts.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine(dry_run: bool = True, rules_dir: str | None = None) -> Engine:
    return Engine(
        rules_dir=rules_dir or str(Path(__file__).parent.parent / "rules"),
        incident_tracker_url="http://fake-tracker",
        dry_run=dry_run,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEngineRunFromFile:
    def test_run_from_file_returns_summary_dict(self):
        engine = _engine(dry_run=True)
        result = engine.run_from_file(str(SAMPLE_ALERTS))
        assert "processed" in result
        assert "correlated" in result
        assert "dispatched" in result
        assert "events" in result

    def test_processed_count_matches_fixture(self):
        engine = _engine(dry_run=True)
        result = engine.run_from_file(str(SAMPLE_ALERTS))
        # fixture has 5 alerts
        assert result["processed"] == 5

    def test_correlated_events_are_list(self):
        engine = _engine(dry_run=True)
        result = engine.run_from_file(str(SAMPLE_ALERTS))
        assert isinstance(result["events"], list)

    def test_file_not_found_raises(self):
        engine = _engine(dry_run=True)
        with pytest.raises(FileNotFoundError):
            engine.run_from_file("/nonexistent/path/alerts.json")


class TestEngineDryRun:
    def test_dry_run_dispatched_equals_correlated(self):
        """In dry-run mode every correlated event counts as dispatched."""
        engine = _engine(dry_run=True)
        result = engine.run_from_file(str(SAMPLE_ALERTS))
        assert result["dispatched"] == result["correlated"]

    def test_dry_run_no_http_calls(self):
        """Dry-run must not make any outbound HTTP requests."""
        with responses_lib.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            # No registered routes → any real request would raise ConnectionError
            engine = _engine(dry_run=True)
            result = engine.run_from_file(str(SAMPLE_ALERTS))
        # Just assert it finished without error
        assert result["processed"] == 5


class TestEngineEmptyRulesDir:
    def test_empty_rules_dir_gives_zero_events(self, tmp_path):
        """An empty rules directory should yield 0 correlated events."""
        engine = Engine(
            rules_dir=str(tmp_path),
            incident_tracker_url="http://fake-tracker",
            dry_run=True,
        )
        result = engine.run_from_file(str(SAMPLE_ALERTS))
        assert result["correlated"] == 0
        assert result["events"] == []

    def test_nonexistent_rules_dir_gives_zero_events(self):
        engine = Engine(
            rules_dir="/totally/nonexistent/rules",
            incident_tracker_url="http://fake-tracker",
            dry_run=True,
        )
        result = engine.run_from_file(str(SAMPLE_ALERTS))
        assert result["correlated"] == 0


class TestEngineJsonEnvelope:
    def test_alerts_envelope_format(self, tmp_path):
        """Engine accepts {\"alerts\": [...]} envelope format."""
        data = {
            "alerts": [
                {
                    "id": "x1",
                    "type": "ARP_SPOOF",
                    "timestamp": "2024-06-01T10:00:00+00:00",
                    "source_ip": "1.1.1.1",
                }
            ]
        }
        alerts_file = tmp_path / "alerts.json"
        alerts_file.write_text(json.dumps(data))
        engine = _engine(dry_run=True)
        result = engine.run_from_file(str(alerts_file))
        assert result["processed"] == 1
