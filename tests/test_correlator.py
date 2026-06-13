"""Tests for src.correlator."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.correlator import CorrelatedEvent, Correlator
from src.loader import Rule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_alert(
    alert_type: str,
    ts: str,
    source_ip: str = "1.2.3.4",
    port_count: int = 20,
    query_length: int = 0,
) -> dict:
    alert = {
        "type": alert_type,
        "timestamp": ts,
        "source_ip": source_ip,
    }
    if port_count:
        alert["port_count"] = port_count
    if query_length:
        alert["query_length"] = query_length
    return alert


PORT_SCAN_RULE = Rule(
    name="repeated-port-scan",
    type="PORT_SCAN",
    severity="HIGH",
    conditions={"min_port_count": 15},
    time_window_sec=60,
    threshold=2,
)

ARP_SPOOF_RULE = Rule(
    name="arp-spoofing-campaign",
    type="ARP_SPOOF",
    severity="CRITICAL",
    conditions={},
    time_window_sec=30,
    threshold=1,
)

DNS_TUNNEL_RULE = Rule(
    name="dns-tunneling-attempt",
    type="DNS_TUNNEL",
    severity="MEDIUM",
    conditions={"min_query_length": 100},
    time_window_sec=120,
    threshold=3,
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCorrelatorPortScan:
    def test_three_alerts_same_window_emits_one_event(self):
        """3 PORT_SCAN alerts within 60 s window → 1 correlated event."""
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:20+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:50+00:00"),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert len(events) == 1
        assert events[0].alert_count == 3

    def test_two_alerts_outside_window_emits_no_event(self):
        """2 PORT_SCAN alerts far apart (>60 s each) with threshold=2 → 0 events."""
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:05:00+00:00"),  # 5 min later
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert len(events) == 0

    def test_event_severity_matches_rule(self):
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:10+00:00"),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert len(events) == 1
        assert events[0].severity == "HIGH"

    def test_event_rule_name(self):
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:10+00:00"),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert events[0].rule_name == "repeated-port-scan"

    def test_condition_port_count_filter(self):
        """Alerts with port_count < min_port_count are filtered out."""
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00", port_count=5),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:10+00:00", port_count=3),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert len(events) == 0

    def test_source_ips_collected(self):
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00", source_ip="1.1.1.1"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:10+00:00", source_ip="2.2.2.2"),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert len(events) == 1
        assert set(events[0].source_ips) == {"1.1.1.1", "2.2.2.2"}


class TestCorrelatorArpSpoof:
    def test_single_arp_spoof_emits_critical_event(self):
        """ARP_SPOOF with threshold=1 → 1 CRITICAL event for a single alert."""
        alerts = [
            {"type": "ARP_SPOOF", "timestamp": "2024-06-01T10:00:00+00:00", "source_ip": "192.168.1.99"}
        ]
        events = Correlator().correlate(alerts, [ARP_SPOOF_RULE])
        assert len(events) == 1
        assert events[0].severity == "CRITICAL"

    def test_no_matching_type_emits_no_event(self):
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
        ]
        events = Correlator().correlate(alerts, [ARP_SPOOF_RULE])
        assert len(events) == 0


class TestCorrelatorTimestamps:
    def test_first_and_last_seen(self):
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:30+00:00"),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        assert len(events) == 1
        assert events[0].first_seen < events[0].last_seen

    def test_two_separate_windows_emit_two_events(self):
        """Two bursts of 2 alerts each, separated by >60 s, each reaches threshold."""
        rule = Rule(
            name="repeated-port-scan",
            type="PORT_SCAN",
            severity="HIGH",
            conditions={"min_port_count": 15},
            time_window_sec=60,
            threshold=2,
        )
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:30+00:00"),
            # gap > 60 s
            _make_alert("PORT_SCAN", "2024-06-01T10:02:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:02:30+00:00"),
        ]
        events = Correlator().correlate(alerts, [rule])
        assert len(events) == 2

    def test_to_dict_serialisable(self):
        alerts = [
            _make_alert("PORT_SCAN", "2024-06-01T10:00:00+00:00"),
            _make_alert("PORT_SCAN", "2024-06-01T10:00:10+00:00"),
        ]
        events = Correlator().correlate(alerts, [PORT_SCAN_RULE])
        d = events[0].to_dict()
        assert "rule_name" in d
        assert "severity" in d
        assert "first_seen" in d
        assert "last_seen" in d
        assert "source_ips" in d
        assert "alert_count" in d
