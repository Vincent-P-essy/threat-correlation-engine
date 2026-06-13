"""Correlator: matches alerts against rules and emits CorrelatedEvent objects."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .loader import Rule

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedEvent:
    rule_name: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    source_ips: list[str]
    alert_count: int
    raw_alerts: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "severity": self.severity,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "source_ips": self.source_ips,
            "alert_count": self.alert_count,
        }


def _parse_timestamp(ts: Any) -> datetime:
    """Parse an ISO-8601 string or unix epoch (int/float) into a UTC datetime."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        # python-dateutil is a dependency but let's keep stdlib first
        try:
            from dateutil import parser as du_parser  # type: ignore
            return du_parser.parse(ts).astimezone(timezone.utc)
        except Exception:  # noqa: BLE001
            pass
    raise ValueError(f"Cannot parse timestamp: {ts!r}")


def _alert_matches_rule(alert: dict, rule: Rule) -> bool:
    """Return True when *alert* satisfies the rule type and condition filters."""
    if alert.get("type") != rule.type:
        return False
    conds = rule.conditions
    if "min_port_count" in conds:
        if int(alert.get("port_count", 0)) < int(conds["min_port_count"]):
            return False
    if "min_query_length" in conds:
        if int(alert.get("query_length", 0)) < int(conds["min_query_length"]):
            return False
    return True


class Correlator:
    """Correlates a flat list of alerts into higher-level security events."""

    def correlate(self, alerts: list[dict], rules: list[Rule]) -> list[CorrelatedEvent]:
        events: list[CorrelatedEvent] = []
        for rule in rules:
            matched = [
                a for a in alerts
                if _alert_matches_rule(a, rule)
            ]
            if not matched:
                continue

            # Sort by timestamp so we can apply a sliding window
            try:
                matched_sorted = sorted(matched, key=lambda a: _parse_timestamp(a["timestamp"]))
            except (KeyError, ValueError) as exc:
                logger.warning("Skipping rule '%s' due to timestamp error: %s", rule.name, exc)
                continue

            window_events = self._apply_window(matched_sorted, rule)
            events.extend(window_events)
            logger.debug(
                "Rule '%s': %d matched alert(s) → %d event(s).",
                rule.name, len(matched), len(window_events),
            )
        return events

    def _apply_window(
        self, sorted_alerts: list[dict], rule: Rule
    ) -> list[CorrelatedEvent]:
        """Group *sorted_alerts* into non-overlapping time windows and emit events
        for groups that reach the rule threshold."""
        events: list[CorrelatedEvent] = []
        window: list[dict] = []
        window_start: datetime | None = None

        for alert in sorted_alerts:
            ts = _parse_timestamp(alert["timestamp"])
            if window_start is None:
                window_start = ts
                window = [alert]
            elif (ts - window_start).total_seconds() <= rule.time_window_sec:
                window.append(alert)
            else:
                # Flush current window
                event = self._maybe_emit(window, rule)
                if event:
                    events.append(event)
                # Start a new window
                window_start = ts
                window = [alert]

        # Flush trailing window
        if window:
            event = self._maybe_emit(window, rule)
            if event:
                events.append(event)

        return events

    @staticmethod
    def _maybe_emit(window: list[dict], rule: Rule) -> CorrelatedEvent | None:
        if len(window) < rule.threshold:
            return None
        timestamps = [_parse_timestamp(a["timestamp"]) for a in window]
        source_ips = list({
            a["source_ip"] for a in window if "source_ip" in a
        })
        return CorrelatedEvent(
            rule_name=rule.name,
            severity=rule.severity,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            source_ips=source_ips,
            alert_count=len(window),
            raw_alerts=window,
        )
