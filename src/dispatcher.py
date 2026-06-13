"""Dispatcher: sends CorrelatedEvent objects to the incident-tracker-api."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import requests

from .correlator import CorrelatedEvent

logger = logging.getLogger(__name__)

DEFAULT_RETRIES = 3
BASE_BACKOFF = 1.0  # seconds


class Dispatcher:
    """HTTP dispatcher that POSTs correlated events to incident-tracker-api."""

    def __init__(
        self,
        incident_tracker_url: str,
        api_key: str | None = None,
        dry_run: bool | None = None,
        retries: int = DEFAULT_RETRIES,
    ) -> None:
        self.incident_tracker_url = incident_tracker_url.rstrip("/")
        self.api_key = api_key or os.environ.get("INCIDENT_TRACKER_API_KEY", "")
        self.dry_run = dry_run if dry_run is not None else (
            os.environ.get("DRY_RUN", "").lower() == "true"
        )
        self.retries = retries
        self._session = requests.Session()
        if self.api_key:
            self._session.headers["Authorization"] = f"Bearer {self.api_key}"
        self._session.headers["Content-Type"] = "application/json"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, event: CorrelatedEvent) -> bool:
        """Dispatch a single *event*. Returns True on success."""
        payload = self._build_payload(event)
        if self.dry_run:
            logger.info("[DRY-RUN] Would dispatch event '%s': %s", event.rule_name, payload)
            return True
        return self._post_with_retry(payload)

    def dispatch_many(self, events: list[CorrelatedEvent]) -> int:
        """Dispatch multiple events. Returns the count of successful dispatches."""
        successes = 0
        for event in events:
            if self.dispatch(event):
                successes += 1
        return successes

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _build_payload(self, event: CorrelatedEvent) -> dict[str, Any]:
        return {
            "title": f"[{event.severity}] {event.rule_name}",
            "severity": event.severity,
            "rule_name": event.rule_name,
            "first_seen": event.first_seen.isoformat(),
            "last_seen": event.last_seen.isoformat(),
            "source_ips": event.source_ips,
            "alert_count": event.alert_count,
            "source": "threat-correlation-engine",
        }

    def _post_with_retry(self, payload: dict) -> bool:
        url = f"{self.incident_tracker_url}/api/v1/incidents"
        for attempt in range(1, self.retries + 1):
            try:
                resp = self._session.post(url, json=payload, timeout=10)
                if resp.status_code in (200, 201):
                    logger.info(
                        "Dispatched incident '%s' (HTTP %d).",
                        payload.get("rule_name"), resp.status_code,
                    )
                    return True
                logger.warning(
                    "Attempt %d/%d – unexpected status %d for '%s'.",
                    attempt, self.retries, resp.status_code, payload.get("rule_name"),
                )
            except requests.RequestException as exc:
                logger.warning(
                    "Attempt %d/%d – request error for '%s': %s",
                    attempt, self.retries, payload.get("rule_name"), exc,
                )
            if attempt < self.retries:
                backoff = BASE_BACKOFF * (2 ** (attempt - 1))
                logger.debug("Waiting %.1fs before retry.", backoff)
                time.sleep(backoff)

        logger.error(
            "Failed to dispatch incident '%s' after %d attempts.",
            payload.get("rule_name"), self.retries,
        )
        return False
