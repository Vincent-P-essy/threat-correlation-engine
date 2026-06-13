"""Engine: orchestrates loader, correlator, and dispatcher.

CLI usage::

    python -m src.engine --input alerts.json --rules-dir rules/ --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from .correlator import CorrelatedEvent, Correlator
from .dispatcher import Dispatcher
from .loader import Rule, load_rules

logger = logging.getLogger(__name__)


class Engine:
    """Top-level orchestrator for the threat correlation pipeline."""

    def __init__(
        self,
        rules_dir: str = "rules",
        incident_tracker_url: str | None = None,
        api_key: str | None = None,
        dry_run: bool = False,
    ) -> None:
        self.rules_dir = rules_dir
        self._incident_tracker_url = incident_tracker_url or os.environ.get(
            "INCIDENT_TRACKER_URL", "http://localhost:8000"
        )
        self._api_key = api_key
        self._dry_run = dry_run
        self._correlator = Correlator()
        self._dispatcher = Dispatcher(
            incident_tracker_url=self._incident_tracker_url,
            api_key=self._api_key,
            dry_run=self._dry_run,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, alerts: list[dict]) -> dict[str, Any]:
        """Process *alerts* and return a summary dict."""
        rules: list[Rule] = load_rules(self.rules_dir)
        events: list[CorrelatedEvent] = self._correlator.correlate(alerts, rules)
        dispatched = self._dispatcher.dispatch_many(events)
        result = {
            "processed": len(alerts),
            "correlated": len(events),
            "dispatched": dispatched,
            "events": [e.to_dict() for e in events],
        }
        logger.info(
            "Run complete: %d alerts processed, %d events correlated, %d dispatched.",
            len(alerts), len(events), dispatched,
        )
        return result

    def run_from_file(self, path: str) -> dict[str, Any]:
        """Read alerts from a JSON file and call :meth:`run`."""
        alerts_path = Path(path)
        if not alerts_path.is_file():
            raise FileNotFoundError(f"Alerts file not found: {path}")
        with alerts_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        # Support both a bare list and {"alerts": [...]} envelope
        if isinstance(data, list):
            alerts = data
        elif isinstance(data, dict):
            alerts = data.get("alerts", data.get("events", []))
        else:
            raise ValueError(f"Unexpected JSON structure in '{path}'")
        return self.run(alerts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threat-engine",
        description="Threat Correlation Engine – correlate alerts and dispatch incidents.",
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        metavar="FILE",
        help="Path to the JSON file containing alerts (output of pcap-analyzer).",
    )
    parser.add_argument(
        "--rules-dir", "-r",
        default="rules",
        metavar="DIR",
        help="Directory containing YAML rule files (default: rules/).",
    )
    parser.add_argument(
        "--incident-tracker-url",
        default=None,
        metavar="URL",
        help="Base URL of incident-tracker-api (overrides INCIDENT_TRACKER_URL env var).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log dispatches without actually sending HTTP requests.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    engine = Engine(
        rules_dir=args.rules_dir,
        incident_tracker_url=args.incident_tracker_url,
        dry_run=args.dry_run,
    )
    try:
        result = engine.run_from_file(args.input)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        sys.exit(1)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
