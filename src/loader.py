"""Rule loader: reads YAML rule files and returns validated Rule dataclasses."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {"name", "type", "severity", "conditions", "time_window_sec"}


@dataclass
class Rule:
    name: str
    type: str
    severity: str
    conditions: dict[str, Any]
    time_window_sec: int
    threshold: int = 1
    description: str = ""
    tags: list[str] = field(default_factory=list)


def _validate(data: dict, path: str) -> None:
    missing = REQUIRED_FIELDS - data.keys()
    if missing:
        raise ValueError(f"Rule '{path}' is missing required fields: {missing}")
    if not isinstance(data["conditions"], dict):
        raise TypeError(f"Rule '{path}': 'conditions' must be a mapping")
    if not isinstance(data["time_window_sec"], int) or data["time_window_sec"] <= 0:
        raise ValueError(f"Rule '{path}': 'time_window_sec' must be a positive integer")


def load_rules(rules_dir: str) -> list[Rule]:
    """Load and validate all YAML rule files from *rules_dir*."""
    rules: list[Rule] = []
    rules_path = Path(rules_dir)
    if not rules_path.is_dir():
        logger.warning("Rules directory '%s' does not exist or is not a directory.", rules_dir)
        return rules

    for yml_file in sorted(rules_path.glob("*.yml")):
        try:
            with yml_file.open("r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                logger.error("Skipping '%s': expected a YAML mapping at top level.", yml_file)
                continue
            _validate(data, str(yml_file))
            rule = Rule(
                name=data["name"],
                type=data["type"],
                severity=data["severity"],
                conditions=data["conditions"],
                time_window_sec=int(data["time_window_sec"]),
                threshold=int(data.get("threshold", 1)),
                description=data.get("description", ""),
                tags=data.get("tags", []),
            )
            rules.append(rule)
            logger.debug("Loaded rule '%s' from '%s'.", rule.name, yml_file)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load rule '%s': %s", yml_file, exc)

    logger.info("Loaded %d rule(s) from '%s'.", len(rules), rules_dir)
    return rules
