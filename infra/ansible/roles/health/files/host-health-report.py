#!/usr/bin/env python3
"""Hermes cron job (no-agent mode): say something only when the host's health changes. Ansible managed.

Reads the status written by hermes-health. Prints nothing when nothing changed, which makes the tick silent.
A reminder is repeated once a day while a problem lasts. A stale status is itself a problem.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

STATUS = Path("/var/lib/hermes-health/status.json")
STATE = Path.home() / ".hermes" / "cron" / "host-health-state.json"
STALE = 20 * 60
REMIND = 24 * 3600


def main() -> None:
    now = time.time()
    try:
        status = json.loads(STATUS.read_text(encoding="utf-8"))
        problems = list(status["problems"])
        if now - status["time"] > STALE:
            problems.append("the health collector has not reported for over 20 minutes")
    except (OSError, ValueError, KeyError):
        problems = ["the health status cannot be read"]
    try:
        previous = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        previous = {"problems": [], "reported": 0}

    current, before = sorted(problems), sorted(previous["problems"])
    changed = current != before
    remind = bool(current) and now - previous["reported"] > REMIND
    if changed or remind:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps({"problems": current, "reported": now}), encoding="utf-8")
        if current:
            print("Host health: " + "; ".join(current))
        else:
            print("Host health: all clear again.")


if __name__ == "__main__":
    main()
