"""The sudo I/O log volume must absorb a burst of automation between two prunes."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "access"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
TIMER = (ROLE / "templates" / "hermes-sudo-io-prune.timer.j2").read_text(encoding="utf-8")

MIB = 1024 * 1024
# Measured on the host on 2026-11-08: 476 MB in 3,017 sessions, so about 160 KB each. Every sudo call
# leaves several small files, and an Ansible run is one sudo call per task. A full apply sustained
# about one session per second.
SESSION_KB = 160
SESSIONS_PER_SECOND = 1
SAFETY = 3


class SudoIoBudgetTests(unittest.TestCase):
    def test_the_slack_above_the_prune_ceiling_absorbs_a_burst_with_margin(self) -> None:
        capacity_mb = DEFAULTS["access_iolog_bytes"] // MIB
        slack_mb = capacity_mb - DEFAULTS["access_io_max_mb"]
        interval = DEFAULTS["access_io_prune_interval_minutes"]
        burst_mb = interval * 60 * SESSIONS_PER_SECOND * SESSION_KB / 1024
        self.assertGreaterEqual(slack_mb, SAFETY * burst_mb, f"slack {slack_mb} MB, burst {burst_mb:.0f} MB")

    def test_the_timer_uses_the_interval_and_is_not_hourly(self) -> None:
        self.assertIn("access_io_prune_interval_minutes", TIMER)
        self.assertNotIn("OnCalendar=hourly", TIMER)
        self.assertIn("Persistent=true", TIMER)

    def test_the_retention_is_unchanged(self) -> None:
        # Only the size ceiling and the cadence move. Sessions older than 30 days still go.
        self.assertEqual(DEFAULTS["access_io_retention_days"], 30)

    def test_the_ceiling_leaves_the_image_a_real_reserve(self) -> None:
        self.assertLess(DEFAULTS["access_io_max_mb"], DEFAULTS["access_iolog_bytes"] // MIB)
        self.assertGreaterEqual(DEFAULTS["access_io_max_mb"], 200)  # a floor, so the log stays useful


if __name__ == "__main__":
    unittest.main()
