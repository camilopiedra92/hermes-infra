#!/usr/bin/env python3
"""The briefing the admin bot reads stays small, safe to ship and consistent with the pins."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
BRIEFING = (ROLE / "files" / "briefing.md").read_text(encoding="utf-8")
FLAT = " ".join(BRIEFING.split())
TASKS = (ROLE / "tasks" / "briefing.yml").read_text(encoding="utf-8")
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))


class BriefingTests(unittest.TestCase):
    def test_it_is_small_because_it_travels_with_every_conversation(self) -> None:
        self.assertLess(len(BRIEFING), 12_000)

    def test_it_is_plain_ascii_so_no_invisible_character_can_hide_in_it(self) -> None:
        bad = [c for c in BRIEFING if ord(c) > 126 or (ord(c) < 32 and c not in "\n")]
        self.assertEqual(bad, [])

    def test_it_holds_no_secret_and_no_identifier_of_a_person_or_a_key(self) -> None:
        for pattern in (r"\d{6,12}:[A-Za-z0-9_-]{30,}", r"tskey-", r"sk-ant-", r"SHA256:[A-Za-z0-9+/]{20,}", r"\b\d{9,}\b"):
            self.assertIsNone(re.search(pattern, BRIEFING), pattern)

    def test_the_documents_it_points_to_exist(self) -> None:
        for path in re.findall(r"`((?:docs|bin|infra)/[A-Za-z0-9_./-]+|AGENTS\.md)`", BRIEFING):
            self.assertTrue((ROOT / path).exists(), path)

    def test_the_facts_it_states_match_the_pins(self) -> None:
        self.assertIn(f"Hermes Agent {PINS['tag']}", BRIEFING)
        self.assertIn(f"Claude Code CLI ({PINS['model']['cli']['version']})", BRIEFING)
        self.assertIn(f"`claude-subscription-directsdk` {PINS['model']['plugin']['version']}", BRIEFING)
        self.assertIn(f"127.0.0.1:{PINS['egress']['nft']['proxy_port']}", BRIEFING)
        for name in PINS["egress"]["domains"]:
            self.assertIn(name, BRIEFING)

    def test_it_keeps_the_rules_that_must_never_be_lost(self) -> None:
        for rule in ("never destroyed, rebuilt or resized", "No secret in git", "Never set `approvals.mode: off`", "Zero additional cost"):
            self.assertIn(rule, FLAT)

    def test_it_is_installed_root_owned_as_the_context_file_hermes_reads(self) -> None:
        self.assertIn("src: briefing.md", TASKS)
        self.assertIn('dest: "{{ hermes_pins.install.hermes_home }}/AGENTS.md"', TASKS)
        self.assertIn("owner: root", TASKS)
        self.assertIn('mode: "0644"', TASKS)
        # Not named AGENTS.md here: an agent working in a checkout would discover it as its own context.
        self.assertFalse((ROLE / "files" / "AGENTS.md").exists())


if __name__ == "__main__":
    unittest.main()
