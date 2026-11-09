"""The Hermes pin is a commit and the hashes of the files the installer trusts."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))


class HermesPinTests(unittest.TestCase):
    def test_the_commit_is_a_full_sha_and_the_tag_is_not_a_branch(self) -> None:
        self.assertRegex(PINS["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(PINS["tag"], r"^v\d+\.\d+\.\d+$")

    def test_every_trusted_file_has_a_sha256(self) -> None:
        self.assertEqual(
            set(PINS["files"]), {"scripts/install.sh", "uv.lock", "pm/lock.json", "pyproject.toml"}
        )
        for name, digest in PINS["files"].items():
            self.assertRegex(digest, r"^[0-9a-f]{64}$", name)

    def test_the_install_never_follows_a_moving_channel_or_pulls_a_browser(self) -> None:
        flags = PINS["install"]["flags"]
        self.assertIn("--non-interactive", flags)
        self.assertIn("--skip-browser", flags)
        self.assertIn("--skip-computer-use", flags)
        self.assertFalse([flag for flag in flags if flag.startswith("--channel") or flag.startswith("--branch")])

    def test_the_messaging_extra_is_installed_explicitly(self) -> None:
        # Hermes leaves Telegram out of the default install and adds it on first use. With
        # security.allow_lazy_installs false it would never arrive, so it is provisioned once,
        # inside the install window, from the lock.
        self.assertEqual(PINS["install"]["extras"], ["telegram"])
        self.assertEqual(PINS["install"]["extra_libraries"], ["python-telegram-bot"])
        script = (ROOT / ".github" / "scripts" / "hermes-install-check.sh").read_text(encoding="utf-8")
        role = (ROOT / "infra" / "ansible" / "roles" / "hermes_gateway" / "tasks" / "install.yml").read_text(encoding="utf-8")
        self.assertIn("'pm', 'install', '--extra'", role)
        self.assertIn("hermes_pins.install.extras", role)
        self.assertIn("python-telegram-bot", script)  # CI fails if Hermes still reports it missing

    def test_the_workflow_uses_the_pin_and_no_unpinned_installer(self) -> None:
        text = (ROOT / ".github" / "workflows" / "hermes-install.yml").read_text(encoding="utf-8")
        self.assertIn("bin/hermes/pins.json", text)
        self.assertNotRegex(text, r"curl[^\n]*\|\s*(ba)?sh")
        self.assertNotIn("hermes-agent.nousresearch.com/install.sh", text)


if __name__ == "__main__":
    unittest.main()
