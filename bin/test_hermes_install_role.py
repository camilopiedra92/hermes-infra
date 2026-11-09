"""The install tasks of hermes_gateway: pinned, verified, idempotent, and the window always closes."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
INSTALL = (ROLE / "tasks" / "install.yml").read_text(encoding="utf-8")
MAIN = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")


class InstallTaskTests(unittest.TestCase):
    def test_it_runs_only_when_asked_for(self) -> None:
        # `never` keeps it out of `--tags gateway`; `install` asks for it. Opening the window is a decision.
        self.assertRegex(MAIN, r"import_tasks: install\.yml\s*\n\s*tags: \[install, never\]")

    def test_the_installer_is_fetched_at_the_pinned_commit_and_checked_by_hash(self) -> None:
        self.assertIn("raw.githubusercontent.com/NousResearch/hermes-agent/{{ hermes_pins.commit }}/scripts/install.sh", INSTALL)
        self.assertIn("sha256:{{ hermes_pins.files['scripts/install.sh'] }}", INSTALL)
        self.assertNotRegex(INSTALL, r"(curl|wget)[^\n]*\|\s*(ba)?sh")
        self.assertNotIn("nousresearch.com/install.sh", INSTALL)

    def test_the_installer_runs_as_the_service_user_from_a_clean_environment(self) -> None:
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        prefix = defaults.split("hermes_gateway_as_service_user:", 1)[1].split("hermes_gateway_cli:", 1)[0]
        for part in ("- sudo", "- -u", "- -H", "- env", "- -i", "HOME=", "HERMES_HOME=", "PATH="):
            self.assertIn(part, prefix)
        self.assertGreaterEqual(INSTALL.count("hermes_gateway_as_service_user"), 4)
        self.assertNotIn("PATH=", INSTALL)  # one definition, not five copies
        self.assertIn("--commit", INSTALL)
        self.assertIn("{{ hermes_pins.commit }}", INSTALL)
        self.assertIn("hermes_pins.install.flags", INSTALL)
        self.assertIn("{{ hermes_pins.state.owner }}", INSTALL)

    def test_the_extras_are_provisioned_from_the_pins(self) -> None:
        self.assertIn("hermes_pins.install.extras", INSTALL)
        self.assertIn("pm", INSTALL)
        self.assertIn("--extra", INSTALL)

    def test_the_result_is_verified_not_assumed(self) -> None:
        for needle in ("rev-parse", "hermes_pins.files['uv.lock']", "hermes_pins.files['pm/lock.json']", "doctor"):
            self.assertIn(needle, INSTALL)
        self.assertIn("ansible.builtin.assert", INSTALL)

    def test_the_installer_gets_a_parent_it_can_write_and_root_takes_it_back(self) -> None:
        # The installer replaces an empty destination with rmdir and moves its clone in, so it writes the parent.
        # /opt is shared: the destination is one level down, under a parent that is the service user's only while installing.
        install = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))["install"]
        self.assertNotEqual(install["code_parent"], "/opt")
        self.assertEqual(str(Path(install["code_dir"]).parent), install["code_parent"])
        give = INSTALL.index("Give the service user the parent")
        run = INSTALL.index("Run the installer as the service user")
        take = INSTALL.index("Take the parent of the code directory back")
        self.assertLess(give, run)
        self.assertLess(run, take)
        self.assertIn("hermes_pins.install.code_parent", INSTALL[give:run])
        self.assertIn("owner: root", INSTALL[take:])

    def test_the_check_runs_with_a_root_owned_opt_like_the_host(self) -> None:
        script = (ROOT / ".github" / "scripts" / "hermes-install-check.sh").read_text(encoding="utf-8")
        self.assertIn("chmod 0755 /opt", script)
        self.assertLess(script.index("chmod 0755 /opt"), script.index("play --tags managed"))

    def test_the_code_ends_root_owned_and_readable(self) -> None:
        self.assertIn("recurse: true", INSTALL)
        self.assertIn("owner: root", INSTALL)
        self.assertIn("go+rX,go-w", INSTALL)

    def test_the_window_is_required_only_when_there_is_something_to_install(self) -> None:
        self.assertIn("hermes-install-window status", INSTALL)
        self.assertRegex(INSTALL, r"Require the install window to be open[\s\S]{0,700}when:")

    def test_the_window_is_closed_whatever_happens(self) -> None:
        self.assertIn("always:", INSTALL)
        always = INSTALL.split("always:", 1)[1]
        self.assertIn("hermes-install-window close", always)

    def test_nothing_follows_a_moving_target_and_no_secret_is_used(self) -> None:
        low = INSTALL.lower()
        for word in ("--channel", "--branch", "latest", "token", "password", "api_key", "yolo"):
            self.assertNotIn(word, low)

    def test_the_gateway_is_not_started_here(self) -> None:
        for word in ("gateway install", "gateway start", "enable --now", "linger"):
            self.assertNotIn(word, INSTALL)


if __name__ == "__main__":
    unittest.main()
