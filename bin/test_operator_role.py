"""The root access of the Hermes admin bot: the sudo policy and the switch that takes it away."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "operator"
TASKS = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
SWITCH = ROLE / "files" / "hermes-admin-access"


def render(user: str = "hermes") -> str:
    text = (ROLE / "templates" / "92-hermes-operator.j2").read_text(encoding="utf-8")
    for key, value in {"ansible_managed": "managed", "operator_user": user,
                       "operator_sudo_logfile": "/var/log/sudo-hermesops.log"}.items():
        text = text.replace("{{ " + key + " }}", value)
    assert "{{" not in text, text
    return text


class PolicyTests(unittest.TestCase):
    def test_the_policy_logs_commands_as_text_and_leaves_terminal_io_to_hermes(self) -> None:
        text = render()
        for needle in ("use_pty", "log_subcmds", "!log_input", "!log_output",
                       "logfile=/var/log/sudo-hermesops.log", "hermes ALL=(ALL:ALL) NOPASSWD: ALL"):
            self.assertIn(needle, text)

    @unittest.skipUnless(Path("/usr/sbin/visudo").exists() and os.geteuid() == 0, "needs visudo and root")
    def test_visudo_accepts_the_policy(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".sudoers") as handle:
            handle.write(render())
            handle.flush()
            os.chmod(handle.name, 0o440)
            subprocess.run(["/usr/sbin/visudo", "-cf", handle.name], check=True, capture_output=True)

    def test_the_sudoers_file_is_validated_before_it_is_installed(self) -> None:
        self.assertIn("validate: /usr/sbin/visudo -cf %s", TASKS)
        self.assertIn('mode: "0440"', TASKS)

    def test_the_account_is_the_service_user_not_a_second_account(self) -> None:
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("operator_user: \"{{ hermes_pins.state.owner }}\"", defaults)

    def test_the_role_never_writes_the_github_token(self) -> None:
        self.assertNotRegex(TASKS.replace("GITHUB_TOKEN", ""), r"github-token|content:.*token")


class SwitchTests(unittest.TestCase):
    def run_switch(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "HERMES_ADMIN_ROOT": str(root), "HERMES_ADMIN_ACCOUNT": "hermes"}
        return subprocess.run([str(SWITCH), *args], env=env, text=True, capture_output=True)

    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        rule = root / "etc/sudoers.d/92-hermes-operator"
        rule.parent.mkdir(parents=True)
        rule.write_text(render(), encoding="utf-8")
        return tmp, root, rule

    def test_off_moves_the_rule_aside_and_on_puts_it_back_unchanged(self) -> None:
        tmp, root, rule = self.make_root()
        with tmp:
            before = rule.read_text(encoding="utf-8")
            self.assertIn("admin access: on", self.run_switch(root, "status").stdout)
            self.assertEqual(self.run_switch(root, "off").returncode, 0)
            self.assertFalse(rule.exists())
            off_file = root / "var/lib/hermes/operator-sudoers.off"
            self.assertEqual(oct(off_file.stat().st_mode & 0o777), "0o600")
            self.assertIn("admin access: off", self.run_switch(root, "status").stdout)
            self.assertEqual(self.run_switch(root, "on").returncode, 0)
            self.assertEqual(rule.read_text(encoding="utf-8"), before)
            self.assertEqual(oct(rule.stat().st_mode & 0o777), "0o440")
            self.assertFalse(off_file.exists())

    def test_off_twice_is_harmless_and_on_without_off_is_refused(self) -> None:
        tmp, root, _rule = self.make_root()
        with tmp:
            self.assertEqual(self.run_switch(root, "on").returncode, 1)
            self.assertEqual(self.run_switch(root, "off").returncode, 0)
            second = self.run_switch(root, "off")
            self.assertEqual(second.returncode, 0)
            self.assertIn("already off", second.stdout)

    def test_unknown_verbs_are_refused(self) -> None:
        tmp, root, _rule = self.make_root()
        with tmp:
            self.assertEqual(self.run_switch(root, "frobnicate").returncode, 2)

    def test_the_role_respects_root_closed_by_hand(self) -> None:
        self.assertIn("operator-sudoers.off", (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        self.assertIn("when: not operator_off.stat.exists", TASKS)
        self.assertIn("when: operator_off.stat.exists", TASKS)


class RoleTests(unittest.TestCase):
    def test_the_tasks_parse_and_the_role_runs_after_the_roles_that_create_the_account(self) -> None:
        yaml.safe_load(TASKS)
        site = yaml.safe_load((ROOT / "infra" / "ansible" / "site.yml").read_text(encoding="utf-8"))
        roles = [r["role"] for r in site[0]["roles"]]
        self.assertLess(roles.index("service_user"), roles.index("operator"))
        self.assertLess(roles.index("access"), roles.index("operator"))


if __name__ == "__main__":
    unittest.main()
