"""The administration channel of the Hermes bot: the account, the sudo policy, sshd and the switch."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "bot_admin"
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
G2 = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))["egress"]
ADMIN = PINS["admin"]
TASKS = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
SWITCH = ROLE / "files" / "hermes-admin-channel"


def render(name: str) -> str:
    text = (ROLE / "templates" / name).read_text(encoding="utf-8")
    values = {"ansible_managed": "managed", "hermes_pins.admin.user": ADMIN["user"], "hermes_pins.admin.host": ADMIN["host"],
              "hermes_pins.admin.port": str(ADMIN["port"]), "hermes_pins.admin.key": ADMIN["key"],
              "hermes_pins.state.mount | dirname": "/home/hermes",
              "bot_admin_sudo_logfile": "/var/log/sudo-hermesops.log"}
    for key, value in values.items():
        text = text.replace("{{ " + key + " }}", value)
    assert "{{" not in text, text
    return text


class PinTests(unittest.TestCase):
    def test_the_account_is_not_the_operator_and_not_the_service_user(self) -> None:
        self.assertEqual(ADMIN["user"], "hermesadmin")
        self.assertNotIn(ADMIN["uid"], (1000, PINS["state"].get("uid", 1001), 1001))
        self.assertEqual(ADMIN["host"], "127.0.0.1")

    def test_the_firewall_opens_exactly_the_port_of_the_pin(self) -> None:
        self.assertEqual(G2["nft"]["admin_port"], ADMIN["port"])

    def test_the_key_lives_in_the_service_user_home_and_is_not_in_git(self) -> None:
        self.assertTrue(ADMIN["key"].startswith("/home/hermes/.ssh/"))
        for path in ROLE.rglob("*"):
            if path.is_file():
                self.assertNotIn("PRIVATE KEY", path.read_text(encoding="utf-8"), str(path))


class SudoPolicyTests(unittest.TestCase):
    def test_the_policy_logs_commands_as_text_and_leaves_terminal_io_to_hermes(self) -> None:
        text = render("92-hermesadmin.j2")
        for needle in ("use_pty", "log_subcmds", "!log_input", "!log_output",
                       "logfile=/var/log/sudo-hermesops.log", "hermesadmin ALL=(ALL:ALL) NOPASSWD: ALL"):
            self.assertIn(needle, text)

    @unittest.skipUnless(Path("/usr/sbin/visudo").exists() and os.geteuid() == 0, "needs visudo and root")
    def test_visudo_accepts_the_policy(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".sudoers") as handle:
            handle.write(render("92-hermesadmin.j2"))
            handle.flush()
            os.chmod(handle.name, 0o440)
            subprocess.run(["/usr/sbin/visudo", "-cf", handle.name], check=True, capture_output=True)

    def test_the_sudoers_file_is_validated_before_it_is_installed(self) -> None:
        self.assertIn("validate: /usr/sbin/visudo -cf %s", TASKS)
        self.assertIn('mode: "0440"', TASKS)


class SshTests(unittest.TestCase):
    def test_sshd_accepts_the_account_from_loopback_only(self) -> None:
        text = render("sshd-hermesadmin.conf.j2")
        self.assertIn("AllowUsers hermesadmin@127.0.0.1", text)
        self.assertNotIn("Match", text)
        self.assertIn("validate: /usr/sbin/sshd -t -f %s", TASKS)

    def test_the_authorized_key_is_restricted(self) -> None:
        for needle in ('from="{{ hermes_pins.admin.host }}"', "no-agent-forwarding", "no-port-forwarding", "no-X11-forwarding"):
            self.assertIn(needle, TASKS)

    def test_the_private_key_mode_is_stated_not_left_to_the_umask(self) -> None:
        self.assertRegex(TASKS, r'path: "\{\{ hermes_pins.admin.key \}\}"\n\s+owner: .*\n\s+group: .*\n\s+mode: "0600"')

    def test_the_account_has_no_password(self) -> None:
        self.assertIn("password_lock: true", TASKS)

    def test_the_host_key_is_pinned_and_a_change_is_refused(self) -> None:
        self.assertIn("StrictHostKeyChecking yes", render("ssh-config.j2"))
        self.assertIn("known_hosts", TASKS)

    def test_the_key_is_made_by_the_service_user_and_only_once(self) -> None:
        self.assertIn("creates:", TASKS)
        self.assertIn("runuser", TASKS)
        self.assertIn("ed25519", TASKS)


class SwitchTests(unittest.TestCase):
    def run_switch(self, root: Path, *args: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "HERMES_ADMIN_ROOT": str(root), "HERMES_ADMIN_ACCOUNT": "hermesadmin"}
        return subprocess.run([str(SWITCH), *args], env=env, text=True, capture_output=True)

    def make_root(self) -> tuple[tempfile.TemporaryDirectory[str], Path, Path]:
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        keys = root / "home/hermesadmin/.ssh/authorized_keys"
        keys.parent.mkdir(parents=True)
        keys.write_text('from="127.0.0.1" ssh-ed25519 AAAA test\n', encoding="utf-8")
        return tmp, root, keys

    def test_off_moves_the_key_aside_and_on_puts_it_back_unchanged(self) -> None:
        tmp, root, keys = self.make_root()
        with tmp:
            before = keys.read_text(encoding="utf-8")
            self.assertIn("admin channel: on", self.run_switch(root, "status").stdout)
            self.assertEqual(self.run_switch(root, "off").returncode, 0)
            self.assertFalse(keys.exists())
            off_file = root / "var/lib/hermes/admin-authorized_keys.off"
            self.assertEqual(oct(off_file.stat().st_mode & 0o777), "0o600")
            self.assertIn("admin channel: off", self.run_switch(root, "status").stdout)
            self.assertEqual(self.run_switch(root, "on").returncode, 0)
            self.assertEqual(keys.read_text(encoding="utf-8"), before)
            self.assertFalse(off_file.exists())

    def test_off_twice_is_harmless_and_on_without_off_is_refused(self) -> None:
        tmp, root, _keys = self.make_root()
        with tmp:
            self.assertEqual(self.run_switch(root, "on").returncode, 1)
            self.assertEqual(self.run_switch(root, "off").returncode, 0)
            second = self.run_switch(root, "off")
            self.assertEqual(second.returncode, 0)
            self.assertIn("already off", second.stdout)

    def test_unknown_verbs_are_refused(self) -> None:
        tmp, root, _keys = self.make_root()
        with tmp:
            self.assertEqual(self.run_switch(root, "frobnicate").returncode, 2)

    def test_the_role_respects_a_channel_closed_by_hand(self) -> None:
        self.assertIn("admin-authorized_keys.off", (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        self.assertIn("not bot_admin_off.stat.exists", TASKS)


class GitCredentialTests(unittest.TestCase):
    HELPER = ROLE / "files" / "hermes-git-credential"

    def ask(self, token_file: Path, action: str, request: str) -> subprocess.CompletedProcess[str]:
        env = {**os.environ, "HERMES_GITHUB_TOKEN_FILE": str(token_file)}
        return subprocess.run([str(self.HELPER), action], input=request, text=True, capture_output=True, env=env)

    def test_it_answers_for_github_https_only_and_from_the_delivered_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "github-token"
            token.write_text("github_pat_canary\n", encoding="utf-8")
            ok = self.ask(token, "get", "protocol=https\nhost=github.com\npath=owner/repo\n\n")
            self.assertEqual(ok.stdout, "username=x-access-token\npassword=github_pat_canary\n")
            for request in ("protocol=https\nhost=example.com\n\n", "protocol=http\nhost=github.com\n\n",
                            "protocol=https\nhost=github.com.evil.test\n\n"):
                self.assertEqual(self.ask(token, "get", request).stdout, "", request)
            self.assertEqual(self.ask(token, "store", "protocol=https\nhost=github.com\n\n").stdout, "")
            self.assertEqual(self.ask(Path(tmp) / "absent", "get", "protocol=https\nhost=github.com\n\n").stdout, "")

    def test_the_token_is_never_written_by_the_role(self) -> None:
        config = render("gitconfig.j2")
        self.assertIn("helper = /usr/local/libexec/hermes-git-credential", config)
        self.assertNotRegex(config, r"github_pat_|ghp_|password|token\s*=")
        self.assertNotIn("github-token", TASKS.replace(".config/hermes/github-token", "").replace("GITHUB_TOKEN", ""))


class RoleTests(unittest.TestCase):
    def test_the_tasks_parse_and_the_role_runs_after_the_sandbox_role_that_creates_the_service_user(self) -> None:
        yaml.safe_load(TASKS)
        site = yaml.safe_load((ROOT / "infra" / "ansible" / "site.yml").read_text(encoding="utf-8"))
        roles = [r["role"] for r in site[0]["roles"]]
        self.assertLess(roles.index("service_user"), roles.index("bot_admin"))
        self.assertLess(roles.index("access"), roles.index("bot_admin"))


if __name__ == "__main__":
    unittest.main()
