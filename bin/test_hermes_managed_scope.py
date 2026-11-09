"""Hermes Managed Scope: the keys an attacker with the service user must not be able to change."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
CONFIG = yaml.safe_load((ROLE / "files" / "managed-config.yaml").read_text(encoding="utf-8"))
ENV = (ROLE / "templates" / "managed.env.j2").read_text(encoding="utf-8")

PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
# Everything that reaches the network or acts on its own and is still off. The owner enabled terminal, file and
# cronjob for the bot on 2026-11-09: they run on the host as the administrator account.
DANGEROUS = {
    "code_execution", "browser", "web", "search", "delegation",
    "computer_use", "image_gen", "video_gen", "tts", "kanban", "connections", "catalog",
}
ENABLED_FOR_THE_ADMIN_BOT = {"terminal", "file", "cronjob", "skills"}


class ManagedConfigTests(unittest.TestCase):
    def test_lazy_installs_telemetry_and_the_keyless_web_ring_are_off(self) -> None:
        self.assertIs(CONFIG["security"]["allow_lazy_installs"], False)
        self.assertIs(CONFIG["telemetry"]["shared_metrics"]["enabled"], False)
        self.assertIs(CONFIG["telemetry"]["shared_metrics"]["send"], False)
        self.assertIs(CONFIG["web"]["keyless_fallback"], False)
        self.assertIs(CONFIG["web"]["keyless_rescue"], False)

    def test_the_gateway_restarts_when_its_event_loop_stalls(self) -> None:
        self.assertEqual(CONFIG["gateway"]["systemd_watchdog_seconds"], 120)

    def test_telegram_gets_an_allowlist_and_only_the_adr_0029_tools_can_act(self) -> None:
        allowed = set(CONFIG["platform_toolsets"]["telegram"])
        self.assertEqual(allowed, {"clarify", "memory", "session_search", "todo"} | ENABLED_FOR_THE_ADMIN_BOT)
        self.assertFalse(allowed & DANGEROUS)

    def test_the_denylist_removes_every_other_dangerous_toolset_as_a_second_belt(self) -> None:
        disabled = set(CONFIG["agent"]["disabled_toolsets"])
        self.assertGreaterEqual(disabled, DANGEROUS)
        self.assertFalse(disabled & ENABLED_FOR_THE_ADMIN_BOT, "a toolset cannot be both allowed and removed")

    def test_skills_are_scanned_on_every_write(self) -> None:
        self.assertIs(CONFIG["skills"]["guard_agent_created"], True)
        self.assertIs(CONFIG["skills"]["write_approval"], False)  # the owner wants the bot to learn by itself; revisit with untrusted inputs

    def test_commands_run_as_the_administrator_account_over_loopback_ssh_and_never_locally(self) -> None:
        admin = PINS["admin"]
        terminal = CONFIG["terminal"]
        self.assertEqual(terminal["backend"], "ssh")
        self.assertEqual(terminal["ssh_user"], admin["user"])
        self.assertEqual(terminal["ssh_key"], admin["key"])
        self.assertEqual(terminal["ssh_port"], admin["port"])
        self.assertEqual(terminal["cwd"], admin["home"])
        # The alias resolves to the pinned address and pins the host key (role bot_admin, templates/ssh-config.j2).
        self.assertEqual(terminal["ssh_host"], "hermes-admin")
        alias = (ROOT / "infra/ansible/roles/bot_admin/templates/ssh-config.j2").read_text(encoding="utf-8")
        self.assertIn("Host " + terminal["ssh_host"], alias)

    def test_approvals_are_manual_and_never_loosened(self) -> None:
        # Values only: the comments say "never yolo" and are allowed to.
        text = yaml.safe_dump(CONFIG).lower()
        self.assertNotIn("yolo", text)
        self.assertNotIn("mode: off", text)
        approvals = CONFIG["approvals"]
        self.assertEqual(approvals["mode"], "manual")
        for key in ("cron_mode", "single_query_mode", "unattended_mode"):
            self.assertEqual(approvals[key], "deny", key)

    def test_the_deny_rules_protect_the_owners_way_back_in(self) -> None:
        deny = " ".join(CONFIG["approvals"]["deny"])
        for needle in ("nft flush", "tailscaled", "systemctl stop ssh", "hermesops", "git push*--force"):
            self.assertIn(needle, deny)
        for pattern in CONFIG["approvals"]["deny"]:
            self.assertNotIn("hermes-admin-channel", pattern)  # the owner's switch must stay usable

    def test_no_secret_and_no_user_id_is_in_the_file(self) -> None:
        # Keys and values only: the comments are allowed to explain.
        text = yaml.safe_dump(CONFIG).lower()
        for word in ("token", "api_key", "password", "secret", "allowed_users"):
            self.assertNotIn(word, text)


class ManagedEnvTests(unittest.TestCase):
    def test_telegram_cannot_discover_other_addresses(self) -> None:
        self.assertIn("HERMES_TELEGRAM_DISABLE_FALLBACK_IPS=true", ENV)

    def test_the_environment_always_carries_an_allowlist_and_never_depends_on_a_variable_being_remembered(self) -> None:
        # 2026-11-08: `--tags gateway` ran this file without the variable (the role carries that tag) and the line was
        # removed. The template has no condition now: the value is decided by the tasks, which keep the one on the host.
        self.assertIn("TELEGRAM_ALLOWED_USERS={{ hermes_gateway_allowed_users_effective }}", ENV)
        self.assertNotIn("is defined", ENV)
        self.assertNotIn("{% if", ENV)

    def test_without_the_variable_the_allowlist_on_the_host_is_kept_and_with_neither_nothing_is_written(self) -> None:
        tasks = (ROLE / "tasks" / "managed.yml").read_text(encoding="utf-8")
        self.assertIn("src: /etc/hermes/.env", tasks)
        self.assertIn("hermes_gateway_telegram_allowed_users | default(", tasks)
        self.assertIn("TELEGRAM_ALLOWED_USERS=([0-9,]+)", tasks)
        refuse = tasks.index("Refuse to write a managed environment with no allowed Telegram user")
        install = tasks.index("Install the managed environment")
        self.assertLess(refuse, install, "the check comes before the file is written")
        self.assertIn("is match('^[0-9]+(,[0-9]+)*$')", tasks)

    def test_no_secret_belongs_in_a_world_readable_file(self) -> None:
        names = [
            line.split("=", 1)[0]
            for line in ENV.splitlines()
            if "=" in line and not line.lstrip().startswith(("#", "{"))
        ]
        self.assertEqual(
            sorted(names), ["HERMES_TELEGRAM_DISABLE_FALLBACK_IPS", "TELEGRAM_ALLOWED_USERS", "TELEGRAM_PROXY"]
        )
        # The proxy is the local one: a loopback address and a port, with no user and no password in it.
        proxy = next(line for line in ENV.splitlines() if line.startswith("TELEGRAM_PROXY="))
        self.assertRegex(proxy, r"^TELEGRAM_PROXY=http://\{\{ hermes_pins\.egress\.nft\.proxy_address \}\}:\{\{ hermes_pins\.egress\.nft\.proxy_port \}\}$")


class RoleTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.managed = (ROLE / "tasks" / "managed.yml").read_text(encoding="utf-8")

    def test_the_managed_directory_is_root_owned_and_readable_by_the_service_user(self) -> None:
        self.assertIn("path: /etc/hermes", self.managed)
        self.assertEqual(self.managed.count('owner: root'), self.managed.count("group: root"))
        self.assertIn('mode: "0755"', self.managed)
        self.assertIn('mode: "0644"', self.managed)
        self.assertNotIn("hermes_pins.state.owner", self.managed)

    def test_the_managed_files_are_installed_from_the_repository(self) -> None:
        self.assertIn("managed-config.yaml", self.managed)
        self.assertIn("managed.env.j2", self.managed)


if __name__ == "__main__":
    unittest.main()
