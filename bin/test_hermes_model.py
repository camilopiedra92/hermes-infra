#!/usr/bin/env python3
"""The model path: the pinned CLI and plugin, the managed provider policy, and the owner's login helper."""

from __future__ import annotations

import json
import os
import pty
import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
G2 = PINS["egress"]
MODEL = PINS["model"]
TASKS = (ROLE / "tasks" / "model.yml").read_text(encoding="utf-8")
# What the tasks do, not what the comments say about what they avoid.
CODE = "\n".join(line for line in TASKS.splitlines() if not line.lstrip().startswith("#"))
MAIN = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
MANAGED = yaml.safe_load((ROLE / "files" / "managed-config.yaml").read_text(encoding="utf-8"))
BINARY = f"{MODEL['cli']['root']}/{MODEL['cli']['version']}/package/claude"


def render(name: str) -> str:
    text = (ROLE / "templates" / name).read_text(encoding="utf-8")
    values = {
        "ansible_managed": "managed",
        "hermes_pins.state.owner": PINS["state"]["owner"],
        "hermes_pins.model.claude_config_dir": MODEL["claude_config_dir"],
        "hermes_gateway_user_home": PINS["state"]["mount"].rsplit("/", 1)[0],
        "hermes_gateway_claude_binary": BINARY,
        "hermes_pins.egress.nft.proxy_address": G2["nft"]["proxy_address"],
        "hermes_pins.egress.nft.proxy_port": str(G2["nft"]["proxy_port"]),
    }
    for key, value in values.items():
        text = text.replace("{{ " + key + " }}", value)
    assert "{{" not in text, text
    return text


def version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


class PinTests(unittest.TestCase):
    def test_the_cli_is_pinned_by_version_and_hash_from_the_registry_over_https(self) -> None:
        cli = MODEL["cli"]
        self.assertRegex(cli["sha512"], r"^[0-9a-f]{128}$")
        self.assertTrue(cli["url"].startswith("https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/"))
        self.assertTrue(cli["url"].endswith(f"claude-code-linux-x64-{cli['version']}.tgz"))
        self.assertEqual(cli["package"], "@anthropic-ai/claude-code-linux-x64")

    def test_the_cli_is_new_enough_for_every_alias_the_routes_use(self) -> None:
        # The plugin README: haiku needs 2.1.293, sonnet 2.1.284, opus 2.1.280. An older CLI answers 400.
        self.assertGreaterEqual(version(MODEL["cli"]["version"]), (2, 1, 293))

    def test_the_plugin_is_one_immutable_commit_never_a_branch_or_a_tag(self) -> None:
        plugin = MODEL["plugin"]
        self.assertRegex(plugin["ref"], r"^[0-9a-f]{40}$")
        self.assertRegex(plugin["manifest_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn("main", plugin["identifier"].split("#")[0])
        self.assertTrue(plugin["identifier"].endswith("#" + plugin["repository_directory"]))
        # Hermes keeps the plugin under the name in its plugin.yaml, which is the provider name, not the folder's.
        self.assertEqual(plugin["install_name"], MODEL["provider"])

    def test_the_default_is_sonnet_5_5_written_out_at_medium_effort(self) -> None:
        # Owner decision, 2026-11-09. The canonical id, not the alias, so the choice reads as the choice.
        self.assertEqual(MODEL["default_model"], "claude-sonnet-5-5")
        self.assertEqual(MODEL["reasoning_effort"], "medium")
        self.assertEqual(MODEL["provider"], "claude-subscription-directsdk-experimental")


class QualificationTests(unittest.TestCase):
    def test_the_install_job_runs_the_plugins_evals_on_the_deployed_binary_and_files(self) -> None:
        script = (ROOT / ".github" / "scripts" / "hermes-install-check.sh").read_text(encoding="utf-8")
        for name in ("evals/directsdk_admission.py", "evals/directsdk_cache_wire.py"):
            self.assertIn(name, script)
        # The binary is the one the role deployed (CLAUDE_BIN, root-owned), and the files are the verified plugin directory.
        self.assertIn('"$PLUGIN_DIR/$eval" "$CLAUDE_BIN"', script)
        # They run after the model tasks installed and verified the plugin, never before.
        self.assertLess(script.index("play --tags model"), script.index("evals/directsdk_admission.py"))
        self.assertIn("|| fail", script[script.index("evals/directsdk_admission.py") :])


class ManagedPolicyTests(unittest.TestCase):
    def test_the_provider_policy_is_managed_and_equals_the_pins(self) -> None:
        self.assertEqual(MANAGED["model"], {"provider": MODEL["provider"], "default": MODEL["default_model"]})
        self.assertIs(MANAGED["auth"]["adopt_external_logins"], False)
        self.assertIs(MANAGED["updates"]["check"], False)
        self.assertIs(MANAGED["plugins"]["auto_apply"], False)
        settings = MANAGED["plugins"]["entries"][MODEL["provider"]]["settings"]
        self.assertEqual(settings["claude_config_dir"], MODEL["claude_config_dir"])
        self.assertIs(settings["claude_code_telemetry"], False)
        self.assertEqual(MANAGED["providers"][MODEL["provider"]]["stale_timeout_seconds"], MODEL["stale_timeout_seconds"])

    def test_the_effort_is_a_preference_and_is_not_pinned_so_the_owner_can_change_it_from_the_chat(self) -> None:
        # Owner decision, 2026-11-09. Policy is pinned in the repository (provider, allowlist, network, tools). A preference is not:
        # a locked effort would need a pull request for a command the owner can type, and the lock protects against nothing, because
        # only the owner can write to the chat. The default is Hermes' own medium, which the install job checks.
        self.assertNotIn("reasoning_effort", MANAGED["agent"])
        self.assertNotIn("reasoning_overrides", MANAGED["agent"])
        self.assertEqual(MODEL["reasoning_effort"], "medium", "the value the install job expects Hermes to resolve")

    def test_the_context_window_is_not_capped_the_owner_kept_the_plugins_one_million(self) -> None:
        # Owner decision, 2026-11-09. The plugin's pinned catalog declares 1,000,000 for Sonnet 5.5 and Hermes reads it from there.
        text = (ROLE / "files" / "managed-config.yaml").read_text(encoding="utf-8")
        self.assertNotIn("context_length", text)

    def test_the_stale_timeout_is_finite_and_above_a_long_healthy_turn(self) -> None:
        self.assertGreaterEqual(MODEL["stale_timeout_seconds"], 600)
        self.assertLessEqual(MODEL["stale_timeout_seconds"], 3600)

    def test_no_other_provider_and_no_api_credential_is_named_anywhere_in_the_policy(self) -> None:
        text = (ROLE / "files" / "managed-config.yaml").read_text(encoding="utf-8")
        for word in ("openrouter", "ANTHROPIC_API_KEY", "api_key", "base_url", "fallback_model"):
            self.assertNotIn(word, text, word)

    def test_the_config_directory_is_outside_the_state_volume_so_backups_never_hold_the_login(self) -> None:
        self.assertFalse(MODEL["claude_config_dir"].startswith(PINS["state"]["mount"]))
        self.assertEqual(os.path.dirname(MODEL["claude_config_dir"]), PINS["state"]["mount"].rsplit("/", 1)[0])


class TaskTests(unittest.TestCase):
    def test_it_runs_only_when_asked_for(self) -> None:
        self.assertRegex(MAIN, r"import_tasks: model\.yml\s*\n\s*tags: \[model, never\]")

    def test_the_cli_is_downloaded_by_root_checked_against_the_pinned_hash_and_unpacked_root_owned(self) -> None:
        self.assertIn('checksum: "sha512:{{ hermes_pins.model.cli.sha512 }}"', TASKS)
        self.assertIn("url: \"{{ hermes_pins.model.cli.url }}\"", TASKS)
        unpack = TASKS[TASKS.index("Unpack the CLI") : TASKS.index("Ask the CLI for its version")]
        self.assertIn("owner: root", unpack)
        self.assertIn("group: root", unpack)

    def test_no_install_script_and_no_package_manager_runs_for_the_cli(self) -> None:
        for word in ("npm ", "npx", "postinstall", "install.cjs", "curl ", "| sh", "pip "):
            self.assertNotIn(word, CODE, word)

    def test_the_plugin_is_installed_by_hermes_at_the_pinned_commit_and_verified_by_manifest(self) -> None:
        self.assertIn("hermes_pins.model.plugin.identifier", TASKS)
        self.assertIn("'--ref', hermes_pins.model.plugin.ref", TASKS)
        self.assertIn("'--no-enable'", TASKS)
        self.assertIn("hermes_pins.model.plugin.manifest_sha256", TASKS)
        self.assertLess(TASKS.index("Let Hermes install the plugin"), TASKS.index("Require the pinned files and nothing else"))

    def test_the_window_is_required_only_when_there_is_something_to_install_and_always_closed(self) -> None:
        self.assertIn("hermes_gateway_needs_plugin", TASKS)
        self.assertRegex(TASKS, r"always:\s*\n\s*- name: Close the install window")

    def test_nothing_logs_in_starts_the_gateway_or_names_an_api_key(self) -> None:
        for word in ("auth login", "gateway', 'start", "gateway', 'run", "state: started", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
            self.assertNotIn(word, CODE, word)

    def test_the_login_directory_is_the_service_users_and_private(self) -> None:
        block = TASKS[TASKS.index("Create the Claude login directory") : TASKS.index("Pin the model path")]
        self.assertIn("claude_config_dir", block)
        self.assertIn('mode: "0700"', block)
        self.assertIn("state.owner", block)


class DropInTests(unittest.TestCase):
    def test_the_gateway_names_the_binary_and_cannot_update_it_and_leaves_no_core_dump(self) -> None:
        text = render("gateway-model.conf.j2")
        self.assertIn(f'"CLAUDE_SUBSCRIPTION_DIRECTSDK_COMMAND={BINARY}"', text)
        self.assertIn('"DISABLE_AUTOUPDATER=1"', text)
        self.assertIn("LimitCORE=0", text)
        self.assertTrue(BINARY.startswith(MODEL["cli"]["root"]), "root-owned, outside every home")


class LoginHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, True))
        self.script = self.dir / "hermes-claude-login"
        self.script.write_text(render("hermes-claude-login.j2"), encoding="utf-8")
        self.script.chmod(0o755)
        self.stubs = self.dir / "bin"
        self.stubs.mkdir()
        self.log = self.dir / "runuser.args"
        (self.stubs / "runuser").write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{self.log}"\n')
        (self.stubs / "install").write_text("#!/bin/sh\nexit 0\n")
        for stub in self.stubs.iterdir():
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        self.env = {**os.environ, "PATH": f"{self.stubs}:{os.environ['PATH']}", "TERM": "xterm-256color"}

    def run_tty(self, *args: str) -> int:
        pid, fd = pty.fork()
        if pid == 0:
            os.execve(str(self.script), [str(self.script), *args], self.env)
        while True:
            try:
                if not os.read(fd, 4096):
                    break
            except OSError:
                break
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])

    def test_it_is_valid_bash(self) -> None:
        self.assertEqual(subprocess.run(["bash", "-n", str(self.script)], check=False).returncode, 0)

    def test_it_refuses_an_unknown_action_extra_arguments_and_a_missing_terminal(self) -> None:
        self.assertEqual(self.run_tty("token"), 2)
        self.assertEqual(self.run_tty("login", "extra"), 2)
        # No terminal: a pasted code needs one, and a pipe or a script is not for it.
        done = subprocess.run([str(self.script)], env=self.env, capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False)
        self.assertEqual(done.returncode, 2)
        self.assertIn("terminal", done.stderr)
        self.assertFalse(self.log.exists(), "nothing ran as the service user")

    def test_it_runs_the_pinned_cli_as_the_service_user_from_a_clean_environment_through_the_proxy(self) -> None:
        self.assertEqual(self.run_tty(), 0)
        args = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(args[:4], ["-u", PINS["state"]["owner"], "--", "env"])
        self.assertIn("-i", args)
        self.assertIn(f"CLAUDE_CONFIG_DIR={MODEL['claude_config_dir']}", args)
        self.assertIn(f"HTTPS_PROXY=http://{G2['nft']['proxy_address']}:{G2['nft']['proxy_port']}", args)
        self.assertIn("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", args)
        self.assertEqual(args[-3:], [BINARY, "auth", "login"])

    def test_status_and_logout_are_the_other_two_actions(self) -> None:
        for action in ("status", "logout"):
            self.assertEqual(self.run_tty(action), 0)
            self.assertEqual(self.log.read_text(encoding="utf-8").splitlines()[-2:], ["auth", action])

    def test_no_credential_or_api_key_is_read_set_or_passed(self) -> None:
        text = self.script.read_text(encoding="utf-8")
        for word in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", ".credentials", "cat ", "cp ", "base64"):
            self.assertNotIn(word, text, word)
        self.assertEqual(len(re.findall(r"\bauth\b", text)), 2)


if __name__ == "__main__":
    unittest.main()
