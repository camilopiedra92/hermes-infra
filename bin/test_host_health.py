#!/usr/bin/env python3
"""Tests for the read-only host health check."""

from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_health():
    path = ROOT / "bin" / "host-health.py"
    spec = importlib.util.spec_from_file_location("host_health", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


host_health = load_health()


RULES = """\
-w /etc/passwd -p wa -k hermes_identity
-w /etc/shadow -p wa -k hermes_identity
-w /etc/group -p wa -k hermes_identity
-w /etc/sudoers -p wa -k hermes_sudoers
-w /etc/sudoers.d -p wa -k hermes_sudoers
-w /etc/ssh/sshd_config -p wa -k hermes_sshd
-w /etc/ssh/sshd_config.d -p wa -k hermes_sshd
-w /home/hermesops/.ssh/authorized_keys -p wa -k hermes_authkeys
-w /etc/nftables.conf -p wa -k hermes_nftables
-w /etc/nftables.d -p wa -k hermes_nftables
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k hermes_execve
"""

HEALTHY = f"""\
auditd_active=active
auditd_rules_rc=0
auditd_rules_b64={base64.b64encode(RULES.encode()).decode()}
mount_options=rw,nosuid,nodev,noexec,relatime
mount_source=/dev/loop3
image_mode=600
image_uid=0
image_gid=0
image_kind=regular file
free_root_bytes=70000000000
free_iolog_bytes=400000000
pruner=active
proxy=active
proxy_listen=127.0.0.1:8888,
proxy_filter_sha={host_health.expected_filter_sha()}
proxy_rule=1
port_range=32768-60999
lo_foreign=
plugin_hash={host_health.HERMES_PINS["model"]["plugin"]["manifest_sha256"]}
admin_uid=1002
admin_sudoers=440
admin_keys=1
admin_off=0
admin_sshd=1
"""


class HostHealthTests(unittest.TestCase):
    def test_healthy_report_is_one_ok_line_per_check(self) -> None:
        lines = host_health.remote_lines(host_health.parse_fields(HEALTHY))
        lines.append(host_health.line(True, "tailnet policy"))
        self.assertEqual(len(lines), 17)
        self.assertTrue(all(item.startswith("ok ") for item in lines))
        self.assertIn("ok auditd rules 11", lines)
        self.assertIn("ok sudo-io mount nosuid,nodev,noexec,loop", lines)
        self.assertIn("ok sudo-io image 0600 root:root", lines)
        self.assertIn("ok sudo-io pruner timer active", lines)
        self.assertIn("ok admin channel on", lines)
        self.assertIn("ok sshd allows hermesadmin from 127.0.0.1 only", lines)
        self.assertIn("ok egress proxy active", lines)
        self.assertIn("ok egress proxy listens on 127.0.0.1:8888", lines)
        self.assertIn("ok egress allowlist matches the pins", lines)
        self.assertIn("ok egress rule for the proxy present", lines)

    def test_the_plugin_is_red_when_it_is_missing_or_its_files_differ_from_the_pin(self) -> None:
        fields = host_health.parse_fields(HEALTHY)
        fields["plugin_hash"] = "0" * 64
        self.assertIn("red model plugin files differ from the pinned commit", host_health.remote_lines(fields))
        fields["plugin_hash"] = ""
        self.assertIn("red model plugin is not installed", host_health.remote_lines(fields))

    def test_the_proxy_is_red_when_down_wide_open_changed_or_unruled(self) -> None:
        fields = host_health.parse_fields(HEALTHY)
        fields.update(
            proxy="inactive",
            proxy_listen="0.0.0.0:8888,",
            proxy_filter_sha="0" * 64,
            proxy_rule="0",
            port_range="1024-65535",
            lo_foreign="127.0.0.1:40000,",
        )
        lines = host_health.remote_lines(fields)
        for text in (
            "red loopback range for the service user matches the kernel's (1024-65535)",
            "red listener in the loopback range: 127.0.0.1:40000",
            "red egress proxy inactive",
            "red egress proxy listens on 0.0.0.0:8888",
            "red egress allowlist differs from the pins",
            "red egress rule for the proxy missing",
        ):
            self.assertIn(text, lines)

    def test_no_rules_output_is_red_and_a_failed_probe_is_red(self) -> None:
        minimum = host_health.minimum_audit_rules()
        self.assertGreaterEqual(minimum, 10)
        self.assertEqual(host_health.count_audit_rules("No rules\n"), 0)
        sample = "\n".join(
            [
                "-w /etc/passwd -p wa -k hermes_identity",
                "-w /etc/shadow -p wa -k hermes_identity",
                "-w /etc/group -p wa -k hermes_identity",
                "-w /etc/sudoers -p wa -k hermes_sudoers",
                "-w /etc/sudoers.d -p wa -k hermes_sudoers",
                "-w /etc/ssh/sshd_config -p wa -k hermes_sshd",
                "-w /etc/ssh/sshd_config.d -p wa -k hermes_sshd",
                "-w /home/hermesops/.ssh/authorized_keys -p wa -k hermes_authkeys",
                "-w /etc/nftables.conf -p wa -k hermes_nftables",
                "-w /etc/nftables.d -p wa -k hermes_nftables",
                "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k hermes_execve",
            ]
        )
        self.assertEqual(host_health.count_audit_rules(sample), 11)
        self.assertGreaterEqual(host_health.count_audit_rules(sample), minimum)
        none = host_health.audit_lines("No rules\n", 0)
        self.assertTrue(any(item.startswith("red auditd rules") for item in none))
        failed = host_health.audit_lines("", 1)
        self.assertTrue(any(item.startswith("red auditd rules") for item in failed))
        self.assertNotIn("grep -c", host_health.REMOTE)

    def test_the_admin_channel_reports_closed_by_hand_and_inconsistent_states(self) -> None:
        fields = host_health.parse_fields(HEALTHY)
        fields.update({"admin_keys": "0", "admin_off": "1"})
        self.assertIn("ok admin channel off (closed by hand)", host_health.remote_lines(fields))
        fields.update({"admin_keys": "1", "admin_off": "1"})
        self.assertIn("red admin channel inconsistent", host_health.remote_lines(fields))
        fields.update({"admin_keys": "1", "admin_off": "0", "admin_sshd": "0"})
        self.assertIn("red sshd does not restrict hermesadmin to 127.0.0.1", host_health.remote_lines(fields))
        fields.update({"admin_sudoers": ""})
        self.assertIn("red admin account or sudoers missing", host_health.remote_lines(fields))

    def test_red_lines_cover_mount_image_space_and_auditd(self) -> None:
        fields = host_health.parse_fields(HEALTHY)
        fields.update(
            {
                "auditd_active": "inactive",
                "auditd_rules_rc": "1",
                "auditd_rules_b64": base64.b64encode(b"No rules\n").decode(),
                "mount_options": "",
                "mount_source": "",
                "image_mode": "644",
                "image_uid": "1000",
                "free_root_bytes": "1000000",
                "free_iolog_bytes": "1000",
                "pruner": "inactive",
                "proxy": "inactive",
                "proxy_listen": "",
                "proxy_filter_sha": "",
                "proxy_rule": "0",
                "port_range": "1024-65535",
                "lo_foreign": "127.0.0.1:40000,",
                "plugin_hash": "",
                "admin_uid": "",
                "admin_sudoers": "",
                "admin_keys": "0",
                "admin_sshd": "0",
            }
        )
        lines = host_health.remote_lines(fields)
        self.assertTrue(all(item.startswith("red ") for item in lines))
        self.assertEqual(len(lines), 16)

    def test_default_remote_command_is_plain_ssh_to_hermesops(self) -> None:
        saved = os.environ.pop("HERMES_SSH", None)
        self.addCleanup(lambda: os.environ.__setitem__("HERMES_SSH", saved) if saved else None)
        self.assertEqual(host_health.ssh_argv(), ["ssh", "hermesops@hermes"])

    def test_ssh_override_is_split_like_a_shell_command(self) -> None:
        os.environ["HERMES_SSH"] = "ssh -F /tmp/cfg hermesops@hermes"
        self.addCleanup(lambda: os.environ.pop("HERMES_SSH", None))
        self.assertEqual(host_health.ssh_argv(), ["ssh", "-F", "/tmp/cfg", "hermesops@hermes"])

    def test_main_exits_nonzero_when_drift_fails(self) -> None:
        work = Path(tempfile.mkdtemp(prefix="host-health-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(work)], check=False))
        ssh = work / "fake-ssh"
        ssh.write_text("#!/bin/sh\nprintf '%s' \"$HEALTH_FIXTURE\"\n", encoding="utf-8")
        ssh.chmod(0o755)
        drift = work / "drift"
        drift.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        drift.chmod(0o755)
        env = os.environ.copy()
        env["HERMES_SSH"] = str(ssh)
        env["HERMES_TAILNET_POLICY"] = str(drift)
        env["HEALTH_FIXTURE"] = HEALTHY
        result = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "host-health.py")],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("red tailnet policy drift", result.stdout)
        self.assertEqual(len(result.stdout.splitlines()), 17)
        self.assertNotIn("sudo ", result.stdout)

    def test_main_is_green_when_the_host_and_policy_match(self) -> None:
        work = Path(tempfile.mkdtemp(prefix="host-health-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(work)], check=False))
        ssh = work / "fake-ssh"
        ssh.write_text(textwrap.dedent("""\
            #!/bin/sh
            printf '%s' "$HEALTH_FIXTURE"
            """), encoding="utf-8")
        ssh.chmod(0o755)
        drift = work / "drift.py"
        drift.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
        env = os.environ.copy()
        env["HERMES_SSH"] = str(ssh)
        env["HERMES_TAILNET_POLICY"] = str(drift)
        env["HEALTH_FIXTURE"] = HEALTHY
        result = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "host-health.py")],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(all(line.startswith("ok ") for line in result.stdout.splitlines()))


if __name__ == "__main__":
    unittest.main()
