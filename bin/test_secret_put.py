#!/usr/bin/env python3
"""Tests for hermes-secret-put: the way a runtime secret reaches the host without being logged."""

from __future__ import annotations

import os
import pty
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parent.parent / "infra" / "ansible" / "roles" / "access"
PUT = ROLE / "files" / "hermes-secret-put"
SUDOERS = ROLE / "templates" / "90-hermesops.j2"
TOKEN = "123456789:AAH-canary_0123456789abcdefghijklmnopq"
KEY = "TELEGRAM_BOT_TOKEN"


def run_put(args: list[str], stdin: str, dest: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "HERMES_SECRET_ENV_FILE": str(dest)}
    return subprocess.run([str(PUT), *args], input=stdin, text=True, capture_output=True, env=env, check=False)


class PutTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.dest = self.dir / ".env"

    def test_writes_the_value_mode_0600_and_prints_nothing_secret(self) -> None:
        result = run_put([KEY], TOKEN + "\n", self.dest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.dest.read_text(), f"{KEY}={TOKEN}\n")
        self.assertEqual(stat.S_IMODE(self.dest.stat().st_mode), 0o600)
        self.assertNotIn(TOKEN, result.stdout + result.stderr)

    def test_replaces_its_own_line_and_keeps_the_others(self) -> None:
        self.dest.write_text(f"OTHER=1\n{KEY}=old\nLAST=2\n")
        self.assertEqual(run_put([KEY], TOKEN + "\r\n", self.dest).returncode, 0)
        lines = self.dest.read_text().splitlines()
        self.assertEqual(sorted(lines), sorted(["OTHER=1", "LAST=2", f"{KEY}={TOKEN}"]))
        self.assertEqual(sum(line.startswith(KEY + "=") for line in lines), 1)

    def test_a_value_of_the_wrong_shape_writes_nothing(self) -> None:
        for bad in ("", "not a token", "123:short", TOKEN + " extra", "x" * 80):
            self.dest.write_text("KEEP=1\n")
            result = run_put([KEY], bad + "\n", self.dest)
            self.assertEqual(result.returncode, 1, bad)
            self.assertEqual(self.dest.read_text(), "KEEP=1\n")
            self.assertNotIn(bad or "\0", result.stderr.replace("hermes-secret-put", ""))

    def test_only_named_keys_and_exactly_one_argument(self) -> None:
        self.assertEqual(run_put(["ANTHROPIC_API_KEY"], TOKEN + "\n", self.dest).returncode, 2)
        self.assertEqual(run_put([KEY, "extra"], TOKEN + "\n", self.dest).returncode, 2)
        self.assertFalse(self.dest.exists())

    def test_a_github_token_is_written_alone_to_its_own_file_and_other_shapes_are_refused(self) -> None:
        pat = "github_pat_11ABCDEFG0" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2w3X4y5Z6_canary"
        target = self.dir / "github-token"
        result = run_put(["GITHUB_TOKEN"], pat + "\n", target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.read_text(), pat + "\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertNotIn(pat, result.stdout + result.stderr)
        for bad in (TOKEN, "ghp_short", "password", "github_pat_" + "x" * 10):
            target.write_text("KEEP\n")
            self.assertEqual(run_put(["GITHUB_TOKEN"], bad + "\n", target).returncode, 1, bad)
            self.assertEqual(target.read_text(), "KEEP\n")

    def test_the_github_token_goes_to_the_administration_account_not_the_gateway(self) -> None:
        text = PUT.read_text(encoding="utf-8")
        self.assertIn("service_user=hermesadmin", text)
        self.assertIn("rel=.config/hermes/github-token", text)
        self.assertIn("service_user=hermes\n", text)

    def test_the_prompt_does_not_echo_the_value(self) -> None:
        env = {**os.environ, "HERMES_SECRET_ENV_FILE": str(self.dest)}
        pid, fd = pty.fork()
        if pid == 0:
            os.execve(str(PUT), [str(PUT), KEY], env)
        out = b""
        while not out.endswith(b": "):
            out += os.read(fd, 4096)
        os.write(fd, (TOKEN + "\n").encode())
        while True:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertFalse(TOKEN.encode() in out, "the value was echoed to the terminal")
        self.assertEqual(self.dest.read_text(), f"{KEY}={TOKEN}\n")


class SudoersTests(unittest.TestCase):
    def render(self) -> str:
        text = SUDOERS.read_text()
        for name, value in {
            "access_ops_user": "hermesops",
            "access_iolog_root": "/var/log/sudo-io",
            "access_sudo_logfile": "/var/log/sudo-hermesops.log",
            "ansible_managed": "managed",
        }.items():
            text = text.replace("{{ " + name + " }}", value)
        return text

    def test_the_secret_rules_come_after_the_blanket_rule_and_have_both_nolog_tags(self) -> None:
        lines = [x for x in self.render().splitlines() if x and not x.startswith("#") and not x.startswith("Defaults")]
        self.assertEqual(len(lines), 3, lines)
        self.assertIn("NOPASSWD: ALL", lines[0])
        # The last matching rule wins, so each command that receives a secret or a pasted code stays below the blanket one.
        for line, command in zip(lines[1:], ("hermes-secret-put", "hermes-claude-login")):
            self.assertIn("NOLOG_INPUT:", line)
            self.assertIn("NOLOG_OUTPUT:", line)
            self.assertTrue(line.endswith("/usr/local/sbin/" + command), line)

    def test_visudo_accepts_the_rendered_file(self) -> None:
        if not shutil.which("visudo"):
            self.skipTest("visudo is not installed")
        with tempfile.NamedTemporaryFile("w", suffix=".sudoers") as handle:
            handle.write(self.render())
            handle.flush()
            result = subprocess.run(["visudo", "-cf", handle.name], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class RealSudoIologTests(unittest.TestCase):
    """The I/O log of a real sudo session must not hold what was typed, and the control must."""

    FRAG = Path("/etc/sudoers.d/99-hermes-secret-test")

    def setUp(self) -> None:
        if os.geteuid() != 0 or not shutil.which("sudo"):
            self.skipTest("needs root and sudo")
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.iolog = self.dir / "iolog"
        self.iolog.mkdir(mode=0o700)
        self.dest = self.dir / ".env"
        self.wrapper = self.dir / "put"
        self.wrapper.write_text(f"#!/bin/sh\nHERMES_SECRET_ENV_FILE={self.dest} exec {PUT} \"$@\"\n")
        self.wrapper.chmod(0o755)
        self.control = self.dir / "echo-secret"
        self.control.write_text("#!/bin/bash\nread -r v\necho \"$v\"\n")
        self.control.chmod(0o755)
        self.addCleanup(lambda: self.FRAG.unlink(missing_ok=True))

    def sudo_with_input(self, command: Path, *args: str) -> int:
        pid, fd = pty.fork()
        if pid == 0:
            os.execvp("sudo", ["sudo", "-n", str(command), *args])
        os.write(fd, (TOKEN + "\n").encode())
        while True:
            try:
                if not os.read(fd, 4096):
                    break
            except OSError:
                break
        return os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])

    def logged(self) -> bytes:
        data = b""
        for path in self.iolog.rglob("*"):
            if path.is_file():
                data += path.read_bytes()
        return data

    def test_nolog_keeps_the_token_out_and_the_control_proves_the_test_can_see_it(self) -> None:
        # Same mechanism as the production rule: the tags on the command, not the Defaults.
        self.FRAG.write_text(
            f"Defaults iolog_dir={self.iolog}/%{{user}},use_pty,!compress_io\n"
            f"root ALL=(ALL) NOPASSWD: LOG_INPUT: LOG_OUTPUT: {self.control}\n"
            f"root ALL=(ALL) NOPASSWD: NOLOG_INPUT: NOLOG_OUTPUT: {self.wrapper}\n"
        )
        self.FRAG.chmod(0o440)
        subprocess.run(["visudo", "-cf", str(self.FRAG)], check=True, capture_output=True)
        self.assertEqual(self.sudo_with_input(self.control), 0)
        self.assertTrue(TOKEN.encode() in self.logged(), "the control session should have recorded the token")
        shutil.rmtree(self.iolog)
        self.iolog.mkdir(mode=0o700)
        self.assertEqual(self.sudo_with_input(self.wrapper, KEY), 0)
        self.assertEqual(self.dest.read_text(), f"{KEY}={TOKEN}\n")
        self.assertFalse(TOKEN.encode() in self.logged(), "the I/O log holds the token")


if __name__ == "__main__":
    unittest.main()
