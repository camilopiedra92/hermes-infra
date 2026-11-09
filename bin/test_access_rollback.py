#!/usr/bin/env python3
"""Tests for the sudo I/O rollback script. Host commands are stubbed."""

from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "infra"
    / "ansible"
    / "roles"
    / "access"
    / "files"
    / "hermes-access-rollback"
)


class RollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="access-rollback-"))
        self.bindir = Path(tempfile.mkdtemp(prefix="access-rollback-bin-"))
        self.log = self.root / "calls"
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.root), str(self.bindir)], check=False))
        self._stub("visudo", "exit 0")
        self._stub("systemctl", "exit 0")
        self._stub("umount", "exit 0")
        self._stub("chattr", "exit 0")
        self._stub("findmnt", 'if [ -f "$HERMES_ROLLBACK_ROOT/mounted" ]; then exit 0; fi\nexit 1')
        self._stub(
            "chown",
            "exit 0",
        )
        self._stub(
            "chmod",
            'mode=$1\nshift\n/bin/chmod "$mode" "$@"\nexit 0',
        )
        backup = self.root / "root" / "hermes-rollback" / "90-hermesops"
        backup.parent.mkdir(parents=True)
        backup.write_text("OLD-SUDOERS\n", encoding="utf-8")
        sudoers = self.root / "etc" / "sudoers.d" / "90-hermesops"
        sudoers.parent.mkdir(parents=True)
        sudoers.write_text("NEW-SUDOERS\n", encoding="utf-8")
        image = self.root / "var" / "lib" / "hermes" / "sudo-io.img"
        image.parent.mkdir(parents=True)
        image.write_text("recordings\n", encoding="utf-8")
        image.chmod(0o644)
        (self.root / "var" / "log" / "sudo-io").mkdir(parents=True)
        (self.root / "mounted").write_text("yes\n", encoding="utf-8")
        unit = self.root / "etc" / "systemd" / "system"
        unit.mkdir(parents=True)
        (unit / "hermes-sudo-io-prune.service").write_text("s\n", encoding="utf-8")
        (unit / "hermes-sudo-io-prune.timer").write_text("t\n", encoding="utf-8")
        (unit / "var-log-sudo\\x2dio.mount").write_text("m\n", encoding="utf-8")

    def _stub(self, name: str, body: str) -> None:
        path = self.bindir / name
        path.write_text(
            "#!/bin/sh\n"
            'printf "%s" "$0" >> "$HERMES_ROLLBACK_LOG"\n'
            'printf " %s" "$@" >> "$HERMES_ROLLBACK_LOG"\n'
            'printf "\\n" >> "$HERMES_ROLLBACK_LOG"\n'
            + body
            + "\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def run_script(self, *args: str, visudo_fails: bool = False) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["HERMES_ROLLBACK_ROOT"] = str(self.root)
        env["HERMES_ROLLBACK_LOG"] = str(self.log)
        env["PATH"] = f"{self.bindir}:{env.get('PATH', '')}"
        if visudo_fails:
            (self.bindir / "visudo").write_text(
                "#!/bin/sh\n"
                'echo visudo >> "$HERMES_ROLLBACK_LOG"\n'
                "exit 1\n",
                encoding="utf-8",
            )
            (self.bindir / "visudo").chmod(0o755)
        return subprocess.run(
            [str(SCRIPT), *args],
            check=False,
            text=True,
            capture_output=True,
            env=env,
        )

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()

    def test_restores_sudoers_before_unmount_and_keeps_the_image(self) -> None:
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        sudoers = (self.root / "etc" / "sudoers.d" / "90-hermesops").read_text(encoding="utf-8")
        self.assertEqual(sudoers, "OLD-SUDOERS\n")
        names = [line.split()[0].rsplit("/", 1)[-1] for line in self.calls()]
        self.assertLess(names.index("visudo"), names.index("umount"))
        self.assertLess(names.index("umount"), names.index("chattr"))
        image = self.root / "var" / "lib" / "hermes" / "sudo-io.img"
        self.assertTrue(image.is_file())
        self.assertEqual(image.read_text(encoding="utf-8"), "recordings\n")
        self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
        unit = self.root / "etc" / "systemd" / "system"
        self.assertFalse((unit / "hermes-sudo-io-prune.timer").exists())
        self.assertFalse((unit / "hermes-sudo-io-prune.service").exists())
        self.assertFalse((unit / "var-log-sudo\\x2dio.mount").exists())

    def test_visudo_failure_does_not_unmount(self) -> None:
        result = self.run_script(visudo_fails=True)
        self.assertNotEqual(result.returncode, 0)
        sudoers = (self.root / "etc" / "sudoers.d" / "90-hermesops").read_text(encoding="utf-8")
        self.assertEqual(sudoers, "NEW-SUDOERS\n")
        self.assertNotIn("umount", "\n".join(self.calls()))
        self.assertIn("invalid", result.stderr)

    def test_missing_backup_refuses_before_unmount(self) -> None:
        backup = self.root / "root" / "hermes-rollback" / "90-hermesops"
        backup.unlink()
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr)
        self.assertNotIn("umount", "\n".join(self.calls()) if self.log.exists() else "")
        sudoers = (self.root / "etc" / "sudoers.d" / "90-hermesops").read_text(encoding="utf-8")
        self.assertEqual(sudoers, "NEW-SUDOERS\n")
        self.assertTrue((self.root / "var" / "lib" / "hermes" / "sudo-io.img").is_file())

    def test_remove_image_flag_deletes_the_image(self) -> None:
        result = self.run_script("--remove-image")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "var" / "lib" / "hermes" / "sudo-io.img").exists())


if __name__ == "__main__":
    unittest.main()
