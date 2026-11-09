#!/usr/bin/env python3
"""An existing sudo I/O image is never formatted. Probes must succeed first."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANSIBLE = ROOT / "infra" / "ansible"
IMAGE_TASKS = ANSIBLE / "roles" / "access" / "tasks" / "image.yml"
SIZE = 8 * 1024 * 1024


def digest(path: Path) -> str:
    data = subprocess.run(["sudo", "-n", "cat", str(path)], capture_output=True, check=True).stdout
    return hashlib.sha256(data).hexdigest()


class SudoImageGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.playbook = shutil.which("ansible-playbook")
        if self.playbook is None:
            self.fail("ansible-playbook is required")
        self.work = Path(tempfile.mkdtemp(prefix="sudo-image-"))
        self.addCleanup(lambda: subprocess.run(["sudo", "-n", "rm", "-rf", str(self.work)], check=False))
        self.image = self.work / "data" / "sudo-io.img"
        self.image.parent.mkdir()
        config = self.work / "ansible.cfg"
        config.write_text(
            "[defaults]\n"
            f"roles_path = {ANSIBLE / 'roles'}\n"
            "inject_facts_as_vars = False\n"
            "host_key_checking = False\n"
            "retry_files_enabled = False\n"
            "stdout_callback = default\n"
            "[privilege_escalation]\n"
            "become_flags = -H -n -E\n",
            encoding="utf-8",
        )
        self.config = config
        play = self.work / "play.yml"
        play.write_text(
            "- name: Prepare the sudo I/O image\n"
            "  hosts: localhost\n"
            "  gather_facts: false\n"
            "  become: true\n"
            "  tasks:\n"
            "    - ansible.builtin.import_role:\n"
            "        name: access\n"
            "        tasks_from: image.yml\n",
            encoding="utf-8",
        )
        self.play = play
        (self.work / "hosts").write_text("localhost ansible_connection=local\n", encoding="utf-8")

    def run_play(self, blkid: str | None = None) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["ANSIBLE_CONFIG"] = str(self.config)
        if blkid is not None:
            bindir = self.work / "bin"
            bindir.mkdir(exist_ok=True)
            script = bindir / "blkid"
            script.write_text(blkid, encoding="utf-8")
            script.chmod(0o755)
            env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
        return subprocess.run(
            [
                self.playbook,
                "-i",
                str(self.work / "hosts"),
                str(self.play),
                "-e",
                f"access_iolog_image={self.image}",
                "-e",
                f"access_iolog_bytes={SIZE}",
            ],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_unchanged(self, before: str, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(digest(self.image), before)
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn("Require ext4 identification", output)
        self.assertNotIn("Format the sudo I/O image", output.split("Require ext4 identification", 1)[-1])

    def test_mkfs_is_gated_on_create_and_a_marker_not_on_probe_output(self) -> None:
        text = IMAGE_TASKS.read_text(encoding="utf-8")
        self.assertIn("access_iolog_image_created is changed", text)
        self.assertIn("access_iolog_new_marker", text)
        format_task = text.split("- name: Format the sudo I/O image", 1)[1].split("- name:", 1)[0]
        self.assertNotIn("fstype", format_task)
        self.assertNotIn("blkid", format_task)
        main = (ANSIBLE / "roles" / "access" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("import_tasks: image.yml", main)

    def test_blank_image_is_not_formatted(self) -> None:
        self.image.write_bytes(b"\0" * SIZE)
        before = digest(self.image)
        self.assert_unchanged(before, self.run_play())

    def test_corrupt_image_is_not_formatted(self) -> None:
        self.image.write_bytes(b"CORRUPT-NOT-EXT4\n" * (SIZE // 17 + 1))
        self.image.write_bytes(self.image.read_bytes()[:SIZE])
        before = digest(self.image)
        self.assert_unchanged(before, self.run_play())

    def test_probe_failure_leaves_the_image_unchanged(self) -> None:
        self.image.write_bytes(b"\0" * SIZE)
        before = digest(self.image)
        result = self.run_play("#!/bin/sh\necho 'blkid: probe failed' >&2\nexit 1\n")
        self.assert_unchanged(before, result)

    def test_empty_probe_output_is_not_treated_as_unformatted(self) -> None:
        self.image.write_bytes(b"\0" * SIZE)
        before = digest(self.image)
        result = self.run_play("#!/bin/sh\nexit 0\n")
        self.assert_unchanged(before, result)


if __name__ == "__main__":
    unittest.main()
