#!/usr/bin/env python3
"""Tests for sudo I/O session pruning and the fixed-size log volume."""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

PRUNE = (
    Path(__file__).resolve().parent.parent
    / "infra"
    / "ansible"
    / "roles"
    / "access"
    / "files"
    / "hermes-sudo-io-prune"
)
SESSION_FILES = ("log", "log.json", "timing", "stdout", "stderr", "ttyout")
SUDOERS_FRAG = Path("/etc/sudoers.d/99-hermes-iolog-test")


def run(cmd: list[str], *, check: bool = True, **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, **kwargs)


def sudo(*args: str, check: bool = True, **kwargs) -> subprocess.CompletedProcess[str]:
    return run(["sudo", "-n", *args], check=check, **kwargs)


def current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name


# The prune script only accepts directories under /var/log/sudo-io, so these tests need that directory writable (CI prepares it).
@unittest.skipUnless(os.access("/var/log/sudo-io", os.W_OK), "needs a writable /var/log/sudo-io")
class PruneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("/var/log/sudo-io") / f"prune-test-{os.getpid()}-{id(self)}"
        sudo("mkdir", "-p", str(self.root))
        sudo("chown", f"{os.getuid()}:{os.getgid()}", str(self.root))
        self.addCleanup(lambda: sudo("rm", "-rf", str(self.root), check=False))

    def make_session(
        self,
        relative: str,
        *,
        age_days: int | None = None,
        bulk: int = 0,
    ) -> Path:
        session = self.root / relative
        session.mkdir(parents=True)
        for name in SESSION_FILES:
            data = f"{relative}:{name}\n".encode()
            if name == "stdout":
                data += b"x" * bulk
            (session / name).write_bytes(data)
        if age_days is not None:
            when = f"{age_days} days ago"
            for target in session.iterdir():
                run(["touch", "-d", when, str(target)])
        return session

    def prune(self, retention: str, max_mb: str, directory: Path | None = None) -> None:
        target = directory or self.root
        result = run([str(PRUNE), str(target), retention, max_mb], check=False, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def fingerprints(self, session: Path) -> dict[str, str]:
        found = {}
        for name in SESSION_FILES:
            digest = run(
                ["sha256sum", str(session / name)],
                capture_output=True,
            ).stdout.split()[0]
            found[name] = digest
        return found

    def wait_until_locked(self, path: Path) -> None:
        for _ in range(50):
            probe = run(["flock", "-n", str(path), "true"], check=False)
            if probe.returncode != 0:
                return
            time.sleep(0.05)
        self.fail(f"{path} was not locked")

    def test_locked_log_is_skipped(self) -> None:
        session = self.make_session("00/00/01", age_days=40)
        (self.root / "seq").write_text("1\n", encoding="utf-8")
        holder = subprocess.Popen(["flock", str(session / "log"), "sleep", "30"])
        try:
            self.wait_until_locked(session / "log")
            self.prune("30", "400")
            self.assertEqual(sorted(path.name for path in session.iterdir()), sorted(SESSION_FILES))
            self.assertEqual((self.root / "seq").read_text(encoding="utf-8"), "1\n")
            self.assertTrue((self.root / "00" / "00").is_dir())
        finally:
            holder.kill()
            holder.wait(timeout=5)

    def test_open_descriptor_is_skipped(self) -> None:
        session = self.make_session("00/00/01", age_days=40)
        held = os.open(session / "ttyout", os.O_RDONLY)
        self.addCleanup(os.close, held)
        self.prune("30", "400")
        self.assertEqual(sorted(path.name for path in session.iterdir()), sorted(SESSION_FILES))

    def test_closed_session_is_removed_as_a_whole(self) -> None:
        old = self.make_session("00/00/01", age_days=40)
        keep = self.make_session("00/00/02")
        before = self.fingerprints(keep)
        (self.root / "seq").write_text("2\n", encoding="utf-8")
        self.prune("30", "400")
        self.assertFalse(old.exists())
        self.assertFalse(list(self.root.rglob("00/00/01/*")))
        self.assertEqual(self.fingerprints(keep), before)
        self.assertTrue((self.root / "00" / "00").is_dir())
        self.assertEqual((self.root / "seq").read_text(encoding="utf-8"), "2\n")

    def test_size_limit_drops_oldest_whole_sessions(self) -> None:
        oldest = self.make_session("00/00/01", age_days=3, bulk=3 * 1024 * 1024)
        middle = self.make_session("00/00/02", age_days=2, bulk=3 * 1024 * 1024)
        newest = self.make_session("00/00/03", age_days=1, bulk=3 * 1024 * 1024)
        before = self.fingerprints(newest)
        (self.root / "seq").write_text("3\n", encoding="utf-8")
        self.prune("9999", "5")
        self.assertFalse(oldest.exists())
        self.assertFalse(middle.exists())
        self.assertEqual(self.fingerprints(newest), before)
        self.assertEqual((self.root / "seq").read_text(encoding="utf-8"), "3\n")
        used = int(run(["du", "-sm", str(self.root)], capture_output=True).stdout.split()[0])
        self.assertLessEqual(used, 5)

    def test_the_prune_finishes_with_thousands_of_sessions_and_a_busy_proc(self) -> None:
        # On 2026-11-08 the hourly prune had been running for 40 minutes on 3,017 sessions: it read every
        # descriptor of every process once per session, and ran du over the whole tree once per removal.
        # The cost must follow the number of sessions, not sessions times descriptors.
        for index in range(2500):
            session = self.root / f"{index // 1000:02d}" / f"{(index // 40) % 25:02d}" / f"S{index:04d}"
            session.mkdir(parents=True)
            for name in ("log", "timing", "stdout"):
                (session / name).write_bytes(b"x" * 64)
            old = time.time() - 40 * 86400
            for name in ("log", "timing", "stdout"):
                os.utime(session / name, (old, old))
        holder = subprocess.Popen(
            ["python3", "-c", "import os,time\nfds=[os.open('/dev/null',os.O_RDONLY) for _ in range(2000)]\ntime.sleep(120)"]
        )
        self.addCleanup(lambda: (holder.kill(), holder.wait(timeout=5)))
        time.sleep(0.5)
        started = time.monotonic()
        result = run([str(PRUNE), str(self.root), "30", "400"], check=False, capture_output=True, timeout=60)
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(elapsed, 20, f"the prune took {elapsed:.0f} s")
        self.assertEqual(len(list(self.root.rglob("log"))), 0)

    def test_real_session_stays_replayable(self) -> None:
        command = self.root / "true-cmd"
        command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        command.chmod(0o755)
        fragment = self.root / "sudoers"
        fragment.write_text(
            "Defaults!"
            + str(command)
            + " log_output,use_pty,ignore_iolog_errors,iolog_dir="
            + str(self.root)
            + "/%{user}\n",
            encoding="utf-8",
        )
        fragment.chmod(0o644)
        sudo("visudo", "-cf", str(fragment))
        sudo("cp", str(fragment), str(SUDOERS_FRAG))
        self.addCleanup(lambda: sudo("rm", "-f", str(SUDOERS_FRAG), check=False))
        sudo(str(command))
        sudo(str(command))
        user_dir = self.root / current_user()
        listing = sudo(
            "find",
            str(user_dir),
            "-type",
            "f",
            "-name",
            "log",
            capture_output=True,
        ).stdout
        sessions = sorted(Path(line).parent for line in listing.splitlines() if line.strip())
        self.assertGreaterEqual(len(sessions), 2, listing)
        first, second = sessions[0], sessions[-1]
        for child in SESSION_FILES:
            sudo("touch", "-d", "40 days ago", str(first / child), check=False)
        before = sudo(
            "sha256sum",
            *[str(second / name) for name in SESSION_FILES],
            capture_output=True,
        ).stdout
        result = sudo(str(PRUNE), str(user_dir), "30", "400", check=False, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(sudo("test", "-d", str(first), check=False).returncode, 0)
        after = sudo(
            "sha256sum",
            *[str(second / name) for name in SESSION_FILES],
            capture_output=True,
        ).stdout
        self.assertEqual(after, before)
        removed = "".join(first.relative_to(user_dir).parts)
        kept_id = "/".join(second.relative_to(user_dir).parts)
        kept = "".join(second.relative_to(user_dir).parts)
        listed = sudo("sudoreplay", "-l", "-d", str(user_dir), capture_output=True)
        self.assertIn(f"TSID={kept}", listed.stdout)
        self.assertNotIn(f"TSID={removed}", listed.stdout)
        replayed = sudo(
            "sudoreplay",
            "-n",
            "-d",
            str(user_dir),
            kept_id,
            check=False,
            capture_output=True,
        )
        self.assertIn("Replaying sudo session", replayed.stdout)
        self.assertEqual(sudo("test", "-f", str(user_dir / "seq"), check=False).returncode, 0)
        self.assertEqual(sudo("test", "-d", str(user_dir / "00" / "00"), check=False).returncode, 0)


@unittest.skipUnless(os.geteuid() == 0, "needs root to build and mount a test image")
class FilesystemCeilingTests(unittest.TestCase):
    def test_image_stops_at_its_size_and_sudo_still_runs(self) -> None:
        work = Path(tempfile.mkdtemp(prefix="sudo-io-ceiling-", dir="/var/tmp"))
        image = work / "io.img"
        mount = work / "mnt"
        command = work / "cmd.sh"
        fragment = work / "sudoers"
        self.addCleanup(self._teardown, mount, work)
        sudo("truncate", "-s", "8M", str(image))
        sudo("mkfs.ext4", "-F", "-m", "0", "-L", "sudo-io-test", str(image), capture_output=True)
        sudo("mkdir", "-p", str(mount))
        sudo("mount", "-o", "loop,nodev,nosuid,noexec,nofail", str(image), str(mount))
        options = sudo("findmnt", "-no", "OPTIONS", str(mount), capture_output=True).stdout
        for flag in ("nosuid", "nodev", "noexec"):
            self.assertIn(flag, options)
        sudo("mkdir", "-m", "700", str(mount / current_user()))
        secret = mount / current_user() / "session.log"
        sudo("tee", str(secret), input="IOLOG-MARKER\n", capture_output=True)
        sudo("chmod", "0600", str(secret))
        denied = sudo("-u", "nobody", "cat", str(secret), check=False, capture_output=True)
        self.assertNotEqual(denied.returncode, 0)
        self.assertNotIn("IOLOG-MARKER", denied.stdout)
        command.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        command.chmod(0o755)
        filler = mount / "filler"
        fill = work / "fill.py"
        fill.write_text(
            "import sys\n"
            "path = sys.argv[1]\n"
            "handle = open(path, 'ab')\n"
            "try:\n"
            "    while True:\n"
            "        handle.write(b'x' * 4096)\n"
            "        handle.flush()\n"
            "except OSError:\n"
            "    pass\n"
            "finally:\n"
            "    try:\n"
            "        handle.close()\n"
            "    except OSError:\n"
            "        pass\n",
            encoding="utf-8",
        )
        sudo("python3", str(fill), str(filler))
        self.assertEqual(image.stat().st_size, 8 * 1024 * 1024)
        allocated = int(sudo("stat", "-c", "%b", str(image), capture_output=True).stdout) * 512
        self.assertLessEqual(allocated, 8 * 1024 * 1024)
        avail = int(
            sudo("df", "-B1", "--output=avail", str(mount), capture_output=True).stdout.splitlines()[-1].strip()
        )
        self.assertLess(avail, 4096)
        sudo(
            "dd",
            "if=/dev/zero",
            f"of={mount / 'more'}",
            "bs=1M",
            "count=1",
            "status=none",
            check=False,
        )
        self.assertEqual(image.stat().st_size, 8 * 1024 * 1024)

        def install(ignore: bool) -> None:
            flag = ",ignore_iolog_errors" if ignore else ""
            fragment.write_text(
                f"Defaults!{command} log_output,use_pty{flag},iolog_dir={mount}/%{{user}}\n",
                encoding="utf-8",
            )
            fragment.chmod(0o644)
            sudo("visudo", "-cf", str(fragment))
            sudo("cp", str(fragment), str(SUDOERS_FRAG))

        install(False)
        refused = sudo(str(command), check=False, capture_output=True)
        self.assertNotEqual(refused.returncode, 0)
        install(True)
        allowed = sudo(str(command), check=False, capture_output=True)
        self.assertEqual(allowed.returncode, 0, allowed.stderr + allowed.stdout)
        self.assertEqual(image.stat().st_size, 8 * 1024 * 1024)

    def _teardown(self, mount: Path, work: Path) -> None:
        sudo("rm", "-f", str(SUDOERS_FRAG), check=False)
        sudo("umount", str(mount), check=False)
        shutil.rmtree(work, ignore_errors=True)


class ImagePermissionTests(unittest.TestCase):
    def test_image_is_created_0600_and_a_0644_image_is_corrected(self) -> None:
        work = Path(tempfile.mkdtemp(prefix="sudo-io-mode-", dir="/var/tmp"))
        self.addCleanup(lambda: sudo("rm", "-rf", str(work), check=False))
        os.chmod(work, 0o755)
        image = work / "sudo-io.img"
        sudo("install", "-o", "root", "-g", "root", "-m", "0600", "/dev/null", str(image))
        sudo("tee", str(image), input="IOLOG-MARKER\n", capture_output=True)
        self.assertEqual(image.stat().st_mode & 0o777, 0o600)
        denied = sudo("-u", "nobody", "cat", str(image), check=False, capture_output=True)
        self.assertNotEqual(denied.returncode, 0)
        self.assertNotIn("IOLOG-MARKER", denied.stdout)

        sudo("chmod", "0644", str(image))
        readable = sudo("-u", "nobody", "cat", str(image), check=False, capture_output=True)
        self.assertEqual(readable.returncode, 0)
        self.assertIn("IOLOG-MARKER", readable.stdout)
        sudo("chown", "root:root", str(image))
        sudo("chmod", "0600", str(image))
        corrected = sudo("-u", "nobody", "cat", str(image), check=False, capture_output=True)
        self.assertNotEqual(corrected.returncode, 0)
        self.assertNotIn("IOLOG-MARKER", corrected.stdout)
        self.assertEqual(image.stat().st_mode & 0o777, 0o600)

        sudo("chmod", "0644", str(image))
        sudo("chmod", "0700", str(work))
        hidden = sudo("-u", "nobody", "cat", str(image), check=False, capture_output=True)
        self.assertNotEqual(hidden.returncode, 0)
        self.assertNotIn("IOLOG-MARKER", hidden.stdout)


if __name__ == "__main__":
    unittest.main()
