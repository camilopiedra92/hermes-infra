"""Accounts that share the host cannot see each other's processes or read each other's new files."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROLE = Path(__file__).resolve().parent.parent / "infra" / "ansible" / "roles" / "hardening"


def read(*parts: str) -> str:
    return ROLE.joinpath(*parts).read_text(encoding="utf-8")


class AccountIsolationTests(unittest.TestCase):
    def test_proc_hides_other_accounts_at_boot_and_now(self) -> None:
        tasks = read("tasks", "main.yml")
        self.assertIn("proc /proc proc nosuid,nodev,noexec,hidepid=2 0 0", tasks)
        self.assertIn("notify: Remount /proc with hidepid", tasks)
        handler = read("handlers", "main.yml")
        self.assertIn("name: systemd-remount-fs.service", handler)
        self.assertIn("state: restarted", handler)

    def test_the_default_umask_leaves_nothing_readable_to_other_accounts(self) -> None:
        tasks = read("tasks", "main.yml")
        match = re.search(r"path: /etc/login\.defs.*?line: UMASK\s+(\d+)", tasks, re.S)
        self.assertIsNotNone(match)
        # The other-bits of the umask must remove read, write and execute (7); 027 and 077 both do.
        self.assertEqual(match.group(1)[-1], "7")

    def test_tmp_is_cleaned_of_old_files_sooner_than_the_distribution_default(self) -> None:
        line = next(x for x in read("files", "tmp.conf").splitlines() if x.startswith("D /tmp"))
        self.assertRegex(line, r"^D /tmp 1777 root root (\d+)d$")
        self.assertLess(int(re.search(r"(\d+)d$", line).group(1)), 30)


if __name__ == "__main__":
    unittest.main()
