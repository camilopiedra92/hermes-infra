""": no secret is kept in git, encrypted or not."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = re.compile(r"(^|/)(\.sops\.ya?ml|[^/]*\.sops\.(ya?ml|json|env)|keys\.txt|[^/]*\.age)$")


class NoSecretsInGitTests(unittest.TestCase):
    def test_no_sops_or_age_material_is_tracked(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, text=True, capture_output=True, check=True
        ).stdout.splitlines()
        offenders = [name for name in tracked if FORBIDDEN.search(name)]
        self.assertEqual(offenders, [], "introducing sops or age needs a decision in docs/DECISIONS.md")


if __name__ == "__main__":
    unittest.main()
