""": no GitHub Actions workflow has a credential or path to the host."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = (
    (re.compile(r"id-token:\s*write"), "requests an OIDC token"),
    (re.compile(r"tailscale/github-action", re.I), "joins the tailnet"),
    (re.compile(r"TS_[A-Z]+_(CLIENT_ID|AUDIENCE)|TAILSCALE_OAUTH"), "uses a tailnet credential"),
    (re.compile(r"inventory/hosts\.yml|ansible_host"), "targets the real host inventory"),
)


class NoCiHostPathTests(unittest.TestCase):
    def test_workflows_have_no_path_to_the_host(self) -> None:
        for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
            text = path.read_text(encoding="utf-8")
            for pattern, reason in FORBIDDEN:
                self.assertIsNone(pattern.search(text), f"{path.name} {reason}")

    def test_policy_has_no_ci_tag(self) -> None:
        text = (ROOT / "policy" / "tailscale-acl.hujson").read_text(encoding="utf-8")
        self.assertNotIn("tag:ci", text)


if __name__ == "__main__":
    unittest.main()
