"""The repository is public: no operational identifier of the host may be committed.

The check is generic on purpose. It does not contain the values it protects, because a test that lists the
address it hides publishes it. It rejects any public or tailnet IPv4 literal, any e-mail address that is not on
the short list below, any provider id next to the words server or firewall, and the private inventory itself.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
PROVIDER_ID = re.compile(r"(?i)\b(?:server|firewall)\b[^\n]{0,24}\b\d{7,}\b")

# The CGNAT base and address named by the sandbox qualification as destinations that must be unreachable, and the
# two published Telegram ranges that explains and replaces with names.
IPV4_ALLOWED = {"100.64.0.0", "100.64.0.1", "149.154.160.0", "91.108.4.0"}
EMAIL_DOMAINS_ALLOWED = {"example.com", "example.org", "example.test", "users.noreply.github.com", "anthropic.com", "cursor.com", "github.com"}
# The owner's tailnet login is in the access policy and in the tests that evaluate it. Moving it behind a group is a
# live access change, tracked as R27. It stays out of every other file.
EMAIL_ALLOWED_FILES = {"policy/tailscale-acl.hujson", "bin/test_tailnet_policy.py"}


def tracked_text() -> list[tuple[str, str]]:
    names = subprocess.run(["git", "ls-files"], cwd=ROOT, text=True, capture_output=True, check=True).stdout.splitlines()
    out = []
    for name in names:
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            out.append((name, path.read_text(encoding="utf-8")))
        except UnicodeDecodeError:
            continue
    return out


FILES = tracked_text()


class PublicSafeTests(unittest.TestCase):
    def test_no_public_or_tailnet_ipv4_address_is_committed(self) -> None:
        found = []
        for name, text in FILES:
            for match in IPV4.finditer(text):
                try:
                    address = ipaddress.ip_address(match.group())
                except ValueError:
                    continue  # a version string such as 1.2.3.400
                if match.group() in IPV4_ALLOWED:
                    continue
                if address.is_global or address in ipaddress.ip_network("100.64.0.0/10"):
                    found.append(f"{name}: an address that identifies a host")
        self.assertEqual(found, [])

    def test_no_personal_e_mail_address_is_committed_outside_the_access_policy(self) -> None:
        found = []
        for name, text in FILES:
            for match in EMAIL.finditer(text):
                domain = match.group().rsplit("@", 1)[1].lower()
                local = match.group().rsplit("@", 1)[0]
                if domain in EMAIL_DOMAINS_ALLOWED or re.fullmatch(r"\d+\.service", domain) or name in EMAIL_ALLOWED_FILES:
                    continue
                if local in {"hermesops", "hermesadmin", "hermes-bot", "user", "git"}:
                    continue
                found.append(f"{name}: an e-mail address")
        self.assertEqual(found, [])

    def test_no_provider_id_of_the_server_or_the_firewall_is_committed(self) -> None:
        found = [name for name, text in FILES if PROVIDER_ID.search(text)]
        self.assertEqual(found, [])

    def test_the_private_inventory_is_not_in_the_repository(self) -> None:
        self.assertFalse((ROOT / "docs" / "inventory").exists())

    def test_workflows_never_run_untrusted_code_with_secrets(self) -> None:
        # A public repository takes pull requests from anyone. The workflows hold no secret and use pull_request only.
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("pull_request_target", text, path.name)
            self.assertNotIn("secrets.", text, path.name)
            self.assertIn("permissions: {}", text, path.name)


if __name__ == "__main__":
    unittest.main()
