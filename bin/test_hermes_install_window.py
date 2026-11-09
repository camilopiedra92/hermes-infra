"""The install window: a bounded, audited hole in the uid hold, closed by a timer."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
G2 = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))["egress"]
TEMPLATE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway" / "templates" / "hermes-install-window.j2"


def render() -> str:
    text = TEMPLATE.read_text(encoding="utf-8")
    values = {
        "hermes_pins.egress.nft.table": G2["nft"]["table"],
        "hermes_pins.egress.nft.window_chain": G2["nft"]["window_chain"],
        "hermes_pins.egress.user.uid": str(G2["user"]["uid"]),
        "hermes_pins.egress.user.name": G2["user"]["name"],
        "ansible_managed": "Ansible managed",
    }
    for key, value in values.items():
        text = text.replace("{{ " + key + " }}", value)
    return text


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="install-window-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(self.dir)], check=False))
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        self.log = self.dir / "calls.log"
        self.log.write_text("", encoding="utf-8")
        self.state = self.dir / "state"
        self.state.mkdir()
        (self.dir / "script").write_text(render(), encoding="utf-8")
        (self.dir / "script").chmod(0o755)
        self.fake("nft", """\
            echo "nft $*" >> "$LOG"
            case "$*" in
              "list chain "*) cat "$STATE/chain" 2>/dev/null; exit 0 ;;
              "add rule "*) shift 5; echo "$*" >> "$STATE/chain"; exit 0 ;;
              "flush chain "*) : > "$STATE/chain"; exit 0 ;;
            esac
            exit 0""")
        self.fake("systemd-run", """\
            echo "systemd-run $*" >> "$LOG"
            [ -n "${FAIL_TIMER:-}" ] && exit 1
            touch "$STATE/timer"; exit 0""")
        self.fake("systemctl", """\
            echo "systemctl $*" >> "$LOG"
            case "$1" in
              is-active) [ -e "$STATE/timer" ] && { echo active; exit 0; } ; echo inactive; exit 3 ;;
              stop) rm -f "$STATE/timer"; exit 0 ;;
            esac
            exit 0""")
        self.fake("pgrep", """\
            echo "pgrep $*" >> "$LOG"
            [ -n "${BUSY:-}" ] && { echo 4242; exit 0; }
            exit 1""")
        self.fake("logger", 'echo "logger $*" >> "$LOG"; exit 0')

    def fake(self, name: str, body: str) -> None:
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + textwrap.dedent(body) + "\n", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_script(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        full = {
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "LOG": str(self.log),
            "STATE": str(self.state),
            **env,
        }
        return subprocess.run([str(self.dir / "script"), *args], env=full, text=True, capture_output=True, check=False)

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines()

    def rules(self) -> list[str]:
        chain = self.state / "chain"
        return chain.read_text(encoding="utf-8").splitlines() if chain.exists() else []


class OpenTests(Harness):
    def test_open_arms_the_timer_before_it_adds_any_rule(self) -> None:
        result = self.run_script("open", "10")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        timer = next(i for i, c in enumerate(calls) if c.startswith("systemd-run"))
        first_rule = next(i for i, c in enumerate(calls) if c.startswith("nft add rule"))
        self.assertLess(timer, first_rule)
        self.assertIn("--on-active=10min", calls[timer])
        self.assertIn("close", calls[timer])

    def test_open_adds_only_web_and_local_dns_and_nothing_else(self) -> None:
        self.run_script("open", "5")
        joined = "\n".join(self.rules())
        self.assertIn("tcp dport { 80, 443 }", joined)
        self.assertIn("127.0.0.53", joined)
        self.assertNotRegex(joined, r"tcp dport\\s*\\{?\\s*22\\b")
        self.assertNotIn("daddr 0.0.0.0/0", joined)
        self.assertTrue(all(rule.rstrip().endswith("accept") for rule in self.rules()))

    def test_open_refuses_when_the_timer_cannot_be_armed(self) -> None:
        result = self.run_script("open", "5", FAIL_TIMER="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rules(), [], "a window without a way to close it must never open")

    def test_open_refuses_while_the_gateway_or_a_container_runs(self) -> None:
        result = self.run_script("open", "5", BUSY="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.rules(), [])

    def test_open_refuses_an_unbounded_or_invalid_duration(self) -> None:
        for bad in ("0", "31", "abc", "-5", ""):
            result = self.run_script("open", bad)
            self.assertNotEqual(result.returncode, 0, bad)
            self.assertEqual(self.rules(), [], bad)

    def test_open_refuses_a_second_window(self) -> None:
        self.run_script("open", "5")
        again = self.run_script("open", "5")
        self.assertNotEqual(again.returncode, 0)

    def test_open_writes_an_audit_line(self) -> None:
        self.run_script("open", "5")
        self.assertTrue(any(c.startswith("logger") and "open" in c for c in self.calls()))


class CloseTests(Harness):
    def test_close_empties_the_chain_and_stops_the_timer(self) -> None:
        self.run_script("open", "5")
        result = self.run_script("close")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.rules(), [])
        self.assertFalse((self.state / "timer").exists())
        self.assertTrue(any(c.startswith("logger") and "close" in c for c in self.calls()))

    def test_close_is_idempotent(self) -> None:
        self.assertEqual(self.run_script("close").returncode, 0)
        self.assertEqual(self.run_script("close").returncode, 0)

    def test_status_reports_open_and_closed(self) -> None:
        self.assertIn("closed", self.run_script("status").stdout)
        self.run_script("open", "5")
        self.assertIn("open", self.run_script("status").stdout)


class TemplateTests(unittest.TestCase):
    def test_the_script_names_only_the_pinned_table_chain_and_uid(self) -> None:
        text = render()
        self.assertIn(G2["nft"]["table"], text)
        self.assertIn(G2["nft"]["window_chain"], text)
        self.assertNotIn("{{", text)
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("delete table", text)

    def test_the_script_uses_no_workaround(self) -> None:
        text = render()
        for word in ("iptables", "ufw", "setenforce", "--no-check"):
            self.assertNotIn(word, text)


if __name__ == "__main__":
    unittest.main()
