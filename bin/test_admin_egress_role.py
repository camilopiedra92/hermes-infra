"""The administration account (the hands of the admin agent) reaches the internet only through its own allowlist proxy."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "admin_egress"
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
EGRESS = PINS["admin"]["egress"]


def read(*parts: str) -> str:
    return ROLE.joinpath(*parts).read_text(encoding="utf-8")


class AdminEgressTests(unittest.TestCase):
    def test_the_proxy_port_is_unique_across_every_egress_proxy(self) -> None:
        ports = [PINS["egress"]["nft"]["proxy_port"], *(tier["proxy_port"] for tier in PINS["tiers"].values())]
        self.assertNotIn(EGRESS["proxy_port"], ports)

    def test_the_allowlist_names_exact_hosts_only(self) -> None:
        for host in EGRESS["domains"]:
            self.assertRegex(host, r"^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}$")
            self.assertNotIn("*", host)
        self.assertEqual(len(EGRESS["domains"]), len(set(EGRESS["domains"])))
        # General-purpose publishing or paste hosts would reopen the exfiltration path the hold closes.
        for forbidden in ("gist.github.com", "pastebin.com", "transfer.sh", "githubusercontent.com"):
            self.assertNotIn(forbidden, EGRESS["domains"])

    def test_the_filter_denies_by_default_and_the_proxy_is_tls_only(self) -> None:
        conf = read("templates", "tinyproxy-ops.conf.j2")
        self.assertIn("FilterDefaultDeny Yes", conf)
        self.assertIn("ConnectPort 443", conf)
        self.assertIn("Allow {{ admin_egress_proxy_address }}", conf)
        self.assertNotRegex(conf, r"(?m)^ConnectPort (?!443$)")

    def test_the_hold_matches_the_account_and_drops_everything_else(self) -> None:
        nft = read("templates", "ops.nft.j2")
        self.assertIn("meta skuid {{ hermes_pins.admin.uid }}", nft)
        lines = [line.strip() for line in nft.splitlines() if "meta skuid" in line]
        self.assertTrue(lines[-1].endswith("drop"), "the last rule must drop")
        for line in lines[:-1]:
            self.assertIn('oifname "lo"', line, "only loopback may be accepted")

    def test_sessions_get_the_proxy_from_sshd_for_that_account_only(self) -> None:
        conf = read("templates", "sshd-ops-proxy.conf.j2")
        self.assertIn("Match User {{ hermes_pins.admin.user }}", conf)
        self.assertIn("{{ hermes_pins.admin.egress.proxy_port }}", conf)
        self.assertIn("NO_PROXY=localhost,127.0.0.1,::1", conf)

    def test_the_hold_is_loaded_last_so_the_proxy_exists_before_the_account_is_held(self) -> None:
        tasks = read("tasks", "main.yml")
        self.assertLess(tasks.index("Enable the proxy"), tasks.index("Hold the administration account"))
        self.assertLess(tasks.index("Point the sessions"), tasks.index("Hold the administration account"))
        self.assertIn("validate: /usr/sbin/nft -c -f %s", tasks)

    def test_the_health_collector_watches_the_proxy(self) -> None:
        collector = (ROOT / "infra" / "ansible" / "roles" / "health" / "files" / "hermes-health").read_text(encoding="utf-8")
        self.assertIn('"tinyproxy-ops"', collector)

    def test_the_role_has_its_own_tag_and_no_ci_job_runs_it(self) -> None:
        site = (ROOT / "infra" / "ansible" / "site.yml").read_text(encoding="utf-8")
        self.assertRegex(site, r"role: admin_egress\s+tags: \[ops_egress\]")
        for workflow in (ROOT / ".github").rglob("*"):
            if workflow.is_file():
                self.assertNotIn("ops_egress", workflow.read_text(encoding="utf-8"), str(workflow))


class AskHelperTests(unittest.TestCase):
    TEMPLATE = (ROOT / "infra" / "ansible" / "roles" / "hermes_tier" / "templates" / "hermes-ask-tier.j2").read_text(encoding="utf-8")

    def test_only_the_worker_can_be_asked_never_the_tier_that_holds_personal_data(self) -> None:
        self.assertTrue(PINS["tiers"]["worker"].get("ask_helper"))
        self.assertFalse(PINS["tiers"]["assistant"].get("ask_helper", False))

    def test_the_prompt_travels_on_stdin_and_the_answer_is_fenced_as_untrusted(self) -> None:
        self.assertIn("--query-file -", self.TEMPLATE)
        self.assertIn("systemd-run --user --pipe --wait", self.TEMPLATE)
        self.assertRegex(self.TEMPLATE, r"echo \"=== UNTRUSTED OUTPUT")
        self.assertRegex(self.TEMPLATE, r"echo \"=== END OF UNTRUSTED OUTPUT")
        self.assertIn('exit "$status"', self.TEMPLATE)

    def test_the_helper_is_usable_by_the_admin_bot_account_only(self) -> None:
        tasks = (ROOT / "infra" / "ansible" / "roles" / "hermes_tier" / "tasks" / "main.yml").read_text(encoding="utf-8")
        block = tasks[tasks.index("Install the helper that lets"):]
        self.assertIn('group: "{{ hermes_pins.state.owner }}"', block)
        self.assertIn('mode: "0750"', block)
        self.assertIn("validate: sh -n %s", block)


if __name__ == "__main__":
    unittest.main()
