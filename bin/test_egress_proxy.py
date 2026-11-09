#!/usr/bin/env python3
"""The proxy that is the only way out for the service user: what is rendered, and what it allows."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
HERMES = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
G2 = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))["egress"]
TASKS = (ROLE / "tasks" / "egress.yml").read_text(encoding="utf-8")


def template(name: str) -> str:
    return (ROLE / "templates" / name).read_text(encoding="utf-8")


def _fill(text: str) -> str:
    values = {
        "ansible_managed": "managed",
        "hermes_pins.egress.proxy_user": HERMES["egress"]["proxy_user"],
        "hermes_pins.state.owner": HERMES["state"]["owner"],
        "hermes_pins.egress.nft.proxy_address": G2["nft"]["proxy_address"],
        "hermes_pins.egress.nft.proxy_port": str(G2["nft"]["proxy_port"]),
        "hermes_gateway_uid": str(G2["user"]["uid"]),
    }
    for key, value in values.items():
        text = text.replace("{{ " + key + " }}", value)
    return text


def render_conf(filter_path: str = "/etc/tinyproxy/hermes-allow.filter") -> str:
    text = _fill(template("tinyproxy.conf.j2"))
    return text.replace("/etc/tinyproxy/hermes-allow.filter", filter_path)


def render_filter(domains: list[str] | None = None) -> str:
    lines = [f"^{re.escape(host)}$" for host in (domains if domains is not None else HERMES["egress"]["domains"])]
    return "\n".join(lines) + "\n"


def render_dropin() -> str:
    return _fill(template("tinyproxy.service-dropin.conf.j2"))


def render_gateway_env() -> str:
    return _fill(template("gateway-egress.conf.j2"))


def directives(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


class AllowedNamesTests(unittest.TestCase):
    def test_the_list_is_the_four_names_the_pinned_hermes_needs(self) -> None:
        self.assertEqual(
            sorted(HERMES["egress"]["domains"]),
            ["api.anthropic.com", "api.telegram.org", "console.anthropic.com", "platform.claude.com"],
        )

    def test_every_name_is_a_bare_host(self) -> None:
        for host in HERMES["egress"]["domains"]:
            self.assertRegex(host, r"^[a-z0-9]+(\.[a-z0-9-]+)+$", "no wildcard, scheme, path or port")

    def test_the_filter_has_one_anchored_expression_per_name_and_nothing_else(self) -> None:
        lines = render_filter().splitlines()
        self.assertEqual(len(lines), len(HERMES["egress"]["domains"]))
        for line in lines:
            self.assertTrue(line.startswith("^") and line.endswith("$"), line)
            self.assertNotIn(".*", line)
            self.assertNotIn("|", line)
        # A dot in a name is a dot, not "any character".
        self.assertIn(r"^api\.telegram\.org$", lines)
        self.assertIsNone(re.search(lines[0], "apixtelegramxorg"))

    def test_the_template_of_the_filter_is_built_from_the_pins(self) -> None:
        text = template("tinyproxy-allow.filter.j2")
        self.assertIn("hermes_pins.egress.domains", text)
        self.assertIn("regex_escape", text)


class ProxyConfigTests(unittest.TestCase):
    def test_it_listens_on_loopback_only_for_loopback_and_on_the_pinned_port(self) -> None:
        conf = directives(render_conf())
        self.assertIn(f"Listen {G2['nft']['proxy_address']}", conf)
        self.assertIn(f"Port {G2['nft']['proxy_port']}", conf)
        self.assertEqual([x for x in conf if x.startswith("Allow ")], [f"Allow {G2['nft']['proxy_address']}"])
        self.assertEqual(G2["nft"]["proxy_address"], "127.0.0.1")

    def test_only_port_443_and_only_the_listed_names_and_no_extras(self) -> None:
        conf = directives(render_conf())
        self.assertEqual([x for x in conf if x.startswith("ConnectPort")], ["ConnectPort 443"])
        for line in ("FilterDefaultDeny Yes", "FilterURLs Off", "FilterType ere", "DisableViaHeader Yes"):
            self.assertIn(line, conf)
        for forbidden in ("Upstream", "StatFile", "ReversePath", "XTinyproxy", "BasicAuth", "AddHeader"):
            self.assertFalse([x for x in conf if x.startswith(forbidden)], forbidden)

    def test_it_runs_as_its_own_user_and_logs_without_a_file_of_its_own(self) -> None:
        conf = directives(render_conf())
        self.assertIn(f"User {HERMES['egress']['proxy_user']}", conf)
        self.assertNotEqual(HERMES["egress"]["proxy_user"], HERMES["state"]["owner"], "the uid is the held one")
        self.assertIn("LogLevel Info", conf)
        self.assertFalse([x for x in conf if x.startswith("LogFile")])


class UnitAndEnvironmentTests(unittest.TestCase):
    def test_the_proxy_is_up_before_the_session_and_fails_closed(self) -> None:
        text = render_dropin()
        self.assertIn("After=nftables.service", text)
        self.assertIn("Requires=nftables.service", text)
        self.assertIn(f"Before=user@{G2['user']['uid']}.service", text)
        # The packaged unit runs it in the foreground with -d; the drop-in says so instead of relying on it.
        self.assertIn("ExecStart=\nExecStart=/usr/bin/tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf", text)
        for hardening in ("NoNewPrivileges=yes", "ProtectSystem=strict", "PrivateTmp=yes", "ProtectHome=yes"):
            self.assertIn(hardening, text)

    def test_the_proxy_has_no_ipv6_sockets_so_it_goes_straight_to_the_reliable_address(self) -> None:
        families = [x for x in directives(render_dropin()) if x.startswith("RestrictAddressFamilies=")]
        self.assertEqual(families, ["RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK"])

    def test_the_unit_dropin_holds_no_proxy_so_the_account_generator_decides(self) -> None:
        env = render_gateway_env()
        names = [x.split("=", 1)[0].removeprefix("Environment=").strip('"') for x in directives(env) if x.startswith("Environment=")]
        self.assertNotIn("HTTPS_PROXY", names)
        self.assertNotIn("HTTP_PROXY", names, "nothing needs plain HTTP, and the proxy forwards it to port 80")
        self.assertIn("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", env)

    def test_each_account_gets_its_own_proxy_from_a_root_owned_generator(self) -> None:
        import os
        import subprocess
        import tempfile

        worker = HERMES["egress"]["worker"]
        script = _fill(template("egress-proxy-generator.j2")).replace(
            "{{ hermes_pins.egress.user.name }}", HERMES["egress"]["user"]["name"]
        ).replace("{{ hermes_pins.egress.worker.user }}", worker["user"]).replace(
            "{{ hermes_pins.egress.worker.proxy_port }}", str(worker["proxy_port"])
        )
        expected = {
            HERMES["egress"]["user"]["name"]: HERMES["egress"]["nft"]["proxy_port"],
            worker["user"]: worker["proxy_port"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            for account, port in {**expected, "someone": None}.items():
                fake = Path(tmp) / "id"
                fake.write_text(f"#!/bin/sh\necho {account}\n", encoding="utf-8")
                fake.chmod(0o755)
                out = subprocess.run(
                    ["/bin/sh", "-c", script], env={"PATH": f"{tmp}:/usr/bin:/bin"}, capture_output=True, text=True, check=True
                ).stdout
                if port is None:
                    self.assertEqual(out, "", "an unknown account gets no proxy variables")
                else:
                    self.assertIn(f"HTTPS_PROXY=http://127.0.0.1:{port}", out)
                    self.assertIn("NO_PROXY=localhost,127.0.0.1,::1", out)
        self.assertNotEqual(worker["proxy_port"], HERMES["egress"]["nft"]["proxy_port"])
        block = TASKS[TASKS.index("Point each account at its own proxy") :]
        self.assertIn("owner: root", block)

    def test_the_worker_may_reach_the_admin_names_plus_only_the_search_api(self) -> None:
        self.assertEqual(HERMES["egress"]["worker"]["extra_domains"], ["api.keenable.ai"])
        proxy = (ROOT / "infra" / "ansible" / "roles" / "hermes_worker" / "templates" / "tinyproxy-worker-allow.filter.j2").read_text(encoding="utf-8")
        self.assertIn("hermes_pins.egress.domains + hermes_pins.egress.worker.extra_domains", proxy)

    def test_telegram_has_its_own_explicit_proxy_in_the_managed_environment(self) -> None:
        env = _fill(template("managed.env.j2"))
        self.assertIn(f"TELEGRAM_PROXY=http://{G2['nft']['proxy_address']}:{G2['nft']['proxy_port']}", env)

    def test_it_runs_only_when_asked_for_and_is_installed_from_the_archive(self) -> None:
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertRegex(main, r"import_tasks: egress\.yml\s*\n\s*tags: \[egress, never\]")
        self.assertIn("name: tinyproxy", TASKS)
        self.assertNotIn("get_url", TASKS)
        self.assertNotIn("pip", TASKS)


if __name__ == "__main__":
    unittest.main()
