"""The health collector reports state that is on the host and not in the repository, and the reverse."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "health"
SCRIPT = ROLE / "files" / "hermes-health"
EXPECTED = {
    "nft_tables": ["ip filter", "inet hermes_filter", "inet hermes_egress"],
    "unit_prefixes": ["hermes-", "tinyproxy"],
    "system_units": ["hermes-health.service", "tinyproxy-worker.service"],
    "accounts": ["hermesops", "hermes"],
    "network_ports": [22],
}
CLEAN = {
    ("nft", "list", "tables"): "table ip filter\ntable inet hermes_filter\ntable inet hermes_egress\n",
    ("getent", "passwd"): "root:x:0:0:r:/root:/bin/bash\nhermesops:x:1000:1000::/h:/bin/bash\nhermes:x:1001:1001::/h:/bin/bash\n",
    ("ss", "-ltnH"): (
        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:9119 0.0.0.0:*\n"
        "LISTEN 0 128 100.70.1.2%tailscale0:443 0.0.0.0:*\nLISTEN 0 128 [::]:22 [::]:*\n"
    ),
}


def completed(text: str) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, stdout=text, stderr="")


class DriftTests(unittest.TestCase):
    def collect(self, outputs: dict, units: list[str], expected: dict | None = None) -> list[str]:
        loader = importlib.machinery.SourceFileLoader("hermes_health", str(SCRIPT))
        spec = importlib.util.spec_from_loader("hermes_health", loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "expected-state.json"
            if expected is not False:
                manifest.write_text(json.dumps(expected or EXPECTED), encoding="utf-8")
            unit_dir = Path(tmp) / "units"
            unit_dir.mkdir()
            for name in units:
                (unit_dir / name).write_text("", encoding="utf-8")
            (unit_dir / "hermes-health.service.d").mkdir()
            with mock.patch.object(module, "EXPECTED", manifest), mock.patch.object(module, "UNIT_DIR", unit_dir), \
                    mock.patch.object(module, "run", lambda *cmd: completed(outputs[cmd])):
                problems: list[str] = []
                module.drift(problems, {})
                return problems

    def test_a_host_that_matches_the_manifest_has_no_drift(self) -> None:
        self.assertEqual(self.collect(CLEAN, ["hermes-health.service", "tinyproxy-worker.service", "ssh.service"]), [])

    def test_a_table_nobody_declared_is_reported(self) -> None:
        outputs = {**CLEAN, ("nft", "list", "tables"): CLEAN[("nft", "list", "tables")] + "table inet hermes_sandbox\n"}
        problems = self.collect(outputs, ["hermes-health.service", "tinyproxy-worker.service"])
        self.assertEqual(problems, ["drift: nftables table inet hermes_sandbox is on the host and not in the repository"])

    def test_a_declared_table_that_is_missing_is_reported(self) -> None:
        outputs = {**CLEAN, ("nft", "list", "tables"): "table ip filter\ntable inet hermes_filter\n"}
        problems = self.collect(outputs, ["hermes-health.service", "tinyproxy-worker.service"])
        self.assertEqual(problems, ["drift: nftables table inet hermes_egress is in the repository and not on the host"])

    def test_an_extra_hermes_unit_is_reported_and_other_units_are_not(self) -> None:
        problems = self.collect(CLEAN, ["hermes-health.service", "tinyproxy-worker.service", "hermes-old.service", "apparmor.service"])
        self.assertEqual(problems, ["drift: system unit hermes-old.service is on the host and not in the repository"])

    def test_an_extra_account_is_reported(self) -> None:
        outputs = {**CLEAN, ("getent", "passwd"): CLEAN[("getent", "passwd")] + "stranger:x:1005:1005::/h:/bin/sh\n"}
        problems = self.collect(outputs, ["hermes-health.service", "tinyproxy-worker.service"])
        self.assertEqual(problems, ["drift: account stranger is on the host and not in the repository"])

    def test_a_port_open_to_the_network_is_reported_but_loopback_and_tailnet_are_not(self) -> None:
        outputs = {**CLEAN, ("ss", "-ltnH"): CLEAN[("ss", "-ltnH")] + "LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n"}
        problems = self.collect(outputs, ["hermes-health.service", "tinyproxy-worker.service"])
        self.assertEqual(problems, ["drift: port open to the network 8080 is on the host and not in the repository"])

    def test_a_missing_manifest_is_a_problem_not_a_pass(self) -> None:
        problems = self.collect(CLEAN, [], expected=False)
        self.assertEqual(problems, ["there is no expected-state manifest to compare the host with"])


class ManifestTests(unittest.TestCase):
    def test_every_system_unit_template_of_the_repository_is_in_the_manifest(self) -> None:
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        user_units = {"hermes-serve.service", "hermes-tier-serve.service", "hermes-install-window"}
        for template in (ROOT / "infra" / "ansible" / "roles").rglob("*.j2"):
            name = template.name[:-3]
            if re.match(r"^(hermes-|tinyproxy-)[\w-]+\.(service|timer)$", name) and name not in user_units:
                if name == "tinyproxy-tier.service":
                    self.assertIn("'tinyproxy-'", defaults)
                else:
                    self.assertIn(name, defaults, f"{name} is installed by a role and missing from the manifest")

    def test_the_collector_unit_may_use_netlink_to_look(self) -> None:
        unit = (ROLE / "templates" / "hermes-health.service.j2").read_text(encoding="utf-8")
        self.assertIn("RestrictAddressFamilies=AF_NETLINK", unit)


if __name__ == "__main__":
    unittest.main()
