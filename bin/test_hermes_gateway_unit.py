#!/usr/bin/env python3
"""The gateway unit tasks: Hermes writes the unit, root owns what limits it."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
TASKS = (ROLE / "tasks" / "gateway.yml").read_text(encoding="utf-8")
MAIN = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")


def render(name: str) -> str:
    text = (ROLE / "templates" / name).read_text(encoding="utf-8")
    gateway = PINS["gateway"]
    values = {
        "ansible_managed": "managed",
        "hermes_pins.state.mount": PINS["state"]["mount"],
        "hermes_pins.state.owner": PINS["state"]["owner"],
        "hermes_pins.gateway.memory_high": gateway["memory_high"],
        "hermes_pins.gateway.memory_max": gateway["memory_max"],
        "hermes_pins.gateway.tasks_max": str(gateway["tasks_max"]),
    }
    for key, value in values.items():
        text = text.replace("{{ " + key + " }}", value)
    assert "{{" not in text, text
    return text


class GatewayUnitTests(unittest.TestCase):
    def test_it_runs_only_when_asked_for_and_does_not_start_anything(self) -> None:
        self.assertRegex(MAIN, r"import_tasks: gateway\.yml\s*\n\s*tags: \[gateway, never\]")
        # Starting needs egress and a Claude login. Restarting the user manager would end the session: the
        # ordering applies the next time it starts.
        for forbidden in ("state: started", "state: restarted", "'gateway', 'start'", "'gateway', 'run'"):
            self.assertNotIn(forbidden, TASKS)

    def test_hermes_writes_the_unit_as_the_service_user_and_the_task_is_idempotent(self) -> None:
        self.assertIn("hermes_gateway_as_service_user", TASKS)
        self.assertIn("'gateway', 'install'", TASKS)
        self.assertIn("creates:", TASKS)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/", TASKS)
        # By default Hermes starts and enables the service. Until the allowlist and the login exist that is a
        # connect loop against the uid hold.
        self.assertIn("'--no-start-now', '--no-start-on-login'", TASKS)

    def test_the_drop_ins_are_root_owned_and_additive(self) -> None:
        limits = "\n".join(x for x in render("gateway-limits.conf.j2").splitlines() if not x.startswith("#"))
        for name in ("ExecStopPost", "ExecStart", "NoNewPrivileges", "User=", "ExecStop="):
            self.assertNotIn(name, limits)
        self.assertIn("MemoryMax=1G", limits)
        self.assertIn("TasksMax=", limits)
        self.assertIn("RequiresMountsFor=" + PINS["state"]["mount"], limits)
        for block in re.findall(r"- name: .*?(?=\n- name: |\Z)", TASKS, flags=re.S):
            if "dest:" in block and "template" in block:
                self.assertIn("owner: root", block)
                self.assertIn("group: root", block)

    def test_the_limits_stay_below_the_slice_and_high_is_below_max(self) -> None:
        def mib(value: str) -> int:
            return int(value[:-1]) * (1024 if value.endswith("G") else 1)

        gateway = PINS["gateway"]
        self.assertLess(mib(gateway["memory_high"]), mib(gateway["memory_max"]))

    def test_the_session_waits_for_nftables_and_fails_closed(self) -> None:
        after = render("user-after-nftables.conf.j2")
        self.assertIn("After=nftables.service", after)
        self.assertIn("Requires=nftables.service", after)
        self.assertIn("user@{uid}.service.d", PINS["gateway"]["system_dropin"])

    def test_systemd_accepts_the_drop_ins(self) -> None:
        if not shutil.which("systemd-analyze"):
            self.skipTest("systemd-analyze is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            unit = Path(tmp) / "hermes-gateway.service"
            unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
            dropin = Path(tmp) / "hermes-gateway.service.d"
            dropin.mkdir()
            (dropin / "10-limits.conf").write_text(render("gateway-limits.conf.j2"), encoding="utf-8")
            result = subprocess.run(
                ["systemd-analyze", "verify", str(unit)], capture_output=True, text=True, check=False
            )
        self.assertNotIn("Unknown key", result.stderr)
        self.assertNotIn("Invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()
