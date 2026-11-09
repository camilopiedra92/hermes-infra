"""The hermes_gateway role: the capped state volume first."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
G2 = PINS["egress"]
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_gateway"
GIB = 1024**3


class StateVolumePinTests(unittest.TestCase):
    def test_the_state_volume_is_sized_from_the_measured_install(self) -> None:
        state = PINS["state"]
        self.assertEqual(state["bytes"], 6 * GIB)
        self.assertEqual(state["inodes"], 262144)
        # The CI install used 1.41 GB and 38,403 inodes. The volume is a multiple of that.
        self.assertGreaterEqual(state["bytes"], 4 * 1_413_496_011)
        self.assertGreaterEqual(state["inodes"], 6 * 38_403)

    def test_hermes_home_is_the_mount_of_the_state_volume(self) -> None:
        self.assertEqual(PINS["state"]["mount"], PINS["install"]["hermes_home"])
        self.assertEqual(PINS["state"]["owner"], "hermes")
        self.assertEqual(PINS["state"]["mode"], "0700")

    def test_the_unit_name_is_what_systemd_derives_from_the_path(self) -> None:
        if shutil.which("systemd-escape"):
            expected = subprocess.run(
                ["systemd-escape", "-p", "--suffix=mount", PINS["state"]["mount"]],
                text=True, capture_output=True, check=True,
            ).stdout.strip()
            self.assertEqual(PINS["state"]["unit"], expected)
        else:
            self.assertEqual(PINS["state"]["unit"], "home-hermes-.hermes.mount")

    def test_the_state_volume_does_not_clash_with_the_worker_volumes(self) -> None:
        worker = ROOT / "infra" / "ansible" / "roles" / "hermes_worker" / "tasks" / "main.yml"
        text = worker.read_text(encoding="utf-8")
        for value in (PINS["state"]["image"], PINS["state"]["unit"]):
            self.assertNotIn(value, text)
        self.assertTrue(PINS["state"]["image"].startswith("/var/lib/hermes/"))

    def test_all_capped_images_together_leave_the_root_margin(self) -> None:
        # The root disk is 75 GB (docs/ARCHITECTURE.md). Admin state, worker state and worker container storage.
        live = PINS["state"]["bytes"] + 6 * GIB + 4 * GIB
        self.assertLess(live, 75 * 10**9 * 30 // 100)


class RoleTests(unittest.TestCase):
    def test_the_state_volume_is_created_by_the_shared_role(self) -> None:
        text = (ROLE / "tasks" / "state.yml").read_text(encoding="utf-8")
        self.assertIn("name: capped_volume", text)
        for field in ("image", "mount", "bytes", "inodes", "unit", "mode", "owner"):
            self.assertIn(f"hermes_pins.state.{field}", text)
        self.assertNotIn("mkfs", text)
        self.assertNotIn("losetup", text)

    def test_the_role_loads_the_pins_the_ci_install_uses(self) -> None:
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("bin/hermes/pins.json", main)
        self.assertIn("name: hermes_pins", main)

    def test_the_role_requires_the_service_user_and_its_home_before_it_mounts(self) -> None:
        # Creating /home/hermes/.hermes would create /home/hermes as root if the user were missing.
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("ansible.builtin.getent", main)
        self.assertIn("dirname", main)
        self.assertLess(main.index("getent"), main.index("import_tasks: state.yml"))

    def test_the_role_is_in_the_play_after_the_service_user_with_its_own_tag(self) -> None:
        site = (ROOT / "infra" / "ansible" / "site.yml").read_text(encoding="utf-8")
        self.assertIn("role: hermes_gateway", site)
        self.assertIn("tags: [gateway]", site)
        self.assertLess(site.index("role: service_user"), site.index("role: hermes_gateway"))

    def test_the_role_holds_no_secret_value(self) -> None:
        shapes = (r"\d{6,12}:[A-Za-z0-9_-]{30,}", r"tskey-", r"sk-ant-", r"github_pat_", r"cfat_", r"[0-9a-f]{64}")
        for path in ROLE.rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8")
                for shape in shapes:
                    self.assertIsNone(re.search(shape, text), f"{path.relative_to(ROLE)}: {shape}")

    def test_no_play_starts_the_admin_gateway(self) -> None:
        # The terminal tool of the gateway blocks it, and a restart belongs to the operator (docs/OPERATIONS.md).
        unit = PINS["gateway"]["unit"]
        for path in ROLE.rglob("*.yml"):
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, rf"name: .*{re.escape(unit)}[^\n]*\n(?:[^\n]*\n){{0,6}}?\s+state: (started|restarted)", str(path))
            self.assertNotIn("enable --now", text)


if __name__ == "__main__":
    unittest.main()
