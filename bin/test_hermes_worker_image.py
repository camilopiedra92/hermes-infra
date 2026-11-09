"""The container image of the worker is pinned by digest in one place and loaded without network."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_worker"
IMAGE = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))["worker"]["image"]


class WorkerImagePinTests(unittest.TestCase):
    def test_the_image_is_pinned_by_registry_digest_and_by_image_id(self) -> None:
        self.assertRegex(IMAGE["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(IMAGE["id"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotEqual(IMAGE["digest"], IMAGE["id"])
        self.assertTrue(IMAGE["repository"].startswith("docker.io/"))

    def test_the_policy_takes_the_image_from_the_pin_and_names_no_tag(self) -> None:
        text = (ROLE / "templates" / "managed-config.yaml.j2").read_text(encoding="utf-8")
        image = re.search(r"^\s*docker_image:\s*(.+)$", text, re.MULTILINE)
        self.assertIsNotNone(image)
        self.assertEqual(image.group(1).strip().strip('"'), "{{ hermes_worker_image_id }}")
        self.assertFalse((ROLE / "files" / "managed-config.yaml").exists())
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("hermes_pins.worker.image.id", defaults)
        self.assertIn("hermes_pins.worker.image.digest", defaults)

    def test_the_image_is_pulled_by_digest_and_loaded_offline_only_when_missing(self) -> None:
        tasks = (ROLE / "tasks" / "image.yml").read_text(encoding="utf-8")
        self.assertIn("hermes_worker_image_pull", tasks)
        self.assertNotIn(":latest", tasks)
        self.assertEqual(tasks.count("hermes_worker_image_present.rc == 1"), 2)  # pull and load
        self.assertLess(tasks.index("podman, pull"), tasks.index("podman save --format"))
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertLess(main.index("image.yml"), main.index("Enable the worker gateway at boot"))

    def test_the_worker_runs_podman_through_its_user_manager(self) -> None:
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("systemd-run", defaults)


if __name__ == "__main__":
    unittest.main()
