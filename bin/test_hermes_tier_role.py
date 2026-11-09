"""One role builds every agent tier; the sandbox image is pinned by digest in one place and loaded without network."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "hermes_tier"
PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
IMAGE = PINS["sandbox"]["image"]


class SandboxImagePinTests(unittest.TestCase):
    def test_the_image_is_pinned_by_registry_digest_and_by_image_id(self) -> None:
        self.assertRegex(IMAGE["digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(IMAGE["id"], r"^sha256:[0-9a-f]{64}$")
        self.assertNotEqual(IMAGE["digest"], IMAGE["id"])
        self.assertTrue(IMAGE["repository"].startswith("docker.io/"))

    def test_the_policy_takes_the_image_from_the_pin_and_names_no_tag(self) -> None:
        text = (ROLE / "templates" / "managed-config.yaml.j2").read_text(encoding="utf-8")
        image = re.search(r"^\s*docker_image:\s*(.+)$", text, re.MULTILINE)
        self.assertIsNotNone(image)
        self.assertEqual(image.group(1).strip().strip('"'), "{{ hermes_tier_image_id }}")
        self.assertFalse((ROLE / "files" / "managed-config.yaml").exists())
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("hermes_pins.sandbox.image.id", defaults)
        self.assertIn("hermes_pins.sandbox.image.digest", defaults)

    def test_the_image_is_pulled_by_digest_and_loaded_offline_only_when_missing(self) -> None:
        tasks = (ROLE / "tasks" / "image.yml").read_text(encoding="utf-8")
        self.assertIn("hermes_tier_image_pull", tasks)
        self.assertNotIn(":latest", tasks)
        self.assertEqual(tasks.count("hermes_tier_image_present.rc == 1"), 2)  # pull and load
        self.assertLess(tasks.index("podman, pull"), tasks.index("podman save --format"))
        main = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertLess(main.index("image.yml"), main.index("Enable the tier gateway at boot"))

    def test_a_sandbox_tier_runs_podman_through_its_user_manager(self) -> None:
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("systemd-run", defaults)


class TierDefinitionTests(unittest.TestCase):
    def test_every_tier_has_its_own_account_and_its_own_proxy_port(self) -> None:
        tiers = PINS["tiers"]
        self.assertIn("worker", tiers)
        users = [t["user"] for t in tiers.values()]
        ports = [t["proxy_port"] for t in tiers.values()] + [PINS["egress"]["nft"]["proxy_port"]]
        serve = [t[k] for t in tiers.values() for k in ("serve_port", "serve_https_port") if k in t]
        self.assertEqual(len(users), len(set(users)))
        self.assertNotIn(PINS["egress"]["user"]["name"], users)
        self.assertEqual(len(ports), len(set(ports)))
        self.assertEqual(len(serve), len(set(serve)))

    def test_every_tier_lists_its_toolsets_and_a_sandbox_tier_sizes_its_container_storage(self) -> None:
        for name, tier in PINS["tiers"].items():
            self.assertTrue(tier["toolsets"], name)
            self.assertIn("disabled_toolsets", tier, name)
            if tier["sandbox"]:
                for key in ("subid_start", "subid_count", "containers_bytes", "containers_inodes"):
                    self.assertIn(key, tier, name)
            else:
                self.assertNotIn("terminal", tier["toolsets"], f"{name}: a tier without a sandbox has no shell")
                self.assertNotIn("file", tier["toolsets"], name)

    def test_the_unit_name_of_each_state_mount_is_what_systemd_derives_from_the_path(self) -> None:
        import shutil
        import subprocess

        if not shutil.which("systemd-escape"):
            self.skipTest("systemd-escape is not available")
        defaults = (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        self.assertIn('unit: "home-{{ hermes_tier_user }}-.hermes.mount"', defaults)
        for tier in PINS["tiers"].values():
            expected = subprocess.run(
                ["systemd-escape", "-p", "--suffix=mount", f"/home/{tier['user']}/.hermes"],
                text=True, capture_output=True, check=True,
            ).stdout.strip()
            self.assertEqual(expected, f"home-{tier['user']}-.hermes.mount")

    def test_backup_health_and_proxy_generator_list_the_tiers_from_the_pins_not_from_a_fixed_name(self) -> None:
        roles = ROOT / "infra" / "ansible" / "roles"
        for path in (
            roles / "backup" / "templates" / "hermes-backup.service.j2",
            roles / "backup" / "files" / "hermes-backup",
            roles / "health" / "files" / "hermes-health",
            roles / "health" / "templates" / "hermes-health.service.j2",
            roles / "hermes_gateway" / "templates" / "egress-proxy-generator.j2",
        ):
            text = path.read_text(encoding="utf-8")
            for tier in PINS["tiers"].values():
                self.assertNotIn(tier["user"], text, f"{path.name} names an account instead of reading the pins")
        self.assertIn("hermes_pins.tiers", (roles / "backup" / "defaults" / "main.yml").read_text(encoding="utf-8"))

    def test_a_tier_with_remote_mcp_servers_may_reach_exactly_their_hosts_and_asks_before_every_write(self) -> None:
        from urllib.parse import urlparse

        assistant = PINS["tiers"]["assistant"]
        for name, server in assistant["mcp_servers"].items():
            self.assertIn(urlparse(server["url"]).hostname, assistant["extra_domains"], name)
            self.assertIn(f"mcp-{name}", assistant["toolsets"], name)
        template = (ROLE / "templates" / "managed-config.yaml.j2").read_text(encoding="utf-8")
        self.assertIn("trust: untrusted", template)
        self.assertNotIn("client_secret: \"", template.replace('"${GOOGLE_OAUTH_CLIENT_SECRET}"', ""))
        self.assertNotIn("serve_port", assistant, "the Desktop backend of a tier is opt-in, with its own ACL and firewall port")


if __name__ == "__main__":
    unittest.main()
