"""Service sandboxing: root services share one sandbox; user units carry no systemd sandbox."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROLES = Path(__file__).resolve().parent.parent / "infra" / "ansible" / "roles"


def text(*parts: str) -> str:
    return ROLES.joinpath(*parts).read_text(encoding="utf-8")


def directives(content: str) -> set[str]:
    return {line.split("=", 1)[0] for line in content.splitlines() if "=" in line and not line.startswith(("#", "Environment"))}


class RootServiceSandboxTests(unittest.TestCase):
    def test_the_common_sandbox_denies_the_dangerous_interfaces(self) -> None:
        sandbox = text("hardening", "templates", "service-sandbox.conf.j2")
        for line in (
            "ProtectKernelModules=true", "ProtectClock=true", "PrivateDevices=true", "MemoryDenyWriteExecute=true",
            "RestrictNamespaces=true", "SystemCallArchitectures=native", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        ):
            self.assertIn(line, sandbox)
        self.assertIn("CAP_SYS_MODULE", sandbox)
        self.assertIn("CAP_SYS_BOOT", sandbox)

    def test_every_root_collector_and_backup_unit_gets_it(self) -> None:
        listed = set(re.findall(r"^\s+- (hermes-[\w-]+)$", text("hardening", "defaults", "main.yml"), re.M))
        self.assertEqual(listed, {"hermes-health", "hermes-backup", "hermes-restore-drill"})
        tasks = text("hardening", "tasks", "main.yml")
        self.assertIn("50-sandbox.conf", tasks)
        for unit in listed:
            owner = "health" if unit == "hermes-health" else "backup"
            self.assertTrue((ROLES / owner / "templates" / f"{unit}.service.j2").exists(), unit)

    def test_no_unit_asks_for_what_the_sandbox_removes(self) -> None:
        sandbox = directives(text("hardening", "templates", "service-sandbox.conf.j2"))
        for owner, unit in (("health", "hermes-health"), ("backup", "hermes-backup"), ("backup", "hermes-restore-drill")):
            own = directives(text(owner, "templates", f"{unit}.service.j2"))
            # These lists add up with the shared sandbox, so a unit may extend them.
            clash = (own & sandbox) - {"SystemCallFilter", "CapabilityBoundingSet", "RestrictAddressFamilies"}
            self.assertFalse(clash, f"{unit} repeats {clash}")


class AttackSurfaceTests(unittest.TestCase):
    def test_unused_image_services_are_purged_and_container_auto_update_is_masked(self) -> None:
        defaults = text("hardening", "defaults", "main.yml")
        for package in ("snapd", "open-iscsi", "multipath-tools", "open-vm-tools", "apport", "pollinate", "lxd-installer"):
            self.assertRegex(defaults, re.compile(rf"^\s+- {package}$", re.M), package)
        tasks = text("hardening", "tasks", "main.yml")
        self.assertIn("purge: true", tasks)
        for unit in ("podman-auto-update.timer", "podman-restart.service"):
            self.assertIn(unit, tasks)
        self.assertIn("kernel.core_pattern = |/bin/false", text("hardening", "files", "60-hermes-hardening.conf"))

    def test_the_reboot_flag_package_stays(self) -> None:
        # update-notifier-common writes /run/reboot-required, which the health collector and the reboot window read.
        self.assertNotIn("update-notifier-common", text("hardening", "defaults", "main.yml"))


FORBIDDEN_IN_USER_UNITS = (
    "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectProc", "ProcSubset",
    "ReadWritePaths", "RestrictNamespaces", "SystemCallFilter", "ProtectClock", "ProtectKernelModules",
    "ProtectKernelLogs", "ProtectKernelTunables", "ProtectControlGroups", "CapabilityBoundingSet",
)


class UserUnitSandboxTests(unittest.TestCase):
    def test_user_units_carry_no_systemd_sandbox_option(self) -> None:
        for owner, name in (
            ("hermes_gateway", "hermes-serve.service.j2"),
            ("hermes_tier", "hermes-tier-serve.service.j2"),
            ("hermes_gateway", "gateway-limits.conf.j2"),
        ):
            active = [line.strip() for line in text(owner, "templates", name).splitlines() if not line.lstrip().startswith("#")]
            for option in FORBIDDEN_IN_USER_UNITS:
                self.assertFalse(
                    [line for line in active if line.startswith(f"{option}=")],
                    f"{name} sets {option}: in a user manager it runs the service in a user namespace, which maps "
                    "root-owned files to nobody (ssh refuses its config), and rootless Podman needs the setuid newuidmap",
                )


if __name__ == "__main__":
    unittest.main()
