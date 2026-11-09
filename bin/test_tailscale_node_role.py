"""The tailscale_node role must match the host: Tailscale SSH is on."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ROLE = ROOT / "infra" / "ansible" / "roles" / "tailscale_node"


class TailscaleNodeRoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
        self.tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")

    def test_tailscale_ssh_is_on_by_default(self) -> None:
        # The host runs Tailscale SSH. A default of false would switch it off at the
        # next site.yml and cut the tailnet path.
        self.assertIs(self.defaults["tailscale_node_run_ssh"], True)

    def test_losing_the_current_ssh_session_is_an_explicit_opt_in(self) -> None:
        # `tailscale set --ssh=true` over Tailscale refuses without --accept-risk=lose-ssh.
        # The flag is never on by default and is passed only when the variable is set.
        self.assertIs(self.defaults["tailscale_node_accept_lose_ssh"], False)
        self.assertIn("--accept-risk=lose-ssh", self.tasks)
        self.assertIn("tailscale_node_accept_lose_ssh", self.tasks)

    def test_the_command_does_not_rewrite_a_matching_host(self) -> None:
        self.assertIn(".RunSSH != tailscale_node_run_ssh", self.tasks)


if __name__ == "__main__":
    unittest.main()
