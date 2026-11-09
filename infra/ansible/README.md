# Ansible

Configures the Hermes host. `site.yml` is the host play. Nothing here
applies itself. The operator runs it from a machine on the tailnet,
after `--check --diff`, with the dead-man in
[docs/runbooks/bootstrap-access.md](../../docs/runbooks/bootstrap-access.md).

Connection is OpenSSH as user `hermesops` over the tailnet.
Operator connection options are in
[operator-access.md](../../docs/runbooks/operator-access.md).
`--check --diff` is necessary and not sufficient: modules without
check-mode support do not simulate, and a diff of a secret task is
forbidden (`no_log`, `diff: false`). The first check skips files whose
parent directory does not exist yet (auditd's `/etc/audit` before the
package is installed). A second check, after apply, must be empty.

The daily drift timer runs check mode on the secret-free play
and alerts when it is not idempotent. It does not apply.

| Role | ADR | State |
| --- | --- | --- |
| access | 0006 | Written. Checks `hermesops` (uid 1000), sudo drop-in, sudo log retention. Does not create the user. |
| tailscale_node | 0006 | Written. Tailscale SSH off, hostname. |
| nftables | 0007 | Written. Host input firewall. |
| auditd | 0009 | Written. Rules, auditd and journald disk caps. AppArmor, unattended-upgrades and OpenSCAP are not in this role. |
| Capped state volume, session prune timer | 0015, 0022 | Not written. |
| rootless_sandbox | 0012 | Written. Rootless Docker and `runsc` for `hermes`, capped filesystems, nftables counters, inspect timer. Does not enable Hermes tools. |
| Gateway unit and pins | 0008 | Not written. |
| restic timer | 0004 | Not written. |
| heartbeat and budget counter | 0005, 0014 | Not written. |

Do not install a second Docker daemon, mount `/var/run/docker.sock`, or enable
the Hermes gateway container from the upstream image quick start.
