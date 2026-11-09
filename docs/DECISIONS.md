# Decisions

Short records of why the system is the way it is. Newest decisions supersede older ones; when a decision is replaced, its
entry is rewritten, not kept as history (git has the history).

1. **One dedicated server, never rebuilt.** The Hetzner CPX21 has a promotional price. Delete and rebuild protection are on in
   the Hetzner API. Configuration is Ansible; OpenTofu is not used for a single server.
2. **Zero extra cost.** The only recurring costs are the Claude subscription and the server. Free tiers only: R2 (10 GB),
   Tailscale personal, public GitHub with free Actions, Healthchecks free. Claude extra usage stays off; no API key, no API fallback.
3. **Access only through Tailscale.** The cloud firewall has no inbound rule; sshd is key-only, no root login, no forwarding.
   Break-glass is the Hetzner console.
4. **Trust tiers, not user-per-bot.** The axis is input trust times capability. Tier 0 (admin bot) has root and the cloud tokens and
   never reads untrusted content. Tier 1 (workers) read untrusted content, hold no credential and act only inside rootless
   containers. A profile is not an isolation boundary, so each tier has its own Linux account, state volume and policy.
5. **Hermes managed scope for policy.** Root-owned `/etc/hermes` (admin) and `/etc/hermes-worker` (worker) pin the settings the
   bot must not change. The worker's directory is selected by a root-owned systemd user-environment generator. Deny lists in
   `approvals.deny` are friction against mistakes only (the Hermes security documentation says so); real controls are
   permissions, tiers, audit and recoverability.
6. **Sandbox: stock rootless Podman with crun.** Hermes already applies capability dropping, `no-new-privileges`, tmpfs and
   cpu/memory/pids limits to the `docker` terminal backend; delegated cgroups make them enforceable. gVisor was dropped: it
   needed a private patch to run rootless, and there is no KVM for microVMs. Reconsider when upstream gVisor supports a delegated
   cgroup subtree.
7. **Brain outside, hands inside.** Workers use the owner's Claude subscription through the pinned plugin in their gateway;
   the login never enters a container. If a task needs the Claude CLI inside a container, use `claude setup-token` and inject
   it through an egress credential proxy, never as an environment variable of the container.
8. **Egress control where it means something.** Gateway accounts are held by nftables to a local proxy (admin: four named
   domains; worker: the same until mediated web access is added). Worker containers have no network device.
9. **Pin everything.** Hermes by tag and commit, the plugin by commit and manifest hash, the Claude CLI by version and
   hash, Python and Ansible by lock file, container images by digest, Actions by commit SHA.
10. **Backups are client-side encrypted and secret-free.** restic to R2, SQLite through its backup API, restore drill monthly.
11. **Bots learn by themselves.** Skills and memory are writable by the bots; the scanner stays on and the daily backup makes
    any bad write reversible. The approval gate returns before any untrusted input source (web, public issues) is enabled
    for the admin bot.
12. **The public repository is the source of truth.** Pull requests, free CI, branch protection and secret scanning. No CI job
    has a path to the host; the admin bot applies from `main`. Nothing that identifies the host or opens a door is published.
13. **Updates.** Security upgrades are automatic, reboots only in the Sunday window, Hermes pins move by pull request.
14. **Observability without a model.** A systemd collector and a no-agent Hermes cron job report state changes to Telegram.
