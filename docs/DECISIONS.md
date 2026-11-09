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
8. **Egress control where it means something.** Each gateway account is held by nftables to its own local proxy that allows
   named domains only (admin: four; worker: the same plus the search API). Separate proxies keep the worker's needs from
   widening the admin's allowlist. Worker containers have no network device.
8a. **Web access for the worker is mediated.** `web_search` and `web_extract` use one pinned free keyless vendor (Keenable) that
    fetches pages itself and refuses private and internal addresses, so the worker never connects to an arbitrary host and
    the tailnet is unreachable through it. Trade-off: queries and URLs are visible to that vendor, and the free tier is rate
    limited. Move to a self-hosted engine only if that becomes a problem. The admin bot has no web tools.
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
15. **One Desktop connection per trust tier.** Hermes Desktop lists the bots of every registered gateway side by side and keeps
    mentions and delegation gateway-local, because crossing a backend changes filesystem, credentials, tools and trust (official
    multi-connection documentation). So each tier exposes its own loopback `hermes serve` (admin on 9119, worker on 9120, assistant on 9121),
    published by Tailscale Serve on its own HTTPS port (443, 8443, 8444) with its own sign-in, and the owner registers each as a
    gateway. Bots of the same tier are profiles of that tier's instance. Putting a worker bot into the admin instance as a
    profile was rejected: profiles share one Linux account, so it would share the admin's credentials and host access.
16. **The worker image is pinned by digest, and runs by image ID.** The admin pulls `python@sha256:<amd64 manifest>` and the
    worker loads it offline (it has no registry egress). A save and load recompress the layers, so a registry digest cannot
    survive the transfer; the image ID (the sha256 of the image config, which covers every layer) does, and the load checks it.
    Both values live in `bin/hermes/pins.json`; the policy names the ID, so Hermes never tries to pull.
17. **One role builds every agent tier.** The role `hermes_tier` is instantiated once per tier from `tiers.<name>` in
    `bin/hermes/pins.json` (account, proxy port, toolsets, sizes, ports). A new tier is data plus a persona, not a copy of a role. Account,
    proxy, nftables table, managed directory, state volume and Desktop port are all derived from the tier name, so no two tiers can
    share one. The sandbox pieces (subordinate ids, container storage, image, cgroup delegation) apply only to a tier with
    `sandbox: true`.
18. **The personal assistant is its own tier.** It combines three things no other agent may hold together: the owner's personal data
    (Google Calendar, Todoist), untrusted input (web search) and write capability. It therefore has its own Linux account, state
    volume, policy and proxy (tier 2). Its hands are vendor-hosted remote MCP servers over OAuth 2.1 (Todoist, Google Calendar), so
    no local code or credential-handling is carried. Least privilege: its terminal and file tools run only in the rootless container, never on the host (the host account also holds its
    Claude login and process environment, and Hermes denies reading only its own stores, so a host file tool could be told
    to read and leak them), `trust: untrusted` on every
    server, so each write asks the owner and a cron run is read-only. Google's Calendar server needs the owner's own OAuth client
    (it refuses dynamic registration); its id and secret live in the tier's `.env`, never in the policy. Publish that OAuth app
    "In production": in "Testing" Google expires refresh tokens after seven days.
19. **The administration account has its own egress proxy, and untrusted reading is delegated.** The egress hold of decision 8
    covered the gateway account (uid 1001), but the admin agent acts through the SSH backend as `hermesadmin` (uid 1002), which
    had no hold, so the agent could read the open web from the account that has root. `hermesadmin` now goes out only through a
    local proxy with an exact-host allowlist (`admin.egress` in `bin/hermes/pins.json`; sshd sets the proxy variables for that
    account, nftables drops the rest). Because that account has root, the hold is friction and an audit trail, not a boundary;
    the control that matters is that untrusted content is read by the worker tier (`hermes-ask-worker`, prompt on stdin, answer
    fenced as untrusted), which holds no credential. Adding a host to the list is a pull request.
20. **The tier gateways stay user units; account isolation comes from the kernel, not from systemd sandboxing.** A tier runs as an
    unprivileged account, and for such an account `ProtectSystem`, `ProtectKernel*` and `PrivateDevices` add nothing the file
    permissions do not already give. What would add something (seccomp, `NoNewPrivileges`, mount namespaces) cannot be had in a
    user unit next to rootless Podman: in a user manager those options run the service in a user namespace, where root-owned files
    appear as `nobody` (it broke the SSH terminal of the admin backend) and the setuid `newuidmap` stops working. Moving the tiers
    to system units would need cgroupfs delegation for Podman and a second set of units for the same Hermes-written gateway, for
    a gain that does not justify it. A measured audit from inside a tier found the real exposures instead: another account's
    command lines were readable through `/proc`, and files written by the admin session were world-readable in `/tmp`. Both are
    closed (`hidepid=2`, `UMASK 027`, a three-day `/tmp` cleaner) and covered by tests.
