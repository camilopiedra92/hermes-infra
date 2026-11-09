# Architecture

One dedicated server runs the Hermes Agent. One owner. Everything is code in this repository, applied from `main`.

## Goals

1. The owner reaches the system through one channel (Telegram) and administers nothing by hand.
2. Total running cost is the Claude subscription plus the server. Free tiers only; no paid add-on is ever enabled.
3. A mistake or an injected instruction is contained by design, and every state is recoverable.
4. No fork, workaround or dead code is carried. Pinned upstream software only.

## Threat model

The assets are the owner's accounts (Hetzner, Cloudflare, Tailscale, GitHub, Claude) and the agent's memory.
The realistic attacks are:

- **Prompt injection** through content an agent reads (web pages, issues, files, dependencies).
- **Compromise of the owner's Telegram account**, the single authentication factor of the admin channel.
- **Supply chain**: a malicious package installed while a bot develops software.
- **Operator error** that cuts access (firewall, SSH, Tailscale).

Security is organised on one axis: **input trust times capability**. An agent that reads untrusted content never holds
the powerful credentials, and the agent that holds them never reads untrusted content.

## Trust tiers

| Tier | Who | Inputs | Capability |
| --- | --- | --- | --- |
| 0 | Admin agent (the Hermes gateway, owner-only Telegram) | owner messages, its own repository and the documented APIs of the providers it administers | root through audited sudo, cloud tokens, approvals manual |
| 1 | Worker agents (own account and Hermes instance) | web, public repos, any text | rootless container only; no host or cloud credential; scoped GitHub token for scratch repositories |
| 2 | Personal assistant (own account and Hermes instance) | web, calendar and task text | owner's Calendar and Todoist through remote MCP (OAuth); terminal and files only inside the rootless container; no host or cloud credential; every MCP write asks the owner |
| - | Break-glass | owner | Hetzner console, Tailscale from the owner's phone |

Worker output (pull requests, files) is untrusted data for tier 0. A worker never merges, never applies.

**What the admin agent may read.** Its hands are the account `hermesadmin`, which has root through sudo, so a network rule on
that account is friction and an audit trail, not a boundary. The account therefore reaches the internet only through its own
proxy, which names the hosts the administrator work needs (GitHub, the package and image registries, the Hetzner, Cloudflare
and Tailscale APIs, the Hermes docs), and everything else is dropped and counted. The rule that does the real work is a
process one: anything that is not on that list (a web page, an issue or pull request written by someone else, a file from an
unknown source) is read by the worker tier through `hermes-ask-worker`, and the answer comes back fenced as untrusted data.
The assistant tier is never used for this, because it holds personal data.

Tier 2 holds personal data and reads the web, which is the combination an injected instruction needs to do harm. Its
containment is capability plus the sandbox: terminal and file tools run only in the container (no network, no credential,
`/output` the only host path), no host code execution, MCP servers marked
`trust: untrusted` (every write needs the owner's approval; an unattended cron run cannot approve, so it can only read),
and a proxy that names only the hosts of its MCP servers and its search vendor.

## Host

- Hetzner CPX21, Ubuntu 24.04, delete and rebuild protection on. The cloud firewall has no inbound rule.
- Access: Tailscale only. OpenSSH key-only, no root login. The admin agent reaches `hermesadmin` over loopback SSH.
- The gateway runs as user `hermes` in a systemd user unit, enabled at boot, with a watchdog and memory limits.
- Policy that the service user cannot change lives in `/etc/hermes/config.yaml` (Hermes managed scope).
- Hardening follows CIS-style defaults for Ubuntu: kernel parameters, SSH limits, unattended security upgrades,
  reboots only in the maintenance window (Sunday 05:00-07:00 America/Bogota).
- Attack surface is removed, not masked: the stock cloud image's snapd, iSCSI, multipath, hypervisor agent, crash uploader and
  entropy fetch are purged, and the container auto-update timer is masked (images are pinned and loaded by the role).
- Root services (collector, backup, restore drill) share one systemd sandbox (no module, clock, reboot, device or namespace
  access). The admin backend runs without privilege escalation. The sandbox tiers cannot: rootless Podman needs the setuid
  `newuidmap`, and in a user manager every namespace or seccomp option implies `NoNewPrivileges`. For them the container
  and the unprivileged account are the boundary, and the gateway drop-in is shared by all tiers, so it stays additive.

## Sandbox (tier 1)

Rootless Podman with the stock `crun` runtime, the Hermes `docker` terminal backend, and these settings on every
container: network none or a proxied allowlist, read-only root filesystem, all capabilities dropped,
`no-new-privileges`, default seccomp profile, user namespace, pids/memory/cpu limits enforced by delegated cgroups.

Measured on this host: `memory.max`, `pids.max`, empty capability set, `NoNewPrivs=1`, seccomp active, a fork bomb
contained. No patched runtime is carried. gVisor would add syscall interposition against kernel exploits, and it
needs a private patch to run rootless; that cost is not justified for code written by the owner's own agents. It is
reconsidered when upstream supports a delegated cgroup subtree.

There is no KVM on this server, so microVMs are not an option.

## Model access for worker agents

Workers think with the owner's Claude subscription and act in a container, and the container never holds a credential.

- **Brain outside, hands inside.** The Hermes agent loop and the pinned Claude Code plugin run in the gateway of the worker
  profile, where the subscription login lives. Only tool calls (terminal, file edits, tests) run in the container.
  The login never enters the sandbox.
- **Claude Code inside the sandbox, when a task needs the CLI itself.** Use a long-lived headless token minted with
  `claude setup-token` (separate from the interactive login, no refresh-token race) and keep it out of the container:
  an egress credential-injection proxy (Hermes `egress/iron-proxy`) adds the header on the way out, so code in the container
  can use the model and cannot read or exfiltrate the secret.
- **One quota, many workers.** The subscription is a single shared cap. Each worker profile has its own turn and wall-clock
  budget, concurrency is limited, and a 429 pauses workers and notifies the owner. Extra usage stays off.

## Recoverability

- Configuration: this repository.
- State: restic to a Cloudflare R2 bucket (free tier), client-side encrypted, daily, 14 daily / 8 weekly / 6 monthly,
  database copies taken through the SQLite backup API, an automated monthly restore drill that the health collector watches. Secrets and the Claude login are never
  backed up; the Claude login is renewed by the owner.
- Server: protected against deletion; rebuilding is a deliberate owner action from the Hetzner console.

## Change flow

Pull request on a branch, CI (free Actions on a public repository), merge by the owner or by the admin agent after
green, then the admin agent runs `ansible-playbook --check --diff`, reads it, applies, and checks again for no change.
A change that can cut access arms a dead-man timer first. No CI job has a path to the host.

## Observability

systemd unit failures, backup status, disk, memory, pending updates and certificate-free health checks run from a
timer and report to Telegram. An external heartbeat (Healthchecks free tier) detects a dead host.
