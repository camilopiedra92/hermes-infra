# hermes-infra

Infrastructure as code for one dedicated [Hermes Agent](https://github.com/NousResearch/hermes-agent) host: the server, the
bots that run on it, and the practices that keep both safe, recoverable and cheap to run.

| Item | Value |
| --- | --- |
| Host | One Hetzner Cloud CPX21 (Ubuntu 24.04), protected against deletion and rebuild |
| Cost | The Claude subscription and the server. Free tiers only |
| Access | Tailscale only; no public inbound port |
| Admin bot (tier 0) | Hermes gateway on Telegram, owner-only, administers the host |
| Worker bots (tier 1) | Separate account, rootless Podman sandbox, no credentials, runs code and develops |
| Model | The owner's Claude subscription through the pinned `claude-subscription-directsdk` plugin |
| Recovery | Daily client-side encrypted restic backup to Cloudflare R2; monthly restore drill |
| Provisioning | Ansible, applied from the host itself after `--check --diff` |

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and threat model,
[docs/DECISIONS.md](docs/DECISIONS.md) for why, and [docs/OPERATIONS.md](docs/OPERATIONS.md) for how to run it.

```text
.
├── docs/            Architecture, decisions, operations
├── infra/ansible/   Host configuration (site.yml and roles)
├── bin/             Pins, host health, tailnet policy tool, tests and the merge gate
├── policy/          Tailscale ACL
└── .github/         CI (free Actions on this public repository)
```

## Quality gate

`python3 bin/verify.py` runs the unit tests under `bin/`, the pinned pre-commit hooks and checks that the tree is clean.
CI runs the same script. Setup:

```sh
uv tool install pre-commit==4.7.0
pre-commit install
python3 bin/verify.py
```

See [AGENTS.md](AGENTS.md) for the rules every contributor, human or agent, follows, and [SECURITY.md](SECURITY.md) to report a
problem.
