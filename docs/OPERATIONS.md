# Operations

Everything here has been run on the host. Commands assume the repository at `~/repos/hermes-infra` and the Ansible
environment of the admin account (`~/venv/ansible`, built with `uv` from `.github/requirements-ci.txt`).

## Access

- **Normal:** the owner talks to the admin bot on Telegram. The bot administers the host as `hermesadmin` over SSH on
  `127.0.0.1` (sudo, audited as text in `/var/log/sudo-hermesops.log`; Hermes keeps every tool call in its session store).
- **Operator session:** Tailscale SSH to `hermesops` from a device on the tailnet.
- **Break-glass:** the Hetzner web console, and the Hetzner API token held by the admin bot. The server has delete and
  rebuild protection; lifting it is a deliberate owner action.
- **Close the bot's door:** `sudo hermes-admin-channel off` (from an operator session or the console) moves its key aside and
  ends its sessions. `on` restores it.

## Changing the host

```sh
cd infra/ansible
~/venv/ansible/bin/ansible-playbook -i inventory/local.yml site.yml --tags <role> --check --diff < /dev/null   # read it
~/venv/ansible/bin/ansible-playbook -i inventory/local.yml site.yml --tags <role> < /dev/null                    # apply
~/venv/ansible/bin/ansible-playbook -i inventory/local.yml site.yml --tags <role> --check < /dev/null           # changed=0
```

Rules: pull request first; `< /dev/null` is required; prefer narrow tags (`--tags gateway` runs the whole role); a change
that can cut access (sshd, nftables, sudoers, Tailscale) arms an `at` rollback first and disarms it after a successful test.
A play never starts or restarts the admin gateway; the terminal tool blocks that from inside the gateway on purpose.
Restart it from an operator session: `systemctl --user -M hermes@ restart hermes-gateway`.

Roles: `access`, `tailscale_node`, `nftables`, `auditd`, `hardening`, `service_user`, `bot_admin`, `hermes_gateway`
(admin bot), `hermes_worker` (tier 1), `backup`, `health`, `capped_volume` (shared).

## Updating

- **OS:** unattended security upgrades run daily. Reboots happen only in the window, Sunday 05:00-07:00 America/Bogota
  (`hermes-reboot-window.timer`, only when `/run/reboot-required` exists). Check `/var/lib/hermes-health/status.json` first.
- **Hermes, plugin, CLI, model:** a pin moves only through a pull request that edits `bin/hermes/pins.json`. Read the
  release notes at the new tag, then `sudo hermes-install-window open 20` (a bounded egress window), apply
  `--tags install` for the admin and `--tags worker` for the worker, and check the bots answer. `hermes update` is never
  scheduled and `updates.check` stays off.
- **Rollback:** revert the pin commit and apply again. Configuration rolls back by reverting the commit; state by restoring a
  backup.

## Backup and restore

Daily 02:00 America/Bogota, `hermes-backup.timer`: restic to the R2 bucket `hermes-state-backups` (free tier), encrypted
client-side. Contents: memory, skills, cron, sessions, scripts, hooks, config of both bots, and their SQLite databases taken
through the SQLite backup API. Never included: bot tokens, the Claude logins, `auth.json`, caches and tools.
Retention 14 daily, 8 weekly, 6 monthly. The repository password is in `/etc/hermes-backup/restic.pass` and in the owner's
password manager; without it a backup cannot be opened.

```sh
sudo systemctl start hermes-backup.service                 # now
sudo cat /var/lib/hermes-backup/status.json                # last result
sudo bash -c 'set -a; . /etc/hermes-backup/restic.env; set +a; restic snapshots'
# restore drill (monthly): restore to a scratch directory, never over live state
sudo bash -c 'set -a; . /etc/hermes-backup/restic.env; set +a; restic restore latest --target /var/tmp/restore'
```

Check every `*.db` under the restored tree with `PRAGMA integrity_check`, then delete the scratch directory. A real
restore stops the affected gateway, restores into its state directory, fixes ownership, starts it, and the owner logs in to
Claude again (logins are single-use and never backed up).

## Monitoring

`hermes-health.timer` (every 5 minutes) writes `/var/lib/hermes-health/status.json`. The Hermes cron job `host-health`
(no-agent mode) sends a Telegram message only when the set of problems changes, and a daily reminder while one lasts.
It checks services, both gateways (active and enabled), failed units, backup age and size, disk, memory, pending upgrades.

## Credentials

| Credential | Where | Rotation |
| --- | --- | --- |
| Telegram bot tokens | `.env` of each bot; copies in `~/.config/hermes-creds` | BotFather `/revoke`, write the new token, restart the gateway |
| Claude logins | `/home/hermes/.claude`, `/home/hermesworker/.claude` | `claude auth login` as that user (owner approves in the browser) |
| Hetzner API token | `~/.config/hermes-creds/hcloud_token` | console, Security, API tokens |
| Tailscale OAuth client | `~/.config/hermes-creds/tailscale.env` | admin console, OAuth clients; use only `acl` and `devices` scopes |
| Cloudflare tokens | `~/.config/hermes-creds/cloudflare.env`, `r2-backup.env` | dashboard, API tokens; the backup token is scoped to one bucket |
| GitHub token | `~/.git-credentials` | settings, personal access tokens, fine-grained |
| restic password | `/etc/hermes-backup/restic.pass` | not rotated in place; a new repository is created if it leaks |

Secrets are never in git, never printed, and files holding them are mode 0600.

## Incident response

1. **Isolate:** `sudo hermes-admin-channel off`; stop the worker gateway
   (`sudo -u hermesworker env XDG_RUNTIME_DIR=/run/user/1003 systemctl --user stop hermes-gateway`).
2. **Preserve:** copy the session stores and `/var/log` to a scratch directory before changing anything.
3. **Revoke:** rotate every credential in the table above that the compromised bot could reach.
4. **Restore:** from the last good backup, then reopen the channel.

## Hermes Desktop

The Desktop app attaches to `hermes-serve.service`, a user unit of the admin account that listens on `127.0.0.1:9119` only
(`--tags serve`). No port is opened on the tailnet. The path in is an SSH tunnel over Tailscale SSH, so the real
authentication is the owner's Tailscale identity; the dashboard token is the second factor.

```sh
ssh -N -L 9119:127.0.0.1:9119 hermesops@hermes          # keep it open
ssh hermesops@hermes sudo cat /etc/hermes-dashboard/session-token   # the token, once
```

In Desktop: Settings, Gateways, Add, Remote gateway, URL `http://127.0.0.1:9119`, authentication Session token. Rotate by
deleting `/etc/hermes-dashboard/session-token`, applying `--tags serve`, restarting `hermes-serve` and pasting the new one.

## Worker (tier 1)

- Images are loaded offline: `podman save` as the admin, `podman load` as the worker. The worker has no registry egress.
- Test containers with the worker's user manager, never plain `sudo -u`, and never with Hermes names or labels
  (`systemd-run --user --pipe --wait`).
- The worker's Claude login is interactive: run `claude auth login` with stdin from a FIFO, give the owner the URL, write the
  code he returns into the FIFO.
