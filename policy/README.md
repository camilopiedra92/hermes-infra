# Tailnet policy

`tailscale-acl.hujson` is the tailnet policy for the Hermes host.
It is applied with `bin/tailnet-policy.py`, which calls the Tailscale API.
The admin-console paste is not the procedure.

The file's own `tests` block is checked locally and again by Tailscale.
`validate` and `apply` refuse a file whose tests do not pass. A file that
uses a policy feature this tool does not evaluate is refused too, rather
than applied on an incomplete reading. Tailscale's validate call is still
required: an empty response body is the pass.

## Credential

OAuth client `cto-box-policy`, owned by Camilo. It has every scope by his
explicit decision on 2026-11-07 (R22). The client id and secret are
`TAILSCALE_OAUTH_CLIENT_ID` and `TAILSCALE_OAUTH_CLIENT_SECRET` in the ops
box environment. They are not in git, not on the host, and this tool never
prints them or the access token. Rotation is 90 days, tracked outside the
repo.

## Commands

From a checkout on an operator machine, with those two variables set:

```bash
bin/tailnet-policy.py drift
bin/tailnet-policy.py diff
bin/tailnet-policy.py validate
bin/tailnet-policy.py apply
```

* `drift` exits 0 when the live HuJSON is byte-for-byte the repo file, and
  1 when it is not. It does not print the policy.
* `diff` prints a unified diff of live against the repo file.
* `validate` runs the file's tests, then `POST /api/v2/tailnet/-/acl/validate`.
  An empty result is success. This does not change the tailnet.
* `apply` does that validation first, then `GET`s the live policy and
  `POST`s the file with `If-Match` set to that ETag. It then reads the
  policy back and exits non-zero unless the bytes match the file. Do not
  run `apply` unattended.

`GET` and the readback use `Accept: application/hujson`, which is how the
11:00 apply compared bytes.

## Applied 2026-11-07 11:00 America/New_York

The operator applied `policy/tailscale-acl.hujson` as it was on `main`:
`POST /api/v2/tailnet/-/acl/validate` returned an empty body, then
`POST /api/v2/tailnet/-/acl` with `If-Match` on the previous ETag. The
readback was byte-identical. ETag
`5a426d83c20e4ef2add472f4621eccecc29d87de58ded03766d09b031e15f08a`.

The previous policy, a 2026-11-06 file that used `tag:hermes` and
`tag:provisioner`, was kept by the previous operator machine and is not in git. Restoring
it is `bin/tailnet-policy.py apply --file <that backup>` after its own tests
pass and the API validates it, with `If-Match` on whatever is live. It is
not a console paste. Break-glass remains the Hetzner console.

The comment at the top of the HuJSON file is part of the applied bytes.
Changing it is a policy change: `diff`, then `apply`. CI does not apply it.

## Tags

Done in the same change, host first, so the box was never tagged while the
host was still untagged. `POST /api/v2/device/{id}/tags`:

1. `hermes` -> `tag:hermes-prod`. SSH over the tailnet and `sudo -n true`
   succeeded.
2. `<retired-diagnosis-box>` -> `tag:hermes-ops`. The same two checks succeeded.

A later tag change uses that API in the same order. A node cannot be
untagged back to a user without a new login. Established sessions are not
cut by the tag change. The device ids are not in git.

## Tailscale SSH

: no CI identity reaches the host, so the policy has no CI tag.
Each grant is a person or an operator session to `tag:hermes-prod` on tcp/22
only. Tailscale SSH is the tailnet server once the role sets `RunSSH=true`.
The ssh rules, user `hermesops` only, are: the owner with `check` and
`checkPeriod` `12h`, then `tag:hermes-ops` with `accept`. `root`, `hermes`,
and `ubuntu` are denied. There is no recorder. `check` is not used
tag-to-tag. An `sshTests` entry names the action it expects: `accept` only
matches an `accept` rule and `check` only a `check` rule, as Tailscale
evaluates them. The owner's entry uses `check`. Applying this file is
`bin/tailnet-policy.py apply` from a machine that holds the OAuth client, or
pasting it into *Access controls*; never from CI. The `RunSSH` switch is
a separate step with its own rollback (`docs/runbooks/bootstrap-access.md`).

## Tag names

Tag names follow (`tag:hermes-prod`), not `tag:hermes`.
