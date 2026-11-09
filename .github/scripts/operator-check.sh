#!/usr/bin/env bash
# Apply the operator role on a CI runner and prove the root access of the admin bot with a real sudo: the service user
# becomes root without a password, sudo logs its commands as text and records no I/O, and the switch takes root away and
# gives it back. Runs as root. Nothing here touches the Hermes host.
set -euo pipefail

REPO_DIR="$PWD"
WORK=$(mktemp -d)
fail() { echo "FAIL: $*" >&2; exit 1; }

# What the service_user and access roles leave on the host before this role runs.
id hermes >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/hermes --shell /usr/sbin/nologin hermes
install -d -m 0700 -o root -g root /var/log/sudo-io
printf '[hermes]\nlocalhost ansible_connection=local\n' >"$WORK/inventory.ini"

play() { (cd "$REPO_DIR/infra/ansible" && ansible-playbook -i "$WORK/inventory.ini" site.yml --tags operator "$@"); }
as_hermes() { sudo -u hermes -H env -i HOME=/home/hermes PATH=/usr/local/bin:/usr/bin:/bin "$@"; }

play --check --diff >"$WORK/check.log" 2>&1 || { cat "$WORK/check.log"; fail "the plan failed"; }
echo "ok: plan (--check --diff) passes"
play >"$WORK/apply.log" 2>&1 || { cat "$WORK/apply.log"; fail "the apply failed"; }
play >"$WORK/again.log" 2>&1 || { cat "$WORK/again.log"; fail "the second apply failed"; }
grep -q 'changed=0' "$WORK/again.log" || { cat "$WORK/again.log"; fail "the second apply changed something"; }
echo "ok: apply, then apply again with changed=0"

[ "$(stat -c '%a' /etc/sudoers.d/92-hermes-operator)" = 440 ] || fail "sudoers mode"
visudo -cf /etc/sudoers.d/92-hermes-operator >/dev/null || fail "visudo rejects the sudoers file"
[ "$(as_hermes sudo -n id -u)" = 0 ] || fail "the service user cannot become root"
echo "ok: the service user becomes root without a password"
grep -q 'USER=root' /var/log/sudo-hermesops.log || fail "sudo wrote no line to the text log"
[ -z "$(find /var/log/sudo-io -path '*hermes*' -type f 2>/dev/null)" ] || fail "sudo recorded the input or output of the bot account"
echo "ok: sudo logs the commands as text and does not record input and output"

STATUS=$(/usr/local/sbin/hermes-admin-access status)
grep -qx 'admin access: on' <<<"$STATUS" || fail "status should say on (got: $STATUS)"
/usr/local/sbin/hermes-admin-access off >/dev/null
if as_hermes sudo -n true 2>/dev/null; then fail "the account still has root after off"; fi
echo "ok: off takes root away"
play >"$WORK/off.log" 2>&1 || { cat "$WORK/off.log"; fail "apply while closed failed"; }
if as_hermes sudo -n true 2>/dev/null; then fail "an apply gave root back after it was taken away by hand"; fi
echo "ok: an apply leaves root closed when it was closed by hand"
/usr/local/sbin/hermes-admin-access on >/dev/null
[ "$(as_hermes sudo -n id -u)" = 0 ] || fail "on did not give root back"
play >"$WORK/final.log" 2>&1 || { cat "$WORK/final.log"; fail "final apply failed"; }
grep -q 'changed=0' "$WORK/final.log" || { cat "$WORK/final.log"; fail "final apply changed something"; }
echo "ok: on gives root back, and the next apply has nothing to change"
