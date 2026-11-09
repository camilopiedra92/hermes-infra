#!/usr/bin/env bash
# Apply the bot_admin role on a CI runner and prove the channel of with a real sshd and a real sudo:
# the service user gets in over 127.0.0.1 with its own key and becomes root, nothing else gets in, and the
# switch closes and opens the channel. Runs as root. Nothing here touches the Hermes host.
set -euo pipefail

REPO_DIR="$PWD"
WORK=$(mktemp -d)
KEY=/home/hermes/.ssh/hermes-admin
fail() { echo "FAIL: $*" >&2; exit 1; }

# What the sandbox and access roles leave on the host before this role runs.
id hermes >/dev/null 2>&1 || useradd --system --create-home --home-dir /home/hermes --shell /usr/sbin/nologin hermes
install -d -m 0700 -o root -g root /var/log/sudo-io
ssh-keygen -A >/dev/null
systemctl start ssh
printf '[hermes]\nlocalhost ansible_connection=local\n' >"$WORK/inventory.ini"

play() { (cd "$REPO_DIR/infra/ansible" && ansible-playbook -i "$WORK/inventory.ini" site.yml --tags bot_admin "$@"); }
as_hermes() { sudo -u hermes -H env -i HOME=/home/hermes PATH=/usr/local/bin:/usr/bin:/bin "$@"; }
admin_ssh() { as_hermes ssh -o BatchMode=yes -o ConnectTimeout=10 hermes-admin "$@"; }

play --check --diff >"$WORK/check.log" 2>&1 || { cat "$WORK/check.log"; fail "the plan failed"; }
echo "ok: plan (--check --diff) passes"
play >"$WORK/apply.log" 2>&1 || { cat "$WORK/apply.log"; fail "the apply failed"; }
play >"$WORK/again.log" 2>&1 || { cat "$WORK/again.log"; fail "the second apply failed"; }
grep -q 'changed=0' "$WORK/again.log" || { cat "$WORK/again.log"; fail "the second apply changed something"; }
echo "ok: apply, then apply again with changed=0"

[ "$(id -u hermesadmin)" = 1002 ] || fail "hermesadmin is not uid 1002"
passwd -S hermesadmin | awk '{print $2}' | grep -qx L || fail "hermesadmin has a usable password"
KEY_STAT=$(stat -c '%a %U' "$KEY" 2>&1 || true)
[ "$KEY_STAT" = "600 hermes" ] || { ls -la /home/hermes/.ssh >&2 || true; fail "the private key is not 0600 hermes (got: $KEY_STAT)"; }
[ "$(stat -c '%a' /etc/sudoers.d/92-hermesadmin)" = 440 ] || fail "sudoers mode"
visudo -cf /etc/sudoers.d/92-hermesadmin >/dev/null || fail "visudo rejects the sudoers file of the account"
sshd -T | grep -q '^allowusers .*hermesadmin@127.0.0.1' || fail "sshd does not restrict the account"
echo "ok: account without password, key 0600 owned by the service user, sudoers valid, sshd restricted"

[ "$(admin_ssh id -un)" = hermesadmin ] || fail "the service user cannot log in as hermesadmin"
[ "$(admin_ssh sudo -n id -u)" = 0 ] || fail "hermesadmin cannot become root"
echo "ok: the service user logs in over 127.0.0.1 with its key (host key pinned) and becomes root"
grep -q 'USER=root' /var/log/sudo-hermesops.log || fail "sudo wrote no line to the text log"
[ -z "$(find /var/log/sudo-io -path '*hermesadmin*' -type f 2>/dev/null)" ] || fail "sudo recorded the input or output of the bot account"
echo "ok: sudo logs the commands of the bot account as text and does not record its input and output"

# The git credential helper answers for github.com from the delivered file, and for nothing else. The token here is a canary.
install -d -m 0700 -o hermesadmin -g hermesadmin /home/hermesadmin/.config/hermes
printf 'github_pat_ci_canary\n' >/home/hermesadmin/.config/hermes/github-token
chown hermesadmin:hermesadmin /home/hermesadmin/.config/hermes/github-token
chmod 0600 /home/hermesadmin/.config/hermes/github-token
as_admin() { sudo -u hermesadmin -H env -i HOME=/home/hermesadmin PATH=/usr/local/bin:/usr/bin:/bin GIT_TERMINAL_PROMPT=0 "$@"; }
GOT=$(printf 'protocol=https\nhost=github.com\n\n' | as_admin git credential fill)
grep -qx 'password=github_pat_ci_canary' <<<"$GOT" || fail "git does not get the delivered token for github.com"
if printf 'protocol=https\nhost=example.com\n\n' | as_admin git credential fill >/dev/null 2>&1; then
  fail "git got a credential for a host other than github.com"
fi
rm -f /home/hermesadmin/.config/hermes/github-token
echo "ok: git gets the delivered token for github.com and for no other host"

# The key works from 127.0.0.1 only.
OTHER=$(hostname -I | awk '{print $1}')
if as_hermes ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null "hermesadmin@$OTHER" true 2>/dev/null; then
  fail "the account logged in from a non-loopback address ($OTHER)"
fi
echo "ok: the account is refused from $OTHER"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/stranger"
if ssh -i "$WORK/stranger" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null hermesadmin@127.0.0.1 true 2>/dev/null; then
  fail "a key nobody authorized logged in"
fi
echo "ok: a stranger's key is refused"
if ssh -o BatchMode=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null hermesadmin@127.0.0.1 true 2>/dev/null; then
  fail "password login worked"
fi
echo "ok: no password login"

# The switch.
STATUS=$(/usr/local/sbin/hermes-admin-channel status)
grep -qx 'admin channel: on' <<<"$STATUS" || fail "status should say on (got: $STATUS)"
/usr/local/sbin/hermes-admin-channel off >/dev/null
if admin_ssh true 2>/dev/null; then fail "the channel is still open after off"; fi
echo "ok: off closes the channel"
play >"$WORK/off.log" 2>&1 || { cat "$WORK/off.log"; fail "apply while closed failed"; }
grep -q 'changed=0' "$WORK/off.log" || { cat "$WORK/off.log"; fail "apply while closed changed something"; }
if admin_ssh true 2>/dev/null; then fail "an apply re-opened a channel closed by hand"; fi
echo "ok: an apply leaves a channel closed by hand closed"
/usr/local/sbin/hermes-admin-channel on >/dev/null
[ "$(admin_ssh id -un)" = hermesadmin ] || fail "on did not re-open the channel"
play >"$WORK/final.log" 2>&1 || { cat "$WORK/final.log"; fail "final apply failed"; }
grep -q 'changed=0' "$WORK/final.log" || { cat "$WORK/final.log"; fail "final apply changed something"; }
echo "ok: on re-opens it, and the next apply has nothing to change"
