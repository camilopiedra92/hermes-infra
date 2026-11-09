#!/usr/bin/env bash
# Install Hermes with the same Ansible role the host uses, then verify what relies on.
# Runs on a CI runner with root. Nothing here touches the Hermes host.
#
# The nftables part of the install window is proved against the real kernel by the `egress` job.
# Here the window is a stand-in that only answers `status` and `close`, so the install tasks run as they
# do on the host: with the window open the first time, and with no window at all the second time.
set -euo pipefail

REPO_DIR="$PWD"
PINS="${PINS:-bin/hermes/pins.json}"
pin() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval("d"+sys.argv[2]))' "$PINS" "$1"; }

COMMIT=$(pin '["commit"]')
CODE_DIR=$(pin '["install"]["code_dir"]')
CODE_PARENT=$(pin '["install"]["code_parent"]')
HERMES_HOME_DIR=$(pin '["install"]["hermes_home"]')
REPORT="${REPORT:-$PWD/hermes-install-report.json}"
LOGDIR="$(dirname "$REPORT")/hermes-install-logs"
WORK=$(mktemp -d)
WINDOW_STATE=/run/hermes-window-state

# The service user cannot read the runner's working directory, and the runner cannot read the
# service user's home. Work from / and copy the logs out, whatever the outcome.
cd /
ELAPSED=0
HEAD_SHA=unknown
size() { du -sb "$1" 2>/dev/null | cut -f1 || echo 0; }
finish() {
  mkdir -p "$LOGDIR"
  cp -r "$HERMES_HOME_DIR/logs/." "$LOGDIR/" 2>/dev/null || true
  chmod -R a+rX "$LOGDIR" 2>/dev/null || true
  python3 - "$REPORT" "$HEAD_SHA" "$ELAPSED" "$(size "$CODE_DIR")" "$(size "$HERMES_HOME_DIR")" \
    "$(size "$HERMES_HOME_DIR/tools")" "$(size "$HERMES_HOME_DIR/installs")" \
    "$(size /home/hermes/.npm)" "$(size /home/hermes/.local)" "$(size /home/hermes/.cache)" \
    "$(find "$HERMES_HOME_DIR" 2>/dev/null | wc -l)" "$(find "$CODE_DIR" 2>/dev/null | wc -l)" <<'PY' || true
import json, sys
a = sys.argv
report = {
    "commit": a[2],
    "install_seconds": int(a[3]),
    "bytes": {"code_dir": int(a[4] or 0), "hermes_home": int(a[5] or 0), "tools": int(a[6] or 0),
              "installs": int(a[7] or 0), "npm_cache": int(a[8] or 0), "local": int(a[9] or 0),
              "cache": int(a[10] or 0)},
    "inodes": {"hermes_home": int(a[11]), "code_dir": int(a[12])},
}
json.dump(report, open(a[1], "w"), indent=2)
print(json.dumps(report, indent=2))
PY
}
trap finish EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# The service user starts from a clean environment, as under systemd.
as_hermes() {
  sudo -u hermes -H env -i HOME=/home/hermes USER=hermes LOGNAME=hermes LANG=C.UTF-8 \
    PATH="/home/hermes/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    HERMES_HOME="$HERMES_HOME_DIR" "$@"
}
HERMES_BIN="/home/hermes/.local/bin/hermes"
run_hermes() { as_hermes "$HERMES_BIN" "$@"; }

printf '[hermes]\nlocalhost ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n' > "$WORK/inventory.ini"
play() { (cd "$REPO_DIR/infra/ansible" && ansible-playbook -i "$WORK/inventory.ini" site.yml "$@"); }

# The runner image makes /opt world-writable (777). The host's /opt is root's, 0755, and an install that only
# works when /opt is writable fails there. 2026-11-08 it did, on the host, and CI had hidden it.
chmod 0755 /opt
echo "::group::The service user, with its home and its state directory"
id hermes >/dev/null 2>&1 || useradd --create-home --shell /usr/sbin/nologin hermes
install -d -o hermes -g hermes -m 0700 "$HERMES_HOME_DIR"
echo "::endgroup::"

echo "::group::A stand-in for the install window (the kernel part is the egress job)"
cat > /usr/local/sbin/hermes-install-window <<'STUB'
#!/bin/sh
case "$1" in
  status) cat /run/hermes-window-state ;;
  close) echo closed > /run/hermes-window-state ;;
esac
STUB
chmod 0750 /usr/local/sbin/hermes-install-window
echo open > "$WINDOW_STATE"
echo "::endgroup::"

# The policy the service user must not be able to change is applied first, as on the host, where lazy
# installs are already off when the Telegram library is installed.
echo "::group::Apply the managed scope, then install"
play --tags managed -e hermes_gateway_telegram_allowed_users=123456789
# The allowlist is kept when the variable is not given, and an apply with no allowlist at all is refused. A run of
# `--tags gateway` removed it from the host on 2026-11-08 because the role carries that tag.
play --tags managed >/dev/null
grep -qx 'TELEGRAM_ALLOWED_USERS=123456789' /etc/hermes/.env || fail "an apply without the variable removed the allowed Telegram user"
cp /etc/hermes/.env "$WORK/env.keep"
rm -f /etc/hermes/.env
if play --tags managed >"$WORK/no-allowlist.log" 2>&1; then fail "the managed environment was written with no allowed Telegram user"; fi
[ ! -e /etc/hermes/.env ] || fail "a managed environment exists after a refused apply"
install -m 0644 -o root -g root "$WORK/env.keep" /etc/hermes/.env
START=$(date +%s)
play --tags install
ELAPSED=$(( $(date +%s) - START ))
[ "$(cat "$WINDOW_STATE")" = closed ] || fail "the install tasks left the window open"
HEAD_SHA=$(git --git-dir="$CODE_DIR/.git" -c safe.directory='*' rev-parse HEAD)
[ "$HEAD_SHA" = "$COMMIT" ] || fail "HEAD is $HEAD_SHA, the pin is $COMMIT"
echo "::endgroup::"

echo "::group::A second run needs no window and changes nothing"
play --tags install | tee "$WORK/second.log"
grep -E "ok=[0-9]+ +changed=0 +unreachable=0 +failed=0" "$WORK/second.log" || fail "the second install run changed something"
echo "::endgroup::"

echo "::group::The code is root-owned and the service user can only read it"
[ "$(stat -c %U "$CODE_DIR")" = root ] || fail "the code directory is not owned by root"
[ "$(stat -c %U "$CODE_PARENT")" = root ] || fail "the parent of the code directory is not owned by root"
find "$CODE_DIR" -name install-stamp.json -exec ls -l {} +
if as_hermes sh -c "touch '$CODE_DIR/.write-test'" 2>/dev/null; then fail "the service user can write under the code directory"; fi
touch "$WORK/marker"; sleep 1
echo "::endgroup::"

echo "::group::hermes --version and pm doctor on the read-only code"
run_hermes --version
run_hermes pm doctor || fail "pm doctor fails on the root-owned tree"
echo "::endgroup::"

echo "::group::The service user cannot change what is pinned"
for change in "security.allow_lazy_installs true" "telemetry.shared_metrics.enabled true" "web.keyless_fallback true"; do
  # shellcheck disable=SC2086
  if OUT=$(run_hermes config set $change 2>&1); then
    echo "$OUT"; fail "the service user changed a pinned key: $change"
  fi
  printf '%s\n' "$OUT" | grep -qi "managed by your administrator" || { echo "$OUT"; fail "no 'managed' refusal for: $change"; }
  echo "refused: $change"
done
echo "::endgroup::"

echo "::group::What Hermes reports"
DOCTOR=$(run_hermes doctor 2>&1) || echo "hermes doctor exited $? (recorded, not a pin check)"
printf '%s\n' "$DOCTOR"
printf '%s\n' "$DOCTOR" | grep -q "/etc/hermes" || fail "hermes doctor does not report the managed directory"
if printf '%s\n' "$DOCTOR" | grep -q "python-telegram-bot (optional, not installed)"; then
  fail "python-telegram-bot is not installed and lazy installs are off, so Telegram could not start"
fi
echo "::endgroup::"

echo "::group::The model path: the pinned CLI and plugin, installed by the role"
CLI_VERSION=$(pin '["model"]["cli"]["version"]')
CLAUDE_BIN="$(pin '["model"]["cli"]["root"]')/$CLI_VERSION/package/claude"
PLUGIN_DIR="$HERMES_HOME_DIR/plugins/$(pin '["model"]["plugin"]["install_name"]')"
PROVIDER=$(pin '["model"]["provider"]')
echo open > "$WINDOW_STATE"
play --tags model | tee "$WORK/model.log" || {
  echo "== what Hermes put in the plugins directory"
  find "$HERMES_HOME_DIR/plugins" -maxdepth 2 2>/dev/null | head -40
  (cd "$PLUGIN_DIR" 2>/dev/null && find . -type f -not -path '*/__pycache__/*' -printf '%P\0' | LC_ALL=C sort -z | xargs -0 sha256sum | head -120) || true
  fail "the model tasks failed"
}
[ "$(cat "$WINDOW_STATE")" = closed ] || fail "the model tasks left the window open"
[ "$(stat -c %U "$CLAUDE_BIN")" = root ] || fail "the Claude Code binary is not owned by root"
if as_hermes sh -c "touch '$(dirname "$CLAUDE_BIN")/.write-test'" 2>/dev/null; then fail "the service user can write next to the CLI"; fi
CLAUDE_OUT=$(as_hermes "$CLAUDE_BIN" --version)
echo "claude --version: $CLAUDE_OUT"
printf '%s\n' "$CLAUDE_OUT" | grep -q "$CLI_VERSION" || fail "the CLI does not report the pinned version $CLI_VERSION"
echo "plugins directory:"; find "$HERMES_HOME_DIR/plugins" -maxdepth 2 | sort | head -20
[ -d "$PLUGIN_DIR" ] || fail "the plugin is not at $PLUGIN_DIR"
PLUGINS=$(run_hermes plugins list --plain --no-bundled 2>&1) || true
printf '%s\n' "$PLUGINS"
printf '%s\n' "$PLUGINS" | grep -qi "claude-subscription-directsdk" || fail "hermes plugins list does not show the plugin"
HERMES_PYTHON=$(run_hermes --print-runtime-command --module evals | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')
echo "== the effective policy"
[ "$(run_hermes config get model.provider)" = "$PROVIDER" ] || fail "the effective model.provider is not the subscription plugin"
# What Hermes resolves from the merged configuration: the default model, its effort and its context. The model is policy and
# cannot be changed by the service user; the effort is a preference and is only checked for its default.
RESOLVED=$(as_hermes "$HERMES_PYTHON" -I -c "import os, sys, logging
os.environ.pop('PYTHONPATH', None)
sys.path.insert(0, '$CODE_DIR')
sys._hermes_pin_default_home = True
import hermes_bootstrap
logging.disable(logging.CRITICAL)
from hermes_cli.config import load_config
from hermes_constants import resolve_reasoning_config
from agent.model_metadata import get_model_context_length
cfg = load_config()
model = cfg['model']['default']
print(model, resolve_reasoning_config(cfg)['effort'], get_model_context_length(model, provider=cfg['model']['provider']))")
echo "resolved (model, effort, context): $RESOLVED"
[ "$RESOLVED" = "$(pin '["model"]["default_model"]') $(pin '["model"]["reasoning_effort"]') 1000000" ] || fail "the resolved default model, effort or context is not the one the owner chose"
for change in "model.provider openrouter" "model.default claude-opus-5-5" "auth.adopt_external_logins true" "updates.check true" "plugins.auto_apply true" \
  "terminal.backend local" "terminal.ssh_user root" "terminal.ssh_key /tmp/other" "approvals.mode off" "approvals.timeout 99999"; do
  # shellcheck disable=SC2086
  if OUT=$(run_hermes config set $change 2>&1); then echo "$OUT"; fail "the service user changed a pinned key: $change"; fi
  printf '%s\n' "$OUT" | grep -qi "managed by your administrator" || { echo "$OUT"; fail "no 'managed' refusal for: $change"; }
  echo "refused: $change"
done
echo "== a second run needs no window and changes nothing"
play --tags model | tee "$WORK/model2.log"
grep -E "ok=[0-9]+ +changed=0 +unreachable=0 +failed=0" "$WORK/model2.log" || fail "the second model run changed something"
echo "::endgroup::"

echo "::group::The plugin's offline evals, on the Claude Code binary and the plugin files that ship"
# A new Claude Code release can change the wire shape the plugin relies on. The plugin's evals run the real binary against a
# loopback peer, with no credentials and no inference. Its own CI pins an older release and bumps it to qualify a new one.
# This runs them on the exact binary the role deployed and the exact plugin files it verified, so a pin moves only if they pass.
for eval in evals/directsdk_admission.py evals/directsdk_cache_wire.py; do
  echo "== $eval"
  as_hermes "$HERMES_PYTHON" -I -c "import os, sys, runpy
os.environ.pop('PYTHONPATH', None)
sys.path.insert(0, '$CODE_DIR')
sys.path.insert(0, '$PLUGIN_DIR')
sys._hermes_pin_default_home = True
import hermes_bootstrap
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name='__main__')" "$PLUGIN_DIR/$eval" "$CLAUDE_BIN" || fail "$eval failed on Claude Code $CLI_VERSION"
done
echo "::endgroup::"

echo "::group::The briefing the bot reads at the start of every conversation"
# Hermes loads AGENTS.md from the gateway's working directory, which is its home, after an injection scan. Ask the real Hermes,
# with the function the gateway uses, and require that the file is loaded and not blocked.
play --tags briefing >/dev/null
[ "$(stat -c %U:%a "$HERMES_HOME_DIR/AGENTS.md")" = root:644 ] || fail "the briefing is not root-owned and mode 0644"
BRIEFED=$(as_hermes "$HERMES_PYTHON" -I -c "import os, sys, logging
os.environ.pop('PYTHONPATH', None)
sys.path.insert(0, '$CODE_DIR')
sys._hermes_pin_default_home = True
import hermes_bootstrap
logging.disable(logging.CRITICAL)
from agent.prompt_builder import build_context_files_prompt
out = build_context_files_prompt(cwd='$HERMES_HOME_DIR', skip_soul=True, context_length=1000000)
print('blocked' if 'BLOCKED' in out else 'loaded', 'Briefing for the Hermes bot' in out, len(out))")
echo "context from the gateway's working directory (state, has the briefing, characters): $BRIEFED"
case "$BRIEFED" in "loaded True "*) ;; *) fail "Hermes does not load the briefing as the context file";; esac
echo "::endgroup::"

echo "::group::Where the rest of the service user's home is"
# The runner image seeds new homes from /etc/skel with .rustup, .dotnet, .cargo and .nvm. They are not
# Hermes. What Hermes leaves outside HERMES_HOME is what is measured in the report.
{ du -sb /home/hermes/.[!.]* /home/hermes/* 2>/dev/null || true; } | sort -rn | sed -n '1,12p' || true
echo "::endgroup::"

echo "::group::Nothing was written under the code directory"
WRITES=$(find "$CODE_DIR" -newer "$WORK/marker" 2>/dev/null | head -20)
[ -z "$WRITES" ] || { echo "$WRITES"; fail "Hermes wrote under the read-only code directory"; }
echo "::endgroup::"
