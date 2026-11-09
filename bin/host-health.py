#!/usr/bin/env python3
"""Read-only health of the Hermes host, run from an operator machine on the tailnet.

One line per check. The process exits 0 when every line is ok, and 1 when
any line is red. It does not restart services or change files.

Remote checks run `ssh hermesops@hermes` (override the whole command with HERMES_SSH,
for example to add -F or a ProxyCommand). The tailnet
policy check is local (override the program with HERMES_TAILNET_POLICY).

  ok auditd active
  ok auditd rules 12
  ok sudo-io mount nosuid,nodev,noexec,loop
  ok sudo-io image 0600 root:root
  ok root filesystem free 65 GiB
  ok sudo-io filesystem free 381 MiB
  ok sudo-io pruner timer active
  ok tailnet policy
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERMES_PINS = json.loads((ROOT / "bin" / "hermes" / "pins.json").read_text(encoding="utf-8"))
NFT_PINS = HERMES_PINS["egress"]["nft"]
ROOT_FREE_MIN = 2 * 1024 * 1024 * 1024
IOLOG_FREE_MIN = 64 * 1024 * 1024
MOUNT_FLAGS = ("nosuid", "nodev", "noexec")

PLUGIN_DIR = f"{HERMES_PINS['install']['hermes_home']}/plugins/{HERMES_PINS['model']['plugin']['install_name']}"


def expected_filter_sha() -> str:
    """Hash of the allowed names the proxy must hold: one anchored expression per pinned host."""
    body = "".join(f"^{re.escape(host)}$\n" for host in HERMES_PINS["egress"]["domains"])
    return hashlib.sha256(body.encode()).hexdigest()


REMOTE = r"""
set +e
active=$(systemctl is-active auditd 2>/dev/null)
rules_rc=0
rules_text=$(auditctl -l 2>/dev/null) || rules_rc=$?
rules_b64=$(printf '%s' "$rules_text" | base64 -w 0)
options=$(findmnt -n -o OPTIONS /var/log/sudo-io 2>/dev/null)
source=$(findmnt -n -o SOURCE /var/log/sudo-io 2>/dev/null)
mode=$(stat -c %a /var/lib/hermes/sudo-io.img 2>/dev/null)
uid=$(stat -c %u /var/lib/hermes/sudo-io.img 2>/dev/null)
gid=$(stat -c %g /var/lib/hermes/sudo-io.img 2>/dev/null)
kind=$(stat -c %F /var/lib/hermes/sudo-io.img 2>/dev/null)
root_free=$(df -B1 --output=avail / 2>/dev/null | tail -n 1 | tr -d ' ')
iolog_free=$(df -B1 --output=avail /var/log/sudo-io 2>/dev/null | tail -n 1 | tr -d ' ')
pruner=$(systemctl is-active hermes-sudo-io-prune.timer 2>/dev/null)
proxy=$(systemctl is-active tinyproxy 2>/dev/null)
proxy_listen=$(ss -Htln 'sport = :@PROXY_PORT@' 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ',')
proxy_filter_sha=$(grep -v '^#' /etc/tinyproxy/hermes-allow.filter 2>/dev/null | grep -v '^$' | sha256sum | cut -d' ' -f1)
port_range=$(sysctl -n net.ipv4.ip_local_port_range 2>/dev/null | tr '\t' '-')
lo_foreign=$(ss -Htlnp 'src 127.0.0.1' 2>/dev/null | awk '{n=split($4,a,":"); p=a[n]+0; if (p>=@LO_LOW@ && p<=@LO_HIGH@ && $0 !~ /users:\(\("(hermes|python|claude)/) print $4}' | tr '\n' ',')
plugin_hash=$(/usr/local/share/hermes/plugin-manifest.sh @PLUGIN_DIR@ 2>/dev/null)
proxy_rule=$(nft list chain inet @NFT_TABLE@ output 2>/dev/null | grep 'tcp dport @PROXY_PORT@' | wc -l | tr -d ' ')
admin_uid=$(id -u @ADMIN_USER@ 2>/dev/null)
admin_sudoers=$(stat -c %a /etc/sudoers.d/92-hermesadmin 2>/dev/null)
admin_keys=$(grep '^from=' /home/@ADMIN_USER@/.ssh/authorized_keys 2>/dev/null | wc -l | tr -d ' ')
admin_off=$([ -e /var/lib/hermes/admin-authorized_keys.off ] && echo 1 || echo 0)
admin_sshd=$(sshd -T 2>/dev/null | grep '^allowusers .*@ADMIN_USER@@@ADMIN_HOST@' | wc -l | tr -d ' ')
printf 'auditd_active=%s\n' "$active"
printf 'auditd_rules_rc=%s\n' "$rules_rc"
printf 'auditd_rules_b64=%s\n' "$rules_b64"
printf 'mount_options=%s\n' "$options"
printf 'mount_source=%s\n' "$source"
printf 'image_mode=%s\n' "$mode"
printf 'image_uid=%s\n' "$uid"
printf 'image_gid=%s\n' "$gid"
printf 'image_kind=%s\n' "$kind"
printf 'free_root_bytes=%s\n' "$root_free"
printf 'free_iolog_bytes=%s\n' "$iolog_free"
printf 'pruner=%s\n' "$pruner"
printf 'proxy=%s\n' "$proxy"
printf 'proxy_listen=%s\n' "$proxy_listen"
printf 'proxy_filter_sha=%s\n' "$proxy_filter_sha"
printf 'proxy_rule=%s\n' "$proxy_rule"
printf 'port_range=%s\n' "$port_range"
printf 'lo_foreign=%s\n' "$lo_foreign"
printf 'plugin_hash=%s\n' "$plugin_hash"
printf 'admin_uid=%s\n' "$admin_uid"
printf 'admin_sudoers=%s\n' "$admin_sudoers"
printf 'admin_keys=%s\n' "$admin_keys"
printf 'admin_off=%s\n' "$admin_off"
printf 'admin_sshd=%s\n' "$admin_sshd"
""".replace("@PROXY_PORT@", str(NFT_PINS["proxy_port"])).replace("@LO_LOW@", NFT_PINS["loopback_ports"].split("-")[0]).replace("@LO_HIGH@", NFT_PINS["loopback_ports"].split("-")[1]).replace("@PLUGIN_DIR@", PLUGIN_DIR).replace("@NFT_TABLE@", NFT_PINS["table"]).replace("@ADMIN_USER@", HERMES_PINS["admin"]["user"]).replace("@ADMIN_HOST@", HERMES_PINS["admin"]["host"])


def line(ok: bool, text: str) -> str:
    return f"{'ok' if ok else 'red'} {text}"


def parse_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


def gibibytes(nbytes: int) -> str:
    return f"{nbytes / (1024 * 1024 * 1024):.0f} GiB"


def mebibytes(nbytes: int) -> str:
    return f"{nbytes / (1024 * 1024):.0f} MiB"


def _int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def count_audit_rules(text: str) -> int:
    count = 0
    for raw in text.splitlines():
        line_text = raw.strip()
        if not line_text or line_text.lower() == "no rules" or line_text.startswith("#"):
            continue
        if re.match(r"-[wWaA]\b", line_text):
            count += 1
    return count


def minimum_audit_rules() -> int:
    path = ROOT / "infra" / "ansible" / "roles" / "auditd" / "templates" / "50-hermes.rules.j2"
    skipping = False
    count = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line_text = raw.strip()
        if line_text.startswith("{% if"):
            skipping = True
            continue
        if line_text.startswith("{% endif"):
            skipping = False
            continue
        if skipping or not line_text or line_text.startswith("#") or line_text.startswith("{{"):
            continue
        if re.match(r"-[wWaA]\b", line_text):
            count += 1
    return count


def audit_lines(text: str, rc: int) -> list[str]:
    if rc != 0:
        return [line(False, "auditd rules probe failed")]
    count = count_audit_rules(text)
    minimum = minimum_audit_rules()
    if count >= minimum:
        return [line(True, f"auditd rules {count}")]
    return [line(False, f"auditd rules {count} need {minimum}")]


def decode_rules(fields: dict[str, str]) -> tuple[str, int | None]:
    rc = _int(fields.get("auditd_rules_rc", ""))
    encoded = fields.get("auditd_rules_b64", "")
    if not encoded:
        return "", rc
    try:
        text = base64.b64decode(encoded, validate=False).decode("utf-8", "replace")
    except (ValueError, binascii.Error):
        return "", None if rc is None else rc
    return text, rc


def remote_lines(fields: dict[str, str]) -> list[str]:
    lines: list[str] = []
    active = fields.get("auditd_active", "")
    lines.append(line(active == "active", f"auditd {active or 'unknown'}"))
    rules_text, rules_rc = decode_rules(fields)
    if rules_rc is None:
        lines.append(line(False, "auditd rules probe failed"))
    else:
        lines.extend(audit_lines(rules_text, rules_rc))
    options = {part.strip() for part in fields.get("mount_options", "").split(",") if part.strip()}
    source = fields.get("mount_source", "")
    mounted = set(MOUNT_FLAGS) <= options and ("loop" in options or source.startswith("/dev/loop"))
    if mounted:
        lines.append(line(True, "sudo-io mount nosuid,nodev,noexec,loop"))
    elif not options and not source:
        lines.append(line(False, "sudo-io mount missing"))
    else:
        lines.append(line(False, f"sudo-io mount {fields.get('mount_options') or source}"))
    mode = fields.get("image_mode", "")
    kind = fields.get("image_kind", "")
    image_ok = mode == "600" and fields.get("image_uid") == "0" and fields.get("image_gid") == "0" and kind == "regular file"
    if image_ok:
        lines.append(line(True, "sudo-io image 0600 root:root"))
    else:
        lines.append(
            line(False, f"sudo-io image mode={mode or '?'} uid={fields.get('image_uid') or '?'} gid={fields.get('image_gid') or '?'} {kind or 'unknown'}")
        )
    root_free = _int(fields.get("free_root_bytes", ""))
    if root_free is None:
        lines.append(line(False, "root filesystem free unknown"))
    else:
        lines.append(line(root_free >= ROOT_FREE_MIN, f"root filesystem free {gibibytes(root_free)}"))
    iolog_free = _int(fields.get("free_iolog_bytes", ""))
    if iolog_free is None:
        lines.append(line(False, "sudo-io filesystem free unknown"))
    else:
        lines.append(line(iolog_free >= IOLOG_FREE_MIN, f"sudo-io filesystem free {mebibytes(iolog_free)}"))
    pruner = fields.get("pruner", "")
    lines.append(line(pruner == "active", f"sudo-io pruner timer {pruner or 'unknown'}"))
    proxy = fields.get("proxy", "")
    lines.append(line(proxy == "active", f"egress proxy {proxy or 'unknown'}"))
    want = f"{NFT_PINS['proxy_address']}:{NFT_PINS['proxy_port']},"
    listen = fields.get("proxy_listen", "")
    lines.append(line(listen == want, f"egress proxy listens on {listen.rstrip(',') or 'nothing'}"))
    sha = fields.get("proxy_filter_sha", "")
    lines.append(line(sha == expected_filter_sha(), "egress allowlist matches the pins" if sha == expected_filter_sha() else "egress allowlist differs from the pins"))
    rule = _int(fields.get("proxy_rule", ""))
    lines.append(line(rule == 1, "egress rule for the proxy present" if rule == 1 else "egress rule for the proxy missing"))
    lines.append(
        line(
            fields.get("port_range", "") == NFT_PINS["loopback_ports"],
            f"loopback range for the service user matches the kernel's ({fields.get('port_range') or 'unknown'})",
        )
    )
    plugin = fields.get("plugin_hash", "")
    pinned = HERMES_PINS["model"]["plugin"]["manifest_sha256"]
    if not plugin:
        lines.append(line(False, "model plugin is not installed"))
    else:
        lines.append(line(plugin == pinned, "model plugin files match the pinned commit" if plugin == pinned else "model plugin files differ from the pinned commit"))
    foreign = fields.get("lo_foreign", "").strip(",")
    lines.append(line(not foreign, "no other listener in the loopback range" if not foreign else f"listener in the loopback range: {foreign}"))
    admin = HERMES_PINS["admin"]
    keys, off = _int(fields.get("admin_keys", "")) or 0, fields.get("admin_off", "") == "1"
    account_ok = _int(fields.get("admin_uid", "")) == admin["uid"] and fields.get("admin_sudoers", "") == "440"
    channel = "off (closed by hand)" if off and keys == 0 else "on" if keys == 1 and not off else "inconsistent"
    lines.append(line(account_ok and channel != "inconsistent", f"admin channel {channel}" if account_ok else "admin account or sudoers missing"))
    sshd_ok = _int(fields.get("admin_sshd", "")) == 1
    lines.append(line(sshd_ok, f"sshd allows {admin['user']} from {admin['host']} only" if sshd_ok else f"sshd does not restrict {admin['user']} to {admin['host']}"))
    return lines


def unreachable_lines() -> list[str]:
    return [
        line(False, "auditd host unreachable"),
        line(False, "auditd rules host unreachable"),
        line(False, "sudo-io mount host unreachable"),
        line(False, "sudo-io image host unreachable"),
        line(False, "root filesystem host unreachable"),
        line(False, "sudo-io filesystem host unreachable"),
        line(False, "sudo-io pruner timer host unreachable"),
        line(False, "egress proxy host unreachable"),
        line(False, "egress proxy listens host unreachable"),
        line(False, "egress allowlist host unreachable"),
        line(False, "egress rule host unreachable"),
        line(False, "loopback range host unreachable"),
        line(False, "loopback listeners host unreachable"),
        line(False, "model plugin host unreachable"),
        line(False, "admin channel host unreachable"),
        line(False, "admin sshd host unreachable"),
    ]


def ssh_argv() -> list[str]:
    return shlex.split(os.environ.get("HERMES_SSH", "ssh hermesops@hermes"))


def drift_bin() -> str:
    return os.environ.get("HERMES_TAILNET_POLICY", str(ROOT / "bin" / "tailnet-policy.py"))


def run_remote() -> subprocess.CompletedProcess[str]:
    command = "sudo -n sh -c " + shlex.quote(REMOTE)
    return subprocess.run(
        [*ssh_argv(), command],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )


def run_drift() -> subprocess.CompletedProcess[str]:
    program = drift_bin()
    argv = [program, "drift"] if not program.endswith(".py") else [sys.executable, program, "drift"]
    return subprocess.run(argv, text=True, capture_output=True, check=False, timeout=60)


def collect() -> list[str]:
    try:
        remote = run_remote()
    except (OSError, subprocess.TimeoutExpired):
        lines = unreachable_lines()
    else:
        if remote.returncode != 0:
            lines = unreachable_lines()
        else:
            lines = remote_lines(parse_fields(remote.stdout))
    try:
        drift = run_drift()
        lines.append(line(drift.returncode == 0, "tailnet policy" if drift.returncode == 0 else "tailnet policy drift"))
    except (OSError, subprocess.TimeoutExpired):
        lines.append(line(False, "tailnet policy drift"))
    return lines


def main() -> int:
    lines = collect()
    print("\n".join(lines))
    return 0 if all(item.startswith("ok ") for item in lines) else 1


if __name__ == "__main__":
    sys.exit(main())
