#!/usr/bin/env python3
"""Gate: check mode must execute read-only probes and tolerate empty output.

The command module, under --check, returns skipped and stdout "". A later
when that sends that stdout through from_json fails the play before any
change. A registered command or shell result used in when or from_json has
to set check_mode: false and changed_when: false. stat, slurp and getent
probes that feed a later task do too.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ANSIBLE = ROOT / "infra" / "ansible"

TASK_KEYWORDS = {
    "always",
    "any_errors_fatal",
    "args",
    "become",
    "become_flags",
    "become_user",
    "block",
    "check_mode",
    "changed_when",
    "connection",
    "delay",
    "delegate_to",
    "diff",
    "environment",
    "failed_when",
    "ignore_errors",
    "ignore_unreachable",
    "listen",
    "loop",
    "loop_control",
    "module_defaults",
    "name",
    "no_log",
    "notify",
    "port",
    "register",
    "remote_user",
    "rescue",
    "retries",
    "run_once",
    "tags",
    "throttle",
    "until",
    "vars",
    "when",
    "with_dict",
    "with_fileglob",
    "with_items",
    "with_list",
}

# These modules read. A registered result is a probe even before a when exists.
ALWAYS_PROBES = {
    "ansible.builtin.getent",
    "ansible.builtin.slurp",
    "ansible.builtin.stat",
    "getent",
    "slurp",
    "stat",
}

# These skip their command in check mode and leave stdout empty.
COMMAND_PROBES = {
    "ansible.builtin.command",
    "ansible.builtin.raw",
    "ansible.builtin.script",
    "ansible.builtin.shell",
    "command",
    "raw",
    "script",
    "shell",
}

KEY_RE = re.compile(r"^  ([A-Za-z0-9_.]+):\s*(.*?)\s*$")


def task_blocks(text: str) -> list[str]:
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line.startswith("- ")]
    blocks = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        blocks.append("\n".join(lines[start:end]))
    return blocks


def task_keys(block: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in block.splitlines():
        match = KEY_RE.match(line)
        if match is None or match.group(1) in found:
            continue
        found[match.group(1)] = match.group(2)
    return found


def task_name(block: str, module: str) -> str:
    first = block.splitlines()[0] if block else ""
    match = re.match(r"^- name:\s*(.*?)\s*$", first)
    if match and match.group(1):
        return match.group(1).strip("'\"")
    return module or "unnamed task"


def module_of(keys: dict[str, str]) -> str:
    for key in keys:
        if key not in TASK_KEYWORDS:
            return key
    return ""


def is_false(value: str) -> bool:
    return value.strip("'\"") == "false"


def ansible_sources(root: Path = ANSIBLE) -> list[tuple[str, str]]:
    sources = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".yml", ".yaml", ".j2"}:
            sources.append((str(path.relative_to(ROOT)), path.read_text(encoding="utf-8")))
    return sources


def _uses_probe(block: str, name: str) -> bool:
    scrubbed = re.sub(rf"^  register:\s*{re.escape(name)}\s*$", "", block, flags=re.M)
    if re.search(rf"\b{re.escape(name)}\b", scrubbed) is None:
        return False
    if f"{name}.stdout" in scrubbed or f"{name}.stderr" in scrubbed or f"{name}.rc" in scrubbed:
        return True
    return "from_json" in scrubbed


def probe_problems(sources: list[tuple[str, str]]) -> list[str]:
    problems = []
    blocks = [(path, block) for path, text in sources for block in task_blocks(text)]
    templates = [text for path, text in sources if path.endswith(".j2")]
    for path, block in blocks:
        keys = task_keys(block)
        module = module_of(keys)
        name = task_name(block, module)
        registered = keys.get("register", "").strip("'\"")
        needs_flags = False
        if module in ALWAYS_PROBES and (module in {"getent", "ansible.builtin.getent"} or registered):
            needs_flags = True
        elif module in COMMAND_PROBES and registered:
            used = any(_uses_probe(other, registered) for _, other in blocks)
            used = used or any(re.search(rf"\b{re.escape(registered)}\b", text) for text in templates)
            needs_flags = used
        if not needs_flags:
            continue
        missing = []
        if not is_false(keys.get("check_mode", "")):
            missing.append("check_mode: false")
        if not is_false(keys.get("changed_when", "")):
            missing.append("changed_when: false")
        if missing:
            problems.append(f"{path}: {name} is a read-only probe missing {', '.join(missing)}")
    return problems


class CheckProbeTests(unittest.TestCase):
    def test_repository_probes_run_in_check_mode(self) -> None:
        problems = probe_problems(ansible_sources())
        self.assertEqual(problems, [])

    def test_command_stdout_used_in_when_requires_check_mode(self) -> None:
        bad = """
- name: Read Tailscale preferences
  ansible.builtin.command: tailscale debug prefs
  register: tailscale_node_prefs
  changed_when: false

- name: Apply settings
  ansible.builtin.command: tailscale set
  when: (tailscale_node_prefs.stdout | from_json).RunSSH != false
  changed_when: true
"""
        problems = probe_problems([("roles/tailscale_node/tasks/main.yml", bad)])
        self.assertEqual(len(problems), 1)
        self.assertIn("check_mode: false", problems[0])
        self.assertIn("Read Tailscale preferences", problems[0])

    def test_shell_and_stat_probes_are_covered(self) -> None:
        bad = """
- name: Read a file
  ansible.builtin.shell: cat /etc/hostname
  register: host_name
  check_mode: false

- name: Use the name
  ansible.builtin.debug:
    msg: "{{ host_name.stdout | from_json }}"

- name: Stat a path
  ansible.builtin.stat:
    path: /etc/hostname
  register: host_stat
"""
        problems = probe_problems([("roles/example/tasks/main.yml", bad)])
        self.assertEqual(len(problems), 2)
        self.assertTrue(any("changed_when: false" in problem and "Read a file" in problem for problem in problems))
        self.assertTrue(any("Stat a path" in problem for problem in problems))

    def test_command_that_is_not_a_probe_is_left_alone(self) -> None:
        text = """
- name: Format an image
  ansible.builtin.command: mkfs.ext4 /tmp/image
  changed_when: true
"""
        self.assertEqual(probe_problems([("roles/access/tasks/main.yml", text)]), [])

    def test_complete_probe_is_accepted(self) -> None:
        text = """
- name: Read Tailscale preferences
  ansible.builtin.command: tailscale debug prefs
  register: tailscale_node_prefs
  changed_when: false
  check_mode: false

- name: Apply settings
  ansible.builtin.command: tailscale set
  when: (tailscale_node_prefs.stdout | default('') | length) > 0
  changed_when: true
"""
        self.assertEqual(probe_problems([("roles/tailscale_node/tasks/main.yml", text)]), [])

    def test_roles_do_not_read_injected_facts(self) -> None:
        config = (ANSIBLE / "ansible.cfg").read_text(encoding="utf-8")
        self.assertIn("inject_facts_as_vars = False", config)
        injected = re.compile(
            r"(?<!facts\[')\b(?:getent_passwd|ansible_(?:distribution|os_family|hostname|fqdn|"
            r"architecture|pkg_mgr|memtotal_mb|kernel|python_version))\b"
        )
        offenders = []
        for path, text in ansible_sources():
            if path.endswith("ansible.cfg"):
                continue
            for number, raw in enumerate(text.splitlines(), start=1):
                if injected.search(raw):
                    offenders.append(f"{path}:{number}: {raw.strip()}")
        self.assertEqual(offenders, [])
        access = (ANSIBLE / "roles" / "access" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertIn("ansible_facts['getent_passwd']", access)

    def test_existing_sudo_image_must_match_before_mount(self) -> None:
        text = (ANSIBLE / "roles" / "access" / "tasks" / "image.yml").read_text(encoding="utf-8")
        blocks = task_blocks(text)
        names = [task_name(block, "") for block in blocks]
        refuse_size = names.index("Refuse a sudo I/O image that is not a regular file of the expected size")
        refuse_type = names.index("Require ext4 identification of the existing sudo I/O image")
        require = names.index("Require the expected sudo I/O volume before mounting")
        self.assertLess(refuse_size, refuse_type)
        self.assertLess(refuse_type, names.index("Format the sudo I/O image"))
        self.assertLess(names.index("Format the sudo I/O image"), require)
        joined = "\n".join(blocks[refuse_size:require + 1])
        self.assertIn("isreg", joined)
        self.assertIn("access_iolog_bytes", joined)
        self.assertIn("ext4", joined)
        extend = next(block for block in blocks if block.startswith("- name: Extend a newly created"))
        self.assertIn("access_iolog_image_created is changed", extend)
        self.assertNotIn("access_iolog_image_stat.stat.size", extend)
        main = (ANSIBLE / "roles" / "access" / "tasks" / "main.yml").read_text(encoding="utf-8")
        self.assertLess(main.index("import_tasks: image.yml"), main.index("Mount the sudo I/O filesystem"))


class CheckModePlayTests(unittest.TestCase):
    def setUp(self) -> None:
        playbook = shutil.which("ansible-playbook")
        if playbook is None:
            self.skipTest("ansible-playbook is not installed")
        self.playbook = playbook

    def check(self, script: str) -> subprocess.CompletedProcess[str]:
        work = Path(tempfile.mkdtemp(prefix="ansible-check-"))
        self.addCleanup(lambda: shutil.rmtree(work, ignore_errors=True))
        binary = work / "tailscale"
        binary.write_text(script, encoding="utf-8")
        binary.chmod(0o755)
        play = work / "play.yml"
        play.write_text(
            "- name: Check the tailscale role\n"
            "  hosts: local\n"
            "  gather_facts: false\n"
            "  roles:\n"
            "    - role: tailscale_node\n",
            encoding="utf-8",
        )
        inventory = work / "hosts"
        inventory.write_text(
            "local ansible_connection=local ansible_python_interpreter=/usr/bin/python3\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["PATH"] = f"{work}{os.pathsep}{env.get('PATH', '')}"
        env["ANSIBLE_CONFIG"] = str(ANSIBLE / "ansible.cfg")
        env["ANSIBLE_ROLES_PATH"] = str(ANSIBLE / "roles")
        return subprocess.run(
            [self.playbook, "-i", str(inventory), str(play), "--check", "--diff"],
            cwd=ANSIBLE,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_check_mode_reads_prefs_and_ignores_empty_output(self) -> None:
        matched = self.check(
            "#!/bin/sh\n"
            'printf "%s\\n" \'{"RunSSH": false, "Hostname": "hermes"}\'\n'
        )
        self.assertEqual(matched.returncode, 0, matched.stdout + matched.stderr)
        self.assertIn("Read Tailscale preferences", matched.stdout)
        self.assertNotIn("failed=1", matched.stdout)

        empty = self.check("#!/bin/sh\nexit 0\n")
        self.assertEqual(empty.returncode, 0, empty.stdout + empty.stderr)
        self.assertNotIn("JSONDecodeError", empty.stderr)
        self.assertNotIn("failed=1", empty.stdout)


if __name__ == "__main__":
    unittest.main()
