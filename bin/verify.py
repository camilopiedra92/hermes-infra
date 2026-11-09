#!/usr/bin/env python3
"""Repository quality gate. The single source of truth for "green".

Runs the unit tests under bin/test_*.py, then every pre-commit hook on all files
(gitleaks, yamllint, ansible-lint, shellcheck,
actionlint and the generic hooks). Fails if a test or hook fails, if a required
hook is missing from the config, or if a hook modified the tree.

A test that assigns ``REQUIRES_CONTAINER_RUNTIME = "docker"`` runs when that
binary is on ``PATH``. When it is not, the gate does not skip the test. It
reads GitHub Actions workflow runs and jobs for a successful ``verify`` job
on ``.github/workflows/ci.yml`` whose head commit tree equals ``HEAD^{tree}``.

Usage: python3 bin/verify.py
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REQUIRED_TOOLS = ("git", "pre-commit", "python3.14")

# Hooks that must stay configured. Removing one from .pre-commit-config.yaml fails the gate.
REQUIRED_HOOKS = (
    "gitleaks",
    "yamllint",
    "ansible-lint",
    "shellcheck",
    "actionlint",
)

# Actions evidence has to be this workflow. The Checks API is not used.
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
VERIFY_JOB_NAME = "verify"


def run(
    cmd: list[str],
    *,
    capture: bool = False,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=capture, check=False, env=env)


def fail(message: str) -> int:
    print(f"verify: FAIL: {message}", file=sys.stderr)
    return 1


class VerifyError(Exception):
    """The gate cannot accept this tree."""


@dataclass(frozen=True)
class CiEvidence:
    """A same-repo CI run whose verify job passed for one tree."""

    commit: str
    run_id: int


def container_runtime_marker(source: str) -> str | None:
    """Return the declared container runtime, if this module assigns one.

    Only a module-level ``REQUIRES_CONTAINER_RUNTIME = "name"`` counts.
    A docker-shaped file name is not a marker.
    """
    module = ast.parse(source)
    for node in module.body:
        targets: list[ast.expr]
        value: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue
        for target in targets:
            if not isinstance(target, ast.Name) or target.id != "REQUIRES_CONTAINER_RUNTIME":
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                return value.value.strip()
            raise VerifyError("REQUIRES_CONTAINER_RUNTIME must be a non-empty string")
    return None


def parse_github_slug(remote_url: str) -> tuple[str, str]:
    """Return ``owner, repo`` from an origin URL. Never echo the URL back."""
    text = remote_url.strip()
    if text.endswith(".git"):
        text = text[: -len(".git")]
    if "github.com/" in text:
        slug = text.split("github.com/", 1)[1]
    elif text.startswith("git@github.com:"):
        slug = text.split(":", 1)[1]
    else:
        raise VerifyError("origin is not a GitHub owner/repo remote")
    parts = [part for part in slug.strip("/").split("/") if part]
    if len(parts) != 2:
        raise VerifyError("origin is not a GitHub owner/repo remote")
    return parts[0], parts[1]


def github_token(env: dict[str, str] | None = None) -> str:
    values = env if env is not None else os.environ
    return values.get("GITHUB_TOKEN") or values.get("GH_TOKEN") or ""


def _next_link(headers: dict[str, str]) -> str | None:
    link = headers.get("Link") or headers.get("link") or ""
    for part in link.split(","):
        if 'rel="next"' not in part:
            continue
        return part.split(";", 1)[0].strip().strip("<>")
    return None


def github_get(url: str, token: str) -> tuple[int, object, dict[str, str]]:
    """GET a GitHub URL. The token is a header and is not put in an error."""
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hermes-infra-verify",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return response.status, payload, {key: value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        path = url.split("?", 1)[0].rsplit("github.com", 1)[-1]
        raise VerifyError(f"GitHub API HTTP {exc.code} for {path}") from None
    except urllib.error.URLError as exc:
        raise VerifyError(f"GitHub API request failed: {exc.reason}") from None


def _api_status(status: int, body: object, what: str, tree: str) -> dict:
    if status in {403, 404} or status != 200 or not isinstance(body, dict):
        raise VerifyError(f"GitHub API HTTP {status} {what} for tree {tree}")
    return body


def _workflow_runs(owner: str, repo: str, head_sha: str | None = None) -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs?per_page=100"
    if head_sha:
        return url + f"&head_sha={head_sha}"
    return url


def _verify_job_conclusion(jobs: list[object]) -> str | None:
    for job in jobs:
        if isinstance(job, dict) and job.get("name") == VERIFY_JOB_NAME:
            conclusion = job.get("conclusion")
            return str(conclusion) if conclusion is not None else None
    return None


def successful_verify_run(
    tree: str,
    owner: str,
    repo: str,
    token: str,
    get=github_get,
    *,
    head_sha: str | None = None,
    max_pages: int = 3,
) -> CiEvidence:
    """Return the CI run whose verify job passed for ``tree``.

    Evidence comes from the Actions API only: workflow runs, then the jobs
    of a candidate run. A run counts only when its workflow path is the CI
    workflow, its conclusion is success, its head repository is this repo,
    its head commit tree is ``tree``, and a job named ``verify`` succeeded.
    """
    if not token:
        raise VerifyError(
            f"no GITHUB_TOKEN or GH_TOKEN; cannot prove a successful verify job for tree {tree}"
        )
    expected_repo = f"{owner}/{repo}"
    problems: list[str] = []
    seen: set[int] = set()
    sources = []
    if head_sha:
        sources.append(_workflow_runs(owner, repo, head_sha))
    sources.append(_workflow_runs(owner, repo))

    def consider(run_info: dict) -> CiEvidence | None:
        run_id = run_info.get("id")
        if not isinstance(run_id, int) or run_id in seen:
            return None
        seen.add(run_id)
        if run_info.get("path") != CI_WORKFLOW_PATH:
            return None
        head = run_info.get("head_commit") or {}
        if not isinstance(head, dict) or head.get("tree_id") != tree:
            return None
        repository = run_info.get("head_repository") or {}
        full_name = repository.get("full_name") if isinstance(repository, dict) else None
        if full_name != expected_repo:
            shown = full_name or "missing head repository"
            problems.append(
                f"CI workflow run {run_id} for tree {tree} is from {shown}, not {expected_repo}"
            )
            return None
        conclusion = run_info.get("conclusion")
        if conclusion != "success":
            problems.append(f"CI workflow run {run_id} for tree {tree} concluded {conclusion}")
            return None
        jobs_url = f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/jobs?per_page=100"
        jobs: list[object] = []
        pages = 0
        while jobs_url and pages < max_pages:
            pages += 1
            status, body, headers = get(jobs_url, token)
            payload = _api_status(status, body, f"reading jobs for CI workflow run {run_id}", tree)
            jobs.extend(payload.get("jobs") or [])
            jobs_url = _next_link(headers)
        job_conclusion = _verify_job_conclusion(jobs)
        if job_conclusion != "success":
            shown = job_conclusion if job_conclusion is not None else "missing"
            problems.append(
                f"CI workflow run {run_id} for tree {tree} job {VERIFY_JOB_NAME} concluded {shown}"
            )
            return None
        sha = str(run_info.get("head_sha") or head.get("id") or "")
        if not sha:
            problems.append(f"CI workflow run {run_id} for tree {tree} has no commit SHA")
            return None
        return CiEvidence(commit=sha, run_id=run_id)

    for start in sources:
        url: str | None = start
        pages = 0
        while url and pages < max_pages:
            pages += 1
            status, body, headers = get(url, token)
            payload = _api_status(status, body, "reading workflow runs", tree)
            for run_info in payload.get("workflow_runs") or []:
                if not isinstance(run_info, dict):
                    continue
                found = consider(run_info)
                if found is not None:
                    return found
            url = _next_link(headers)
    if problems:
        raise VerifyError(problems[0])
    raise VerifyError(f"no matching CI workflow run for tree {tree}")


def run_unit_tests(
    test_files: list[Path],
    *,
    which,
    execute,
    tree: str,
    prove,
    emit=print,
) -> None:
    """Run unit tests. Container tests without their runtime need CI evidence."""
    deferred: list[tuple[Path, str]] = []
    for path in test_files:
        runtime = container_runtime_marker(path.read_text(encoding="utf-8"))
        if runtime and which(runtime) is None:
            deferred.append((path, runtime))
            continue
        if runtime:
            emit(f"verify: path local: {runtime} on PATH; running {path.name}")
        result = execute(path)
        if result.returncode != 0:
            raise VerifyError(f"{path.name} exited with {result.returncode}")
    if not deferred:
        return
    runtimes = ", ".join(sorted({runtime for _path, runtime in deferred}))
    names = ", ".join(path.name for path, _runtime in deferred)
    emit(
        f"verify: container runtime not on PATH ({runtimes}); "
        f"not running {names}; requiring a successful CI verify job for tree {tree}"
    )
    evidence = prove(tree)
    emit(
        f"verify: path CI evidence: tree {tree} run {evidence.run_id} "
        f"commit {evidence.commit} job verify success"
    )


def main() -> int:
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        return fail(f"missing tools on PATH: {', '.join(missing)}")

    config = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    absent = [hook for hook in REQUIRED_HOOKS if f"id: {hook}\n" not in config]
    if absent:
        return fail(f"required hooks missing from .pre-commit-config.yaml: {', '.join(absent)}")

    head = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    print(f"verify: commit {head}")
    for tool in ("pre-commit",):
        version = run([tool, "--version"], capture=True).stdout.splitlines()
        print(f"verify: {tool}: {version[0] if version else 'unknown'}")

    if run(["git", "status", "--porcelain"], capture=True).stdout.strip():
        return fail("working tree is not clean; the gate must run on a committed tree")

    test_files = sorted((ROOT / "bin").glob("test_*.py"))
    if not test_files:
        return fail("missing bin/test_*.py")
    test_env = os.environ.copy()
    test_env["PYTHONDONTWRITEBYTECODE"] = "1"
    tree = run(["git", "rev-parse", "HEAD^{tree}"], capture=True)
    if tree.returncode != 0:
        return fail("git rev-parse HEAD^{tree} failed")
    tree_sha = tree.stdout.strip()

    def execute(path: Path) -> subprocess.CompletedProcess[str]:
        return run([sys.executable, str(path)], env=test_env)

    def prove(tree_id: str) -> CiEvidence:
        remote = run(["git", "remote", "get-url", "origin"], capture=True)
        if remote.returncode != 0:
            raise VerifyError("git remote get-url origin failed")
        owner, repo = parse_github_slug(remote.stdout)
        return successful_verify_run(tree_id, owner, repo, github_token(), head_sha=head)

    try:
        run_unit_tests(
            test_files,
            which=shutil.which,
            execute=execute,
            tree=tree_sha,
            prove=prove,
        )
    except VerifyError as exc:
        return fail(str(exc))

    result = run(["pre-commit", "run", "--all-files", "--show-diff-on-failure", "--color", "never"])
    if result.returncode != 0:
        return fail(f"pre-commit exited with {result.returncode}")

    if run(["git", "status", "--porcelain"], capture=True).stdout.strip():
        return fail("hooks modified the working tree")

    print(f"verify: PASS on {head}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
