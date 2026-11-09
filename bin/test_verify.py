#!/usr/bin/env python3
"""Gate behavior for tests that declare a container runtime."""

from __future__ import annotations

import io
import subprocess
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import verify

ROOT = Path(__file__).resolve().parent.parent
TREE = "a" * 40
OTHER = "b" * 40
SHA = "c" * 40
TOKEN = "ghp_test_token_not_printed"
RUN_ID = 42407373723


def _completed(code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["test"], code, "", "")


def _files(tmp: Path) -> list[Path]:
    plain = tmp / "test_plain.py"
    plain.write_text("print('plain')\n", encoding="utf-8")
    marked = tmp / "test_docker_name_only.py"
    marked.write_text(
        'REQUIRES_CONTAINER_RUNTIME = "docker"\nprint("container")\n',
        encoding="utf-8",
    )
    return [plain, marked]


def _run(
    tree: str,
    *,
    sha: str = SHA,
    run_id: int = RUN_ID,
    conclusion: str = "success",
    full_name: str = "owner/repo",
    path: str = verify.CI_WORKFLOW_PATH,
) -> dict:
    return {
        "id": run_id,
        "path": path,
        "conclusion": conclusion,
        "head_sha": sha,
        "head_repository": {"full_name": full_name},
        "head_commit": {"id": sha, "tree_id": tree},
    }


def _runs(*runs: dict) -> dict:
    return {"workflow_runs": list(runs)}


def _jobs(conclusion: str = "success", name: str = "verify") -> dict:
    return {"jobs": [{"name": name, "conclusion": conclusion}]}


class MarkerTests(unittest.TestCase):
    def test_marker_is_declared_and_not_inferred_from_the_name(self) -> None:
        self.assertIsNone(verify.container_runtime_marker("def test_docker():\n    pass\n"))
        self.assertEqual(
            verify.container_runtime_marker('REQUIRES_CONTAINER_RUNTIME = "docker"\n'),
            "docker",
        )

    def test_remote_parser_drops_credentials(self) -> None:
        owner, repo = verify.parse_github_slug(
            "https://x-access-token:ghp_secret@github.com/camilopiedra92/hermes-infra.git"
        )
        self.assertEqual((owner, repo), ("camilopiedra92", "hermes-infra"))


class RuntimePathTests(unittest.TestCase):
    def test_docker_present_runs_the_marked_test(self) -> None:
        tmp = Path(self._tmp())
        files = _files(tmp)
        ran: list[str] = []
        notes: list[str] = []

        def execute(path: Path) -> subprocess.CompletedProcess[str]:
            ran.append(path.name)
            return _completed()

        def prove(_tree: str) -> str:
            raise AssertionError("CI evidence must not be queried when docker is on PATH")

        verify.run_unit_tests(
            files,
            which=lambda name: "/usr/bin/docker" if name == "docker" else None,
            execute=execute,
            tree=TREE,
            prove=prove,
            emit=notes.append,
        )
        self.assertEqual(ran, ["test_plain.py", "test_docker_name_only.py"])
        self.assertTrue(any(note.startswith("verify: path local: docker on PATH") for note in notes))

    def test_docker_absent_matching_green_tree_passes(self) -> None:
        tmp = Path(self._tmp())
        files = _files(tmp)
        ran: list[str] = []
        notes: list[str] = []

        def execute(path: Path) -> subprocess.CompletedProcess[str]:
            ran.append(path.name)
            return _completed()

        verify.run_unit_tests(
            files,
            which=lambda _name: None,
            execute=execute,
            tree=TREE,
            prove=lambda tree: verify.CiEvidence(commit=SHA, run_id=99) if tree == TREE else None,
            emit=notes.append,
        )
        self.assertEqual(ran, ["test_plain.py"])
        self.assertTrue(
            any(
                note == f"verify: path CI evidence: tree {TREE} run 99 commit {SHA} job verify success"
                for note in notes
            )
        )

    def test_ordinary_failure_is_not_replaced_by_ci_evidence(self) -> None:
        tmp = Path(self._tmp())
        files = _files(tmp)

        def execute(path: Path) -> subprocess.CompletedProcess[str]:
            return _completed(1 if path.name == "test_plain.py" else 0)

        with self.assertRaises(verify.VerifyError) as caught:
            verify.run_unit_tests(
                files,
                which=lambda _name: None,
                execute=execute,
                tree=TREE,
                prove=lambda _tree: (_ for _ in ()).throw(AssertionError("prove")),
                emit=lambda _note: None,
            )
        self.assertIn("test_plain.py exited with 1", str(caught.exception))

    def _tmp(self) -> str:
        return self.enterContext(tempfile_dir())


def tempfile_dir():
    import tempfile

    return tempfile.TemporaryDirectory()


class ApiEvidenceTests(unittest.TestCase):
    def _evidence(self, get, head_sha: str | None = None) -> verify.CiEvidence:
        return verify.successful_verify_run(TREE, "owner", "repo", TOKEN, get, head_sha=head_sha)

    def _failure(self, get, head_sha: str | None = None) -> str:
        with self.assertRaises(verify.VerifyError) as caught:
            self._evidence(get, head_sha)
        message = str(caught.exception)
        self.assertNotIn(TOKEN, message)
        return message

    def test_matching_actions_run_and_verify_job_pass(self) -> None:
        urls: list[str] = []

        def get(url: str, token: str):
            urls.append(url)
            self.assertEqual(token, TOKEN)
            self.assertNotIn(TOKEN, url)
            if "/jobs" in url:
                return 200, _jobs(), {}
            if "/actions/runs" in url:
                return 200, _runs(_run(TREE)), {}
            raise AssertionError(url)

        evidence = self._evidence(get, head_sha=SHA)
        self.assertEqual(evidence, verify.CiEvidence(commit=SHA, run_id=RUN_ID))
        self.assertIn(f"head_sha={SHA}", urls[0])
        self.assertIn(f"/actions/runs/{RUN_ID}/jobs", urls[1])
        self.assertNotIn("check-runs", " ".join(urls))

    def test_non_matching_tree_fails(self) -> None:
        def get(url: str, token: str):
            self.assertNotIn(TOKEN, url)
            if "/actions/runs" in url:
                return 200, _runs(_run(OTHER)), {}
            raise AssertionError(url)

        message = self._failure(get)
        self.assertIn(f"no matching CI workflow run for tree {TREE}", message)

    def test_failed_run_on_the_tree_fails(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                raise AssertionError("jobs are not read for a failed run")
            return 200, _runs(_run(TREE, conclusion="failure")), {}

        message = self._failure(get)
        self.assertIn(f"CI workflow run {RUN_ID} for tree {TREE} concluded failure", message)

    def test_cancelled_run_on_the_tree_fails(self) -> None:
        def get(_url: str, _token: str):
            return 200, _runs(_run(TREE, conclusion="cancelled")), {}

        message = self._failure(get)
        self.assertIn(f"CI workflow run {RUN_ID} for tree {TREE} concluded cancelled", message)

    def test_fork_run_fails(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                raise AssertionError("a fork run is not evidence")
            return 200, _runs(_run(TREE, full_name="someone/hermes-infra")), {}

        message = self._failure(get)
        self.assertIn("someone/hermes-infra", message)
        self.assertIn("not owner/repo", message)

    def test_missing_verify_job_fails(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                return 200, _jobs(name="other"), {}
            return 200, _runs(_run(TREE)), {}

        message = self._failure(get)
        self.assertIn(f"job verify concluded missing", message)

    def test_failed_verify_job_fails(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                return 200, _jobs("failure"), {}
            return 200, _runs(_run(TREE)), {}

        message = self._failure(get)
        self.assertIn(f"CI workflow run {RUN_ID} for tree {TREE} job verify concluded failure", message)

    def test_older_success_still_counts_after_a_failed_run(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                return 200, _jobs(), {}
            return 200, _runs(_run(TREE, run_id=1, conclusion="failure"), _run(TREE, run_id=2)), {}

        evidence = self._evidence(get)
        self.assertEqual(evidence.run_id, 2)

    def test_forbidden_runs_list_fails(self) -> None:
        message = self._failure(lambda _url, _token: (403, {"message": TOKEN}, {}))
        self.assertIn("HTTP 403", message)
        self.assertIn(TREE, message)

    def test_missing_runs_list_fails(self) -> None:
        message = self._failure(lambda _url, _token: (404, {}, {}))
        self.assertIn("HTTP 404", message)
        self.assertIn(TREE, message)

    def test_forbidden_jobs_list_fails(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                return 403, {"message": TOKEN}, {}
            return 200, _runs(_run(TREE)), {}

        message = self._failure(get)
        self.assertIn("HTTP 403", message)
        self.assertIn(str(RUN_ID), message)

    def test_missing_jobs_list_fails(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                return 404, {}, {}
            return 200, _runs(_run(TREE)), {}

        message = self._failure(get)
        self.assertIn("HTTP 404", message)
        self.assertIn(str(RUN_ID), message)

    def test_gh_token_is_accepted(self) -> None:
        self.assertEqual(verify.github_token({"GH_TOKEN": TOKEN}), TOKEN)
        self.assertEqual(verify.github_token({"GITHUB_TOKEN": "a", "GH_TOKEN": "b"}), "a")

    def test_missing_token_fails_without_calling_the_api(self) -> None:
        def get(_url: str, _token: str):
            raise AssertionError("API called without a token")

        with self.assertRaises(verify.VerifyError) as caught:
            verify.successful_verify_run(TREE, "owner", "repo", "", get)
        self.assertIn("no GITHUB_TOKEN or GH_TOKEN", str(caught.exception))

    def test_api_error_fails(self) -> None:
        def get(_url: str, _token: str):
            return 500, {"message": TOKEN}, {}

        with self.assertRaises(verify.VerifyError) as caught:
            verify.successful_verify_run(TREE, "owner", "repo", TOKEN, get)
        message = str(caught.exception)
        self.assertIn("GitHub API HTTP 500", message)
        self.assertIn(TREE, message)
        self.assertNotIn(TOKEN, message)

    def test_wrong_workflow_path_is_not_a_match(self) -> None:
        def get(url: str, _token: str):
            if "/jobs" in url:
                raise AssertionError("another workflow is not evidence")
            return 200, _runs(_run(TREE, path=".github/workflows/other.yml")), {}

        message = self._failure(get)
        self.assertIn(f"no matching CI workflow run for tree {TREE}", message)

    def test_same_tree_on_another_commit_is_found_in_the_run_list(self) -> None:
        other = "d" * 40

        def get(url: str, _token: str):
            if "head_sha=" in url:
                return 200, {"workflow_runs": []}, {}
            if "/jobs" in url:
                return 200, _jobs(), {}
            return 200, _runs(_run(TREE, sha=other, run_id=7)), {}

        evidence = self._evidence(get, head_sha=SHA)
        self.assertEqual(evidence, verify.CiEvidence(commit=other, run_id=7))

    def test_http_error_hides_the_token_and_names_the_actions_path(self) -> None:
        def boom(request, timeout):  # noqa: ARG001
            self.assertEqual(request.get_header("Authorization"), f"Bearer {TOKEN}")
            self.assertNotIn(TOKEN, request.full_url)
            raise urllib.error.HTTPError(
                request.full_url,
                403,
                "Forbidden",
                hdrs=None,
                fp=io.BytesIO(TOKEN.encode()),
            )

        with patch("verify.urllib.request.urlopen", boom):
            with self.assertRaises(verify.VerifyError) as caught:
                verify.github_get(
                    "https://api.github.com/repos/owner/repo/actions/runs?head_sha=abc",
                    TOKEN,
                )
        message = str(caught.exception)
        self.assertIn("HTTP 403", message)
        self.assertIn("/repos/owner/repo/actions/runs", message)
        self.assertNotIn("check-runs", message)
        self.assertNotIn(TOKEN, message)
        self.assertNotIn("abc", message)

    def test_network_error_hides_the_token(self) -> None:
        def boom(request, timeout):  # noqa: ARG001
            self.assertIn("Bearer", request.get_header("Authorization"))
            raise urllib.error.URLError("network down")

        with patch("verify.urllib.request.urlopen", boom):
            with self.assertRaises(verify.VerifyError) as caught:
                verify.github_get("https://api.github.com/repos/o/r/actions/runs", TOKEN)
        message = str(caught.exception)
        self.assertIn("network down", message)
        self.assertNotIn(TOKEN, message)


if __name__ == "__main__":
    unittest.main()
