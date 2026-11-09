#!/usr/bin/env python3
"""Unit tests for bin/tailnet-policy.py. The HTTP layer is scripted."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policy" / "tailscale-acl.hujson"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
ACCESS_TOKEN = "test-access-token"


def load_tool():
    path = Path(__file__).with_name("tailnet-policy.py")
    spec = importlib.util.spec_from_file_location("tailnet_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()


class ScriptedTransport:
    def __init__(self, responses: list[tuple[int, bytes, dict[str, str]]]) -> None:
        self._responses = list(responses)
        self.requests: list = []

    def __call__(self, request):
        self.requests.append(request)
        if not self._responses:
            raise AssertionError(f"unexpected request {request.method} {request.url}")
        status, body, headers = self._responses.pop(0)
        return TOOL.HttpResponse(status, body, headers)


class EvaluatorTests(unittest.TestCase):
    def test_repo_policy_tests_pass(self) -> None:
        policy = TOOL.parse_hujson(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(TOOL.evaluate_tests(policy), [])

    def test_hujson_comments_and_trailing_commas(self) -> None:
        parsed = TOOL.parse_hujson(
            """
            // comment
            {"grants": [{"src": ["tag:a"], "dst": ["tag:b"], "ip": ["tcp:22"],}],
             "tests": [{"src": "tag:a", "accept": ["tag:b:22"],}]}
            """
        )
        self.assertEqual(TOOL.evaluate_tests(parsed), [])

    def test_comment_inside_string_is_kept(self) -> None:
        parsed = TOOL.parse_hujson('{"groups": {"group:ops": ["not//a-comment"]}}')
        self.assertEqual(parsed["groups"]["group:ops"], ["not//a-comment"])

    def test_removed_grant_fails_its_test(self) -> None:
        policy = TOOL.parse_hujson(POLICY.read_text(encoding="utf-8"))
        policy["grants"] = [
            grant
            for grant in policy["grants"]
            if grant["src"] != ["camilopiedra92@gmail.com"]
        ]
        failures = TOOL.evaluate_tests(policy)
        self.assertTrue(any("want accept, got deny" in item for item in failures))

    def test_overbroad_grant_fails_a_deny(self) -> None:
        policy = TOOL.parse_hujson(POLICY.read_text(encoding="utf-8"))
        policy["grants"].append(
            {"src": ["tag:hermes-prod"], "dst": ["tag:hermes-ops"], "ip": ["*"]}
        )
        failures = TOOL.evaluate_tests(policy)
        self.assertTrue(any("want deny, got accept" in item for item in failures))

    def test_autogroup_self_does_not_reach_a_tag(self) -> None:
        policy = {
            "grants": [
                {"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
            ],
            "tests": [
                {
                    "src": "owner@example.com",
                    "accept": ["owner@example.com:22"],
                    "deny": ["tag:hermes-prod:22"],
                }
            ],
        }
        self.assertEqual(TOOL.evaluate_tests(policy), [])

    def test_group_member_matches(self) -> None:
        policy = {
            "groups": {"group:ops": ["owner@example.com"]},
            "grants": [
                {"src": ["group:ops"], "dst": ["tag:host"], "ip": ["tcp:22"]},
            ],
            "tests": [{"src": "owner@example.com", "accept": ["tag:host:22"]}],
        }
        self.assertEqual(TOOL.evaluate_tests(policy), [])

    def test_missing_tests_block_fails(self) -> None:
        self.assertEqual(TOOL.evaluate_tests({"grants": []}), ["policy has no tests block"])

    def test_unsupported_field_fails_closed(self) -> None:
        failures = TOOL.evaluate_tests({"nodeAttrs": [], "tests": []})
        self.assertTrue(any("unsupported policy field" in item for item in failures))

    def test_ssh_recorder_is_not_evaluated(self) -> None:
        policy = {
            "tests": [{"src": "tag:a", "deny": ["tag:b:22"]}],
            "ssh": [
                {
                    "action": "accept",
                    "src": ["tag:a"],
                    "dst": ["tag:b"],
                    "users": ["root"],
                    "recorder": ["tag:recorder"],
                }
            ],
            "sshTests": [{"src": "tag:a", "dst": ["tag:b"], "deny": ["root"]}],
        }
        failures = TOOL.evaluate_tests(policy)
        self.assertTrue(any("unsupported fields: recorder" in item for item in failures))

    def _check_rule_policy(self, kind: str) -> dict:
        return {
            "tests": [{"src": "owner@example.com", "accept": ["tag:host:22"]}],
            "grants": [{"src": ["owner@example.com"], "dst": ["tag:host"], "ip": ["tcp:22"]}],
            "ssh": [
                {
                    "action": "check",
                    "src": ["owner@example.com"],
                    "dst": ["tag:host"],
                    "users": ["ops"],
                    "checkPeriod": "12h",
                }
            ],
            "sshTests": [
                {"src": "owner@example.com", "dst": ["tag:host"], kind: ["ops"]}
            ],
        }

    def test_ssh_test_accept_on_a_check_rule_is_refused(self) -> None:
        # Tailscale rejected the repo policy with exactly this: want accept, got check.
        failures = TOOL.evaluate_tests(self._check_rule_policy("accept"))
        self.assertTrue(any("want accept, got check" in item for item in failures), failures)

    def test_ssh_test_check_on_a_check_rule_passes(self) -> None:
        self.assertEqual(TOOL.evaluate_tests(self._check_rule_policy("check")), [])

    def test_ssh_test_check_on_an_accept_rule_is_refused(self) -> None:
        policy = self._check_rule_policy("check")
        policy["ssh"][0]["action"] = "accept"
        policy["ssh"][0].pop("checkPeriod")
        failures = TOOL.evaluate_tests(policy)
        self.assertTrue(any("want check, got accept" in item for item in failures), failures)

    def test_tag_to_tag_check_mode_is_refused(self) -> None:
        policy = {
            "tests": [{"src": "tag:a", "deny": ["tag:hermes-prod:22"]}],
            "ssh": [
                {
                    "action": "check",
                    "src": ["tag:a"],
                    "dst": ["tag:hermes-prod"],
                    "users": ["hermesops"],
                }
            ],
            "sshTests": [
                {"src": "tag:a", "dst": ["tag:hermes-prod"], "deny": ["hermesops"]}
            ],
        }
        failures = TOOL.evaluate_tests(policy)
        self.assertTrue(any("uses check from a tag to a tag" in item for item in failures))

    def test_repo_policy_ssh_accepts_only_owner_and_box(self) -> None:
        policy = TOOL.parse_hujson(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(TOOL.evaluate_tests(policy), [])
        groups: dict = {}
        sources = (
            "camilopiedra92@gmail.com",
            "tag:hermes-ops",
        )
        for src in sources:
            self.assertTrue(TOOL._ssh_allowed(policy, src, "tag:hermes-prod", "hermesops", groups), src)
            for user in ("root", "hermes", "ubuntu"):
                self.assertFalse(TOOL._ssh_allowed(policy, src, "tag:hermes-prod", user, groups), user)
        owner = next(
            rule
            for rule in policy["ssh"]
            if rule["src"] == ["camilopiedra92@gmail.com"]
        )
        self.assertEqual(owner["action"], "check")
        self.assertEqual(owner["checkPeriod"], "12h")
        self.assertFalse(
            TOOL._ssh_allowed(policy, "tag:hermes-prod", "tag:hermes-ops", "hermesops", groups)
        )
        self.assertNotIn("ci-", POLICY.read_text(encoding="utf-8"))

    def test_quote_etag(self) -> None:
        self.assertEqual(TOOL.quote_etag("abc"), '"abc"')
        self.assertEqual(TOOL.quote_etag('"abc"'), '"abc"')
        self.assertEqual(TOOL.quote_etag('W/"abc"'), '"abc"')


class CommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env = mock.patch.dict(
            os.environ,
            {
                "TAILSCALE_OAUTH_CLIENT_ID": CLIENT_ID,
                "TAILSCALE_OAUTH_CLIENT_SECRET": CLIENT_SECRET,
            },
        )
        self._env.start()
        self.policy = POLICY.read_bytes()

    def tearDown(self) -> None:
        self._env.stop()

    def run_tool(self, argv: list[str], transport: ScriptedTransport) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = TOOL.main(argv, transport=transport)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_silent_about_secrets(self, stdout: str, stderr: str) -> None:
        combined = stdout + stderr
        self.assertNotIn(CLIENT_SECRET, combined)
        self.assertNotIn(ACCESS_TOKEN, combined)
        self.assertNotIn("Authorization", combined)

    def token_response(self) -> tuple[int, bytes, dict[str, str]]:
        body = json.dumps(
            {"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600}
        ).encode()
        return (200, body, {"Content-Type": "application/json"})

    def test_apply_refuses_failed_tests_without_http(self) -> None:
        text = POLICY.read_text(encoding="utf-8").replace(
            '"ip":  ["tcp:22"],',
            '"ip":  ["*"],',
            1,
        )
        # Keep the fixture out of the repo tree so the gate stays clean.
        path = Path(os.environ.get("TMPDIR", "/tmp")) / "tailnet-policy-overbroad.hujson"
        path.write_text(text, encoding="utf-8")
        self.addCleanup(path.unlink, missing_ok=True)
        transport = ScriptedTransport([])
        code, _stdout, stderr = self.run_tool(["apply", "--file", str(path)], transport)
        self.assertEqual(code, 2)
        self.assertEqual(transport.requests, [])
        self.assertIn("want deny, got accept", stderr)
        self.assert_silent_about_secrets("", stderr)

    def test_validate_posts_the_file_and_requires_an_empty_body(self) -> None:
        transport = ScriptedTransport([self.token_response(), (200, b"", {})])
        code, stdout, stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
        self.assertEqual(code, 0, stderr)
        self.assertIn("empty result", stdout)
        self.assertEqual(transport.requests[0].url, f"{TOOL.API_ROOT}/oauth/token")
        validate = transport.requests[1]
        self.assertEqual(validate.method, "POST")
        self.assertTrue(validate.url.endswith("/acl/validate"))
        self.assertEqual(validate.body, self.policy)
        self.assertEqual(validate.headers["Authorization"], f"Bearer {ACCESS_TOKEN}")
        self.assertNotIn(CLIENT_SECRET, validate.headers.get("Authorization", ""))
        self.assert_silent_about_secrets(stdout, stderr)

    def test_validate_accepts_an_empty_json_object(self) -> None:
        # Tailscale answers a passing validation with an empty JSON object.
        transport = ScriptedTransport([self.token_response(), (200, b"{}", {})])
        code, stdout, stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
        self.assertEqual(code, 0, stderr)
        self.assertIn("empty result", stdout)

    def test_validate_accepts_an_empty_json_object_with_whitespace(self) -> None:
        transport = ScriptedTransport([self.token_response(), (200, b" {\n}\n", {})])
        code, _stdout, stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
        self.assertEqual(code, 0, stderr)

    def test_validate_rejection_names_the_http_status(self) -> None:
        body = json.dumps({"message": "test(s) failed", "data": []}).encode()
        transport = ScriptedTransport([self.token_response(), (200, body, {})])
        code, _stdout, stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
        self.assertEqual(code, 2)
        self.assertIn("HTTP 200", stderr)

    def test_validate_rejects_a_json_array_or_non_json_body(self) -> None:
        for body in (b"[]", b"null", b"<html>bad gateway</html>", b'{"message": ""}'):
            transport = ScriptedTransport([self.token_response(), (200, body, {})])
            code, _stdout, _stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
            self.assertEqual(code, 2, body)

    def test_apply_proceeds_when_validate_returns_an_empty_json_object(self) -> None:
        etag = "5a426d83c20e4ef2add472f4621eccecc29d87de58ded03766d09b031e15f08a"
        transport = ScriptedTransport(
            [
                self.token_response(),
                (200, b"{}", {}),
                (200, b"previous", {"ETag": etag}),
                (200, self.policy, {}),
                (200, self.policy, {"ETag": f'"{etag}"'}),
            ]
        )
        code, stdout, stderr = self.run_tool(["apply", "--file", str(POLICY)], transport)
        self.assertEqual(code, 0, stderr)
        self.assertIn("readback matches", stdout)

    def test_validate_rejects_a_non_empty_result(self) -> None:
        body = json.dumps({"message": "test(s) failed", "data": []}).encode()
        transport = ScriptedTransport([self.token_response(), (200, body, {})])
        code, _stdout, stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
        self.assertEqual(code, 2)
        self.assertIn("test(s) failed", stderr)
        self.assertEqual(len(transport.requests), 2)

    def test_apply_uses_if_match_and_requires_byte_identical_readback(self) -> None:
        etag = "5a426d83c20e4ef2add472f4621eccecc29d87de58ded03766d09b031e15f08a"
        transport = ScriptedTransport(
            [
                self.token_response(),
                (200, b"", {}),
                (200, b"previous", {"ETag": etag}),
                (200, self.policy, {}),
                (200, self.policy, {"ETag": f'"{etag}"'}),
            ]
        )
        code, stdout, stderr = self.run_tool(["apply", "--file", str(POLICY)], transport)
        self.assertEqual(code, 0, stderr)
        self.assertIn("readback matches", stdout)
        methods = [(item.method, item.url) for item in transport.requests]
        self.assertEqual(
            methods,
            [
                ("POST", f"{TOOL.API_ROOT}/oauth/token"),
                ("POST", f"{TOOL.API_ROOT}/tailnet/-/acl/validate"),
                ("GET", f"{TOOL.API_ROOT}/tailnet/-/acl"),
                ("POST", f"{TOOL.API_ROOT}/tailnet/-/acl"),
                ("GET", f"{TOOL.API_ROOT}/tailnet/-/acl"),
            ],
        )
        posted = transport.requests[3]
        self.assertEqual(posted.headers["If-Match"], f'"{etag}"')
        self.assertEqual(posted.body, self.policy)
        self.assertNotIn("If-Match", transport.requests[1].headers)
        self.assert_silent_about_secrets(stdout, stderr)

    def test_apply_stops_when_validate_fails(self) -> None:
        transport = ScriptedTransport(
            [self.token_response(), (400, b'{"message":"test(s) failed"}', {})]
        )
        code, _stdout, stderr = self.run_tool(["apply", "--file", str(POLICY)], transport)
        self.assertEqual(code, 2)
        set_calls = [
            item for item in transport.requests if item.url.rstrip("/").endswith("/acl")
        ]
        self.assertEqual(set_calls, [])
        self.assertIn("test(s) failed", stderr)

    def test_apply_fails_when_readback_differs(self) -> None:
        transport = ScriptedTransport(
            [
                self.token_response(),
                (200, b"", {}),
                (200, self.policy, {"ETag": '"abc"'}),
                (200, self.policy, {}),
                (200, b"not-the-file\n", {"ETag": '"def"'}),
            ]
        )
        code, _stdout, stderr = self.run_tool(["apply", "--file", str(POLICY)], transport)
        self.assertEqual(code, 2)
        self.assertIn("not byte-identical", stderr)

    def test_drift_exit_codes(self) -> None:
        same = ScriptedTransport(
            [self.token_response(), (200, self.policy, {"ETag": '"abc"'})]
        )
        code, stdout, stderr = self.run_tool(["drift", "--file", str(POLICY)], same)
        self.assertEqual(code, 0, stderr)
        self.assertIn("matches", stdout)

        different = ScriptedTransport(
            [self.token_response(), (200, b"other\n", {"ETag": '"abc"'})]
        )
        code, stdout, stderr = self.run_tool(["drift", "--file", str(POLICY)], different)
        self.assertEqual(code, 1)
        self.assertIn("differs", stderr)
        self.assertNotIn("other", stdout)

    def test_diff_prints_policy_bytes_not_the_token(self) -> None:
        transport = ScriptedTransport(
            [self.token_response(), (200, b"live-policy\n", {"ETag": '"abc"'})]
        )
        code, stdout, stderr = self.run_tool(["diff", "--file", str(POLICY)], transport)
        self.assertEqual(code, 1)
        self.assertIn("live-policy", stdout)
        self.assert_silent_about_secrets(stdout, stderr)

    def test_api_error_redacts_the_secret_and_token(self) -> None:
        message = json.dumps(
            {"message": f"rejected {CLIENT_SECRET} and {ACCESS_TOKEN}"}
        ).encode()
        transport = ScriptedTransport([self.token_response(), (500, message, {})])
        code, stdout, stderr = self.run_tool(["validate", "--file", str(POLICY)], transport)
        self.assertEqual(code, 2)
        self.assertIn("[redacted]", stderr)
        self.assert_silent_about_secrets(stdout, stderr)

    def test_missing_secret_names_the_variable_only(self) -> None:
        with mock.patch.dict(os.environ, {"TAILSCALE_OAUTH_CLIENT_SECRET": ""}, clear=False):
            transport = ScriptedTransport([])
            code, _stdout, stderr = self.run_tool(["drift", "--file", str(POLICY)], transport)
        self.assertEqual(code, 2)
        self.assertIn("TAILSCALE_OAUTH_CLIENT_SECRET", stderr)
        self.assertEqual(transport.requests, [])


if __name__ == "__main__":
    unittest.main()
