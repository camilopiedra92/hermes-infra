#!/usr/bin/env python3
"""Check and apply the Hermes tailnet policy through the Tailscale API.

Subcommands:
  validate   parse the file, run its tests, then POST /api/v2/tailnet/-/acl/validate
  diff       show a unified diff of the live HuJSON against the repo file
  apply      validate, then POST the file with If-Match on the live ETag
  drift      exit 1 when the live policy bytes differ from the repo file

Credentials come from TAILSCALE_OAUTH_CLIENT_ID and
TAILSCALE_OAUTH_CLIENT_SECRET. This program never prints those values, the
access token, or an Authorization header.

The policy file is HuJSON. apply refuses when the file's own tests block
does not pass, before it calls the API that would change the tailnet.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

API_ROOT = "https://api.tailscale.com/api/v2"
TAILNET = "-"
DEFAULT_FILE = Path(__file__).resolve().parent.parent / "policy" / "tailscale-acl.hujson"
USER_AGENT = "hermes-infra-tailnet-policy"
TIMEOUT_SECONDS = 30

# Top-level keys this tool can evaluate. Anything else can change test
# results, so apply refuses rather than ignoring it.
_KNOWN_TOP_LEVEL = frozenset(
    {"tagOwners", "grants", "acls", "tests", "ssh", "sshTests", "groups", "hosts"}
)
_GRANT_KEYS = frozenset({"src", "dst", "ip"})
_ACL_KEYS = frozenset({"action", "src", "dst"})
_TEST_KEYS = frozenset({"src", "accept", "deny", "proto"})
_SSH_RULE_KEYS = frozenset({"action", "src", "dst", "users", "checkPeriod"})
_SSH_TEST_KEYS = frozenset({"src", "dst", "accept", "check", "deny"})


class PolicyError(Exception):
    """A policy or API failure. exit_code 1 is drift; 2 is a hard refusal."""

    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]


Transport = Callable[[HttpRequest], HttpResponse]


@dataclass(frozen=True)
class LivePolicy:
    body: bytes
    etag: str


def redact(text: str, secrets: list[str]) -> str:
    redacted = text
    for secret in secrets:
        if secret:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted


def hujson_to_json(text: str) -> str:
    """Turn Tailscale HuJSON (// comments, trailing commas) into JSON text."""
    without_comments = _strip_line_comments(text)
    return _strip_trailing_commas(without_comments)


def parse_hujson(text: str) -> dict:
    try:
        parsed = json.loads(hujson_to_json(text))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"policy file is not valid HuJSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PolicyError("policy file must be a JSON object")
    return parsed


def evaluate_tests(policy: dict) -> list[str]:
    """Return human-readable failures. An empty list means the tests passed."""
    unsupported = _unsupported_policy(policy)
    if unsupported:
        return unsupported
    tests = policy.get("tests")
    if not isinstance(tests, list) or not tests:
        return ["policy has no tests block"]
    failures: list[str] = []
    for index, test in enumerate(tests, start=1):
        if not isinstance(test, dict):
            failures.append(f"test {index} is not an object")
            continue
        extra = set(test) - _TEST_KEYS
        if extra:
            failures.append(f"test {index} has unsupported fields: {', '.join(sorted(extra))}")
            continue
        src = test.get("src")
        if not isinstance(src, str) or not src:
            failures.append(f"test {index} has no src")
            continue
        proto = test.get("proto")
        if proto is not None and proto not in ("tcp", "udp"):
            failures.append(f"test {index} has unsupported proto {proto!r}")
            continue
        for kind in ("accept", "deny"):
            destinations = test.get(kind, [])
            if destinations is None:
                destinations = []
            if not isinstance(destinations, list):
                failures.append(f"test {index} {kind} is not a list")
                continue
            for destination in destinations:
                if not isinstance(destination, str):
                    failures.append(f"test {index} {kind} entry is not a string")
                    continue
                try:
                    allowed = _access_allowed(policy, src, destination, proto)
                except PolicyError as exc:
                    failures.append(f"test {index}: {exc}")
                    continue
                if kind == "accept" and not allowed:
                    failures.append(f"test {index}: {src} -> {destination} want accept, got deny")
                if kind == "deny" and allowed:
                    failures.append(f"test {index}: {src} -> {destination} want deny, got accept")
    failures.extend(_evaluate_ssh_tests(policy))
    return failures


def load_policy_file(path: Path) -> tuple[bytes, dict]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc}") from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(f"{path} is not UTF-8") from exc
    return raw, parse_hujson(text)


def quote_etag(etag: str) -> str:
    value = etag.strip()
    if value.startswith("W/"):
        value = value[2:].strip()
    if not value:
        raise PolicyError("live policy response had no ETag")
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value
    return f'"{value}"'


class UrllibTransport:
    """HTTP transport that does not follow redirects."""

    def __call__(self, request: HttpRequest) -> HttpResponse:
        opener = urllib.request.build_opener(_NoRedirect())
        req = urllib.request.Request(
            request.url,
            data=request.body if request.method != "GET" else None,
            headers=request.headers,
            method=request.method,
        )
        try:
            with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
                return HttpResponse(response.status, response.read(), _header_map(response.headers))
        except urllib.error.HTTPError as exc:
            body = exc.read()
            return HttpResponse(exc.code, body, _header_map(exc.headers))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise PolicyError(f"refusing HTTP redirect {code}")


class TailscaleClient:
    def __init__(self, transport: Transport, client_id: str, client_secret: str) -> None:
        self._transport = transport
        self._client_id = client_id
        self._client_secret = client_secret
        self._token: str | None = None
        self.secrets = [client_secret]

    def validate(self, policy: bytes) -> HttpResponse:
        return self._send(
            "POST",
            f"{API_ROOT}/tailnet/{TAILNET}/acl/validate",
            {"Content-Type": "application/hujson", "Accept": "application/hujson"},
            policy,
        )

    def get_policy(self) -> LivePolicy:
        response = self._send(
            "GET",
            f"{API_ROOT}/tailnet/{TAILNET}/acl",
            {"Accept": "application/hujson"},
            b"",
        )
        return LivePolicy(body=response.body, etag=quote_etag(_header(response.headers, "ETag")))

    def set_policy(self, policy: bytes, etag: str) -> None:
        self._send(
            "POST",
            f"{API_ROOT}/tailnet/{TAILNET}/acl",
            {
                "Content-Type": "application/hujson",
                "Accept": "application/hujson",
                "If-Match": quote_etag(etag),
            },
            policy,
        )

    def _token_value(self) -> str:
        if self._token is not None:
            return self._token
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
        ).encode("ascii")
        response = self._send(
            "POST",
            f"{API_ROOT}/oauth/token",
            {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            form,
            authenticated=False,
        )
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyError("oauth token response was not JSON") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise PolicyError("oauth token response had no access_token")
        self._token = token
        self.secrets.append(token)
        return token

    def _send(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes,
        *,
        authenticated: bool = True,
    ) -> HttpResponse:
        sent = {
            "User-Agent": USER_AGENT,
            "Accept": headers.get("Accept", "application/json"),
        }
        sent.update(headers)
        if authenticated:
            sent["Authorization"] = f"Bearer {self._token_value()}"
        response = self._transport(HttpRequest(method, url, sent, body))
        if response.status < 200 or response.status >= 300:
            raise PolicyError(self._error_text(response))
        return response

    def _error_text(self, response: HttpResponse) -> str:
        message = "non-JSON error body"
        try:
            payload = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict) and isinstance(payload.get("message"), str):
            message = payload["message"]
        return redact(f"Tailscale API returned HTTP {response.status}: {message}", self.secrets)


def _validation_passed(body: bytes) -> bool:
    """True when the validate call reported nothing wrong.

    Tailscale answers a passing validation with an empty body or an empty JSON
    object. Anything else, a message, a data list, an array, HTML from a proxy,
    is a rejection."""
    text = body.decode("utf-8", errors="replace").strip()
    if not text:
        return True
    try:
        return json.loads(text) == {}
    except ValueError:
        return False


def _require_valid(response: HttpResponse, client: TailscaleClient) -> None:
    if _validation_passed(response.body):
        return
    detail = redact(response.body.decode("utf-8", errors="replace").strip(), client.secrets)
    raise PolicyError(f"validate rejected the policy (HTTP {response.status}): {detail}")


def command_validate(raw: bytes, policy: dict, client: TailscaleClient) -> int:
    _require_tests(policy)
    _require_valid(client.validate(raw), client)
    print("validate: policy tests passed and the API returned an empty result")
    return 0


def command_diff(raw: bytes, client: TailscaleClient) -> int:
    live = client.get_policy().body
    if live == raw:
        print("diff: live policy matches the repo file")
        return 0
    sys.stdout.writelines(
        difflib.unified_diff(
            _lines(raw),
            _lines(live),
            fromfile="repo",
            tofile="live",
        )
    )
    return 1


def command_drift(raw: bytes, client: TailscaleClient) -> int:
    live = client.get_policy()
    if live.body == raw:
        print("drift: live policy matches the repo file")
        return 0
    print("drift: live policy differs from the repo file", file=sys.stderr)
    return 1


def command_apply(raw: bytes, policy: dict, client: TailscaleClient) -> int:
    _require_tests(policy)
    _require_valid(client.validate(raw), client)
    live = client.get_policy()
    client.set_policy(raw, live.etag)
    readback = client.get_policy()
    if readback.body != raw:
        diff = "".join(
            difflib.unified_diff(
                _lines(raw),
                _lines(readback.body),
                fromfile="posted",
                tofile="readback",
            )
        )
        raise PolicyError(f"readback is not byte-identical to the policy file\n{diff}")
    print("apply: policy updated; readback matches the file")
    return 0


def main(argv: list[str] | None = None, transport: Transport | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tailnet-policy")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--file",
        type=Path,
        default=DEFAULT_FILE,
        help="HuJSON policy file (default: policy/tailscale-acl.hujson)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "diff", "apply", "drift"):
        subparsers.add_parser(name, parents=[common])
    args = parser.parse_args(argv)
    try:
        raw, policy = load_policy_file(args.file)
        if args.command in {"validate", "apply"}:
            _require_tests(policy)
        client = _client(transport)
        if args.command == "validate":
            return command_validate(raw, policy, client)
        if args.command == "diff":
            return command_diff(raw, client)
        if args.command == "drift":
            return command_drift(raw, client)
        if args.command == "apply":
            return command_apply(raw, policy, client)
        raise PolicyError(f"unknown command {args.command}")
    except PolicyError as exc:
        print(f"tailnet-policy: {exc}", file=sys.stderr)
        return exc.exit_code


def _client(transport: Transport | None) -> TailscaleClient:
    client_id = os.environ.get("TAILSCALE_OAUTH_CLIENT_ID", "")
    client_secret = os.environ.get("TAILSCALE_OAUTH_CLIENT_SECRET", "")
    missing = [
        name
        for name, value in (
            ("TAILSCALE_OAUTH_CLIENT_ID", client_id),
            ("TAILSCALE_OAUTH_CLIENT_SECRET", client_secret),
        )
        if not value
    ]
    if missing:
        raise PolicyError("missing environment variable: " + ", ".join(missing))
    return TailscaleClient(transport or UrllibTransport(), client_id, client_secret)


def _require_tests(policy: dict) -> None:
    failures = evaluate_tests(policy)
    if failures:
        raise PolicyError("policy tests failed:\n" + "\n".join(failures))


def _lines(body: bytes) -> list[str]:
    text = body.decode("utf-8", errors="replace")
    if text and not text.endswith("\n"):
        text += "\n"
    return text.splitlines(keepends=True)


def _header_map(headers) -> dict[str, str]:  # noqa: ANN001
    return {key: value for key, value in headers.items()}


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _unsupported_policy(policy: dict) -> list[str]:
    extra = set(policy) - _KNOWN_TOP_LEVEL
    if extra:
        return [f"unsupported policy field: {', '.join(sorted(extra))}"]
    failures: list[str] = []
    ssh_rules = policy.get("ssh")
    if ssh_rules is not None and not isinstance(ssh_rules, list):
        failures.append("ssh is not a list")
        ssh_rules = []
    for index, rule in enumerate(ssh_rules or [], start=1):
        if not isinstance(rule, dict):
            failures.append(f"ssh rule {index} is not an object")
            continue
        unknown = set(rule) - _SSH_RULE_KEYS
        if unknown:
            failures.append(f"ssh rule {index} has unsupported fields: {', '.join(sorted(unknown))}")
            continue
        action = rule.get("action")
        if action not in ("accept", "check"):
            failures.append(f"ssh rule {index} has unsupported action {action!r}")
            continue
        period = rule.get("checkPeriod")
        if period is not None and action != "check":
            failures.append(f"ssh rule {index} sets checkPeriod on action {action}")
        elif period is not None and not _check_period(period):
            failures.append(f"ssh rule {index} has unsupported checkPeriod {period!r}")
        sources = rule.get("src") or []
        destinations = rule.get("dst") or []
        if action == "check" and _all_tags(sources) and _all_tags(destinations):
            failures.append(
                f"ssh rule {index} uses check from a tag to a tag; Tailscale rejects that"
            )
    if ssh_rules and not policy.get("sshTests"):
        failures.append("ssh rules have no sshTests block")
    failures.extend(_unsupported_policy_grants(policy))
    return failures


def _check_period(value: object) -> bool:
    if not isinstance(value, str) or len(value) < 2 or value[-1] not in "smhd":
        return False
    return value[:-1].isdigit()


def _all_tags(selectors: list) -> bool:
    return bool(selectors) and all(isinstance(item, str) and item.startswith("tag:") for item in selectors)


def _evaluate_ssh_tests(policy: dict) -> list[str]:
    tests = policy.get("sshTests")
    if tests is None:
        return []
    if not isinstance(tests, list) or not tests:
        return ["sshTests block is empty"]
    failures: list[str] = []
    groups = policy.get("groups") or {}
    for index, test in enumerate(tests, start=1):
        if not isinstance(test, dict):
            failures.append(f"sshTest {index} is not an object")
            continue
        extra = set(test) - _SSH_TEST_KEYS
        if extra:
            failures.append(f"sshTest {index} has unsupported fields: {', '.join(sorted(extra))}")
            continue
        src = test.get("src")
        if not isinstance(src, str) or not src:
            failures.append(f"sshTest {index} has no src")
            continue
        destinations = test.get("dst") or []
        if not isinstance(destinations, list) or not destinations:
            failures.append(f"sshTest {index} has no dst")
            continue
        for kind in ("accept", "check", "deny"):
            users = test.get(kind, [])
            if users is None:
                users = []
            if not isinstance(users, list):
                failures.append(f"sshTest {index} {kind} is not a list")
                continue
            for user in users:
                if not isinstance(user, str) or not user:
                    failures.append(f"sshTest {index} {kind} entry is not a user")
                    continue
                for host in destinations:
                    if not isinstance(host, str) or not host:
                        failures.append(f"sshTest {index} dst entry is not a host")
                        continue
                    got = _ssh_action(policy, src, host, user, groups) or "deny"
                    if got != kind:
                        failures.append(
                            f"sshTest {index}: {src} -> {user}@{host} want {kind}, got {got}"
                        )
    return failures


def _ssh_allowed(policy: dict, src: str, host: str, user: str, groups: dict) -> bool:
    return _ssh_action(policy, src, host, user, groups) is not None


def _ssh_action(policy: dict, src: str, host: str, user: str, groups: dict) -> str | None:
    """The action of the first ssh rule that lets src reach user@host, or None.

    Tailscale judges an sshTest `accept` only against an accept rule and a
    `check` only against a check rule, so the action is part of the answer."""
    for rule in policy.get("ssh") or []:
        if not isinstance(rule, dict):
            continue
        if rule.get("action") not in ("accept", "check"):
            continue
        if not _src_matches(rule.get("src") or [], src, groups):
            continue
        if not _dst_matches(rule.get("dst") or [], host, src):
            continue
        users = rule.get("users") or []
        if user in users:
            return str(rule["action"])
    return None


def _unsupported_policy_grants(policy: dict) -> list[str]:
    failures: list[str] = []
    for index, grant in enumerate(policy.get("grants") or [], start=1):
        if not isinstance(grant, dict):
            failures.append(f"grant {index} is not an object")
            continue
        unknown = set(grant) - _GRANT_KEYS
        if unknown:
            failures.append(f"grant {index} has unsupported fields: {', '.join(sorted(unknown))}")
    for index, rule in enumerate(policy.get("acls") or [], start=1):
        if not isinstance(rule, dict):
            failures.append(f"acl {index} is not an object")
            continue
        unknown = set(rule) - _ACL_KEYS
        if unknown:
            failures.append(f"acl {index} has unsupported fields: {', '.join(sorted(unknown))}")
    hosts = policy.get("hosts") or {}
    if hosts:
        failures.append("hosts entries are not evaluated by this tool")
    return failures


def _access_allowed(policy: dict, src: str, destination: str, proto: str | None) -> bool:
    host, port_text = _split_destination(destination)
    if not port_text.isdigit():
        raise PolicyError(f"destination {destination!r} has a non-numeric port")
    port = int(port_text)
    groups = policy.get("groups") or {}
    for grant in policy.get("grants") or []:
        if _src_matches(grant.get("src") or [], src, groups) and _dst_matches(
            grant.get("dst") or [], host, src
        ):
            if _specs_allow(grant.get("ip") or [], port, proto):
                return True
    for rule in policy.get("acls") or []:
        if rule.get("action") != "accept":
            continue
        if not _src_matches(rule.get("src") or [], src, groups):
            continue
        for dst in rule.get("dst") or []:
            if not isinstance(dst, str):
                continue
            dst_host, dst_spec = _split_destination(dst)
            if _dst_matches([dst_host], host, src) and _specs_allow([dst_spec], port, proto):
                return True
    return False


def _src_matches(selectors: list, src: str, groups: dict) -> bool:
    for item in selectors:
        if not isinstance(item, str):
            continue
        if item == src:
            return True
        if item == "autogroup:member" and _is_user(src):
            return True
        members = groups.get(item)
        if isinstance(members, list) and src in members:
            return True
    return False


def _dst_matches(selectors: list, host: str, src: str) -> bool:
    for item in selectors:
        if not isinstance(item, str):
            continue
        if item == host or item == "*":
            return True
        if item == "autogroup:self" and _is_user(src) and host == src:
            return True
    return False


def _specs_allow(specs: list, port: int, proto: str | None) -> bool:
    return any(isinstance(spec, str) and _spec_allows(spec, port, proto) for spec in specs)


def _spec_allows(spec: str, port: int, proto: str | None) -> bool:
    if spec == "*":
        return True
    if ":" in spec:
        spec_proto, spec_port = spec.split(":", 1)
        if proto is not None and spec_proto != proto:
            return False
    else:
        spec_port = spec
    if spec_port == "*":
        return True
    if "-" in spec_port:
        start, end = spec_port.split("-", 1)
        if start.isdigit() and end.isdigit():
            return int(start) <= port <= int(end)
        return False
    if "," in spec_port:
        return any(part.isdigit() and int(part) == port for part in spec_port.split(","))
    return spec_port.isdigit() and int(spec_port) == port


def _split_destination(destination: str) -> tuple[str, str]:
    host, separator, port = destination.rpartition(":")
    if not separator or not host or not port:
        raise PolicyError(f"destination {destination!r} is not host:port")
    return host, port


def _is_user(src: str) -> bool:
    return "@" in src and not src.startswith("tag:") and not src.startswith("group:")


def _strip_line_comments(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < len(text) and text[index + 1] == "/":
            index += 2
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    out: list[str] = []
    in_string = False
    escape = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            index += 1
            continue
        if char == ",":
            look = index + 1
            while look < len(text) and text[look] in " \t\r\n":
                look += 1
            if look < len(text) and text[look] in "}]":
                index += 1
                continue
        out.append(char)
        index += 1
    return "".join(out)


if __name__ == "__main__":
    sys.exit(main())
