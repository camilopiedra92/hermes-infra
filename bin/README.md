# `bin/`

`python3 bin/verify.py` is the merge gate. It runs every `bin/test_*.py` file,
then the pinned pre-commit hooks, and it refuses a dirty tree. CI runs the
same script.

## Container tests

A test that needs Docker (or another container runtime) declares it:

```python
REQUIRES_CONTAINER_RUNTIME = "docker"
```

The assignment has to be module-level. The file name is not a marker.
`bin/verify.py` reads the assignment.

- When `docker` is on `PATH`, the gate runs that test and prints
  `verify: path local: docker on PATH; running <file>`.
- When it is not, the gate does not skip the test and does not treat that as
  a pass. It computes `git rev-parse HEAD^{tree}` and reads the GitHub Actions
  API, read-only. It lists `GET /repos/{owner}/{repo}/actions/runs` (first with
  `head_sha` of `HEAD` when that SHA is known, then the recent runs) and then
  `GET /actions/runs/{run_id}/jobs`. A run counts only when all of these hold:
  its workflow path is `.github/workflows/ci.yml`, its conclusion is `success`,
  `head_repository.full_name` is this repo, a job named `verify` concluded
  `success`, and the run's head commit tree equals `HEAD^{tree}`. A `--no-ff`
  merge commit of a branch that already contains `main` has the same tree as
  the branch tip, so the PR head's green run counts. The gate prints
  `verify: path CI evidence: tree <tree> run <id> commit <sha> job verify success`.
- Anything else fails, and the message names the tree. That includes no
  `GITHUB_TOKEN` or `GH_TOKEN`, no network, HTTP 403, HTTP 404, any other API
  error, no matching run, a failed or cancelled run, a run from a fork, and a
  run whose `verify` job did not succeed. The token is sent only as an
  Authorization header and is not printed. The Checks API is not used.

`bin/test_g2_check_fresh.py` is the test that declares `docker`.
