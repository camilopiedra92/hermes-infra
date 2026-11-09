# Contributing

Branch from `main`, open a pull request, and use Conventional Commits in English.

## Gate

`python3 bin/verify.py` is the merge gate. It runs `bin/test_*.py` and the pinned
pre-commit hooks on a clean tree. CI runs the same script.

A test that needs a container runtime declares it with a module-level
`REQUIRES_CONTAINER_RUNTIME = "docker"`. The file name is not enough.

- Docker on `PATH`: the gate runs the test and prints `verify: path local`.
- Docker absent: the gate does not skip the test. It proves the same tree
  already passed CI by reading Actions workflow runs and their jobs.
  `git rev-parse HEAD^{tree}` must equal the run's head commit tree, the
  workflow must be `.github/workflows/ci.yml`, the run must be from this
  repo and concluded `success`, and the `verify` job must have succeeded.
  A `--no-ff` merge of a branch that already contains `main` has that same
  tree. The gate prints `verify: path CI evidence` with the tree, the Actions
  run id, and the commit.
- No `GITHUB_TOKEN` or `GH_TOKEN`, no network, HTTP 403 or 404, any other API
  error, a failed or cancelled run, a fork, or no matching run fails the gate.
  The token is an Authorization header only and is not printed.

Details are in [bin/README.md](bin/README.md).
