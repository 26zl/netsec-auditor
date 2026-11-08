# Contributing to netsec-auditor

Thanks for your interest. Bug reports, fixes, and well-scoped features are all
welcome. For anything non-trivial, open an issue first so we can agree on the
approach before you write code.

> **Authorized use only.** netsec-auditor is a security-scanning tool. Only run
> it — including its tests and any manual checks — against systems you own or
> have explicit, written permission to test. Never contribute code, fixtures, or
> examples that target third-party infrastructure without authorization.

## Development setup

Requires **Python 3.11+** and, for the scanning paths, the **`nmap`** binary on
your `PATH`.

```bash
git clone https://github.com/26zl/netsec-auditor.git
cd netsec-auditor
pip install -e ".[dev]"
```

## Tests and linting

The test suite, Ruff and strict mypy all run in CI on Python 3.11 to 3.15 and
must pass.

```bash
pytest                    # test suite
ruff check .              # lint
mypy netsec_auditor       # strict type check
```

`ruff` and its rules are configured in `pyproject.toml`. Please add or update a
test for any behavior change, especially in the scanning, scope, or reporting
paths.

Write tests against the intended behavior, not against what the code currently
does; a test that asserts a defect keeps it alive.

CI also builds the Docker image, audits dependencies with `pip-audit`, and runs
the tests against the exact versions in `uv.lock`, which the Docker image also
installs. The published wheel keeps the version ranges in `pyproject.toml`.
Refresh the lockfile with `uv lock` when you change a dependency.

## Pull requests

- Keep the diff focused: one logical change per PR.
- Make sure `pytest`, `ruff check .` and `mypy netsec_auditor` pass before pushing.
- Use clear commit subjects (e.g. `add DNP3 read-only probe`, not `update`).
  Reference issue numbers when relevant.
- Note any new runtime dependency or required system package in the PR
  description.

## Releases

1. Set the new version in `netsec_auditor/__init__.py` (the only place it lives)
   and the default `NETSEC_AUDITOR_REF` in `scripts/install.sh`, and update the
   pinned example in the README.
2. Merge to `main`, then push a `vX.Y.Z` tag. The `publish` workflow checks that the
   tag matches both, runs the checks, builds the wheel and sdist with `SHA256SUMS`
   and a build-provenance attestation, and creates the GitHub Release with
   generated notes.

## Reporting security issues

Please do not open public issues for vulnerabilities in netsec-auditor itself.
Report them privately to the maintainer via GitHub instead.
