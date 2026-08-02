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

The test suite and Ruff are required CI checks. Strict mypy also runs, but is
currently advisory while the existing type backlog is resolved.

```bash
pytest                    # test suite
ruff check .              # lint
mypy netsec_auditor       # strict type check; currently reports known debt
```

`ruff` and its rules are configured in `pyproject.toml`. Please add or update a
test for any behavior change, especially in the scanning, scope, or reporting
paths.

Write tests against the intended behavior, not against what the code currently
does — several defects have survived because a test asserted them.

CI also builds the Docker image, audits dependencies with `pip-audit`, and
verifies `uv.lock` still resolves. The lockfile is for reproducible CI and local
development only; the published wheel keeps the version ranges in
`pyproject.toml`. Refresh it with `uv lock` when you change a dependency.

## Pull requests

- Keep the diff focused: one logical change per PR.
- Make sure `pytest` and `ruff check .` pass before pushing.
- Use clear commit subjects (e.g. `add DNP3 read-only probe`, not `update`).
  Reference issue numbers when relevant.
- Note any new runtime dependency or required system package in the PR
  description.

## Reporting security issues

Please do not open public issues for vulnerabilities in netsec-auditor itself.
Report them privately to the maintainer via GitHub instead.
