# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A release is a `v*` tag matching the version in `pyproject.toml`; the `publish`
workflow builds the wheel and sdist and attaches them to a
[GitHub Release](https://github.com/26zl/netsec-auditor/releases).

## [Unreleased]

### Changed

- `full` and `scan` always include the OT/ICS ports so the engine's OT safety
  interlock engages, nmap is handed the scope-validated IPs and the scope's
  `max_scan_rate`, and `full` only runs OS detection with the new
  `--os-detection` flag (#14).
- Docker image builds on `python:3.13-slim` (#8).
- CI runs on pull requests and pushes to `main` only, and the third-party
  actions it uses are pinned to commit SHAs.

### Added

- `.editorconfig` and this changelog.

### Security

- `uv.lock`: Pillow 13.0.0, virtualenv 21.15.2, filelock 4.2.5, certifi
  2026.10.23, Brotli 1.2.1 and brotlicffi 1.2.1.0, clearing the open
  Dependabot alerts. These are development and `pdf`-extra dependencies; the
  published wheel keeps the version ranges in `pyproject.toml`.
- Earlier lockfile bumps on `main`: cryptography (#11), soupsieve and
  weasyprint (#12), virtualenv (#13).

## [1.0.8] - 2026-08-02

### Fixed

- `doctor` reports WeasyPrint as unusable when its native libraries are
  missing.

Release notes for 1.0.0 through 1.0.7 are on
[GitHub Releases](https://github.com/26zl/netsec-auditor/releases).

[Unreleased]: https://github.com/26zl/netsec-auditor/compare/v1.0.8...HEAD
[1.0.8]: https://github.com/26zl/netsec-auditor/compare/v1.0.7...v1.0.8
