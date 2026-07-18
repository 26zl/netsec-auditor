# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or pull
request for anything security-sensitive.

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/26zl/netsec-auditor/security/advisories/new)
(repository **Security → Advisories → Report a vulnerability**).

You can expect an acknowledgement within **5 business days**. Once a report is
confirmed, a fix and coordinated release will be prepared, and you will be
credited in the published advisory unless you ask to remain anonymous.

## What is in scope

NetSec Auditor is an offensive-capable auditing tool. Reports that the tool *can
be used* to scan systems are **not** vulnerabilities — that is its purpose, and
every scan is gated by an explicit authorization scope.

Security-relevant reports we *do* want:

- The tool breaking its own **read-only / passive** guarantee (e.g. emitting a
  mutating HTTP method, or any exploit/DoS/cracking behaviour).
- **Scope escape** — scanning a target outside the authorized scope, e.g. via
  redirects, DNS answers, or port handling (SSRF-style bypasses).
- **Secret disclosure** — captured credentials, cookies, tokens, or query values
  leaking into logs or generated reports.
- **Local safety** — path traversal, symlink following, or unsafe permissions
  when writing reports, caches, or scope files (especially under sudo).
- **Supply-chain** issues in the packaged distribution (PyPI wheel, Docker image).

## Responsible use

Only run NetSec Auditor against systems you own or have explicit, written
permission to test. Unauthorized scanning may be illegal. Misuse by a third
party is not a vulnerability in this project.
