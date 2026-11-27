# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-11-27

### Added
- OSS Scanner build environment (`.oss-scanner/Dockerfile`) and threat
  model (`.oss-scanner/threat_model.md`).
- Dependabot now also tracks GitHub Actions versions, not only pip, and waits
  7 days before proposing a new release (security updates are not delayed).

### Security
- Workflow actions are pinned to full commit SHAs instead of mutable tags, so
  a repointed tag cannot change the code CI runs. Dependabot keeps the pins
  current.

### Changed
- Smoke test runs on Python 3.10 through 3.14 (adds 3.13 and 3.14) and uses
  `actions/checkout@v7` and `actions/setup-python@v7`, which drops the
  Node.js 20 deprecation warning.
- README lists CVE-2025-54988 next to CVE-2025-66516 for test42. The later
  CVE supersedes the earlier one; the payload is unchanged.
- `CONTRIBUTING.md` inlines the project conventions and names the license
  correctly.

### Fixed
- Semgrep workflow ran on the retired `ubuntu-20.04` runner, so every
  scheduled scan sat queued for 24 hours and was cancelled. It now runs on
  `ubuntu-latest` with the `semgrep/semgrep` image and `actions/checkout@v7`,
  and skips Dependabot PRs, which cannot read the Semgrep token.
- Star History chart in the README renders again (sealed-token embed).

### Removed
- Advanced CodeQL workflow, which failed on every run because CodeQL default
  setup is enabled and already covers the same languages.

## [1.0.1] - 2026-04-20

### Added
- `__version__` constant in `malicious-pdf.py` and a `--version` CLI flag
  so users running from a clone can identify the release they have.
- `CONTRIBUTING.md` describing the contribution workflow and testing policy.
- `CHANGELOG.md` (this file).
- CI smoke-test workflow that runs the generator and asserts the expected
  number of PDF files is produced on every push and pull request.

### Changed
- `CLAUDE.md` documents the release process and the smoke-test count that
  must be bumped when generators are added or removed.

## [1.0.0] - 2026-04-20

First tagged release. Captures the state of the project at the time the
changelog was introduced.

### Added
- 67 PDF generators covering phone-home callbacks, SSRF, XSS, XXE, NTLM
  credential theft, and data exfiltration techniques.
- `--obfuscate` flag with levels 0–4, including base64 JS payload staging
  (level 4) inspired by the April 2026 Adobe Reader 0-day analysis.
- `--output-dir` and `--no-credit` flags.
- Visible credit footer rendered on each generated PDF page.
- Filename + short payload description printed during generation.
- Test cases from 2025–2026 CVEs targeting server-side processors
  (Apache Tika, LibreOffice, Foxit, Apryse).
- CodeQL and Semgrep static-analysis workflows.
- Dependabot configuration.
- `SECURITY.md` with PGP-encrypted private vulnerability reporting.

[Unreleased]: https://github.com/jonaslejon/malicious-pdf/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/jonaslejon/malicious-pdf/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/jonaslejon/malicious-pdf/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/jonaslejon/malicious-pdf/releases/tag/v1.0.0
