# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CONTRIBUTING.md` describing the contribution workflow and testing policy.
- `CHANGELOG.md` (this file).
- CI smoke-test workflow that runs the generator and asserts the expected
  number of PDF files is produced on every push and pull request.

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

[Unreleased]: https://github.com/jonaslejon/malicious-pdf/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jonaslejon/malicious-pdf/releases/tag/v1.0.0
