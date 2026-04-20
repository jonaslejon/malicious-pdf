# Contributing to malicious-pdf

Thanks for your interest in improving this project. This document describes how
to report issues, propose changes, and add new test cases.

## Reporting bugs and requesting enhancements

- File non-security issues at https://github.com/jonaslejon/malicious-pdf/issues.
- Search existing issues first to avoid duplicates.
- Include: command run, expected vs. actual output, Python version, OS, and the
  PDF viewer / processor under test if relevant.
- Bug reports and enhancement requests are accepted in **English**.
- Maintainers aim to acknowledge new reports within 14 days.

## Reporting security vulnerabilities

Do **not** open a public issue for security vulnerabilities. Follow the private
disclosure process documented in [`SECURITY.md`](SECURITY.md). The maintainer
aims for an initial response within 14 days.

## Pull requests

1. Fork the repo and branch from `main`.
2. Keep changes focused — one technique or fix per PR.
3. Follow the project conventions described under "Project conventions" below.
4. Update `README.md` (test matrix and file count) and `CHANGELOG.md` when
   user-visible behavior changes.
5. Confirm the smoke test passes locally:
   ```bash
   python3 malicious-pdf.py https://example.com
   ls output/ | wc -l   # should match the documented test count
   ```
6. Open a PR describing **what** changed and **why**, and link any relevant
   CVE, advisory, or research blog post.

## Project conventions

- Pure Python 3, single file (`malicious-pdf.py`). PDFs are constructed as
  raw strings/bytes — do not introduce external PDF libraries.
- Each test case is a `create_malpdfN(filename, host)` function registered in
  the `pdf_generators` dict in `main()`.
- Test numbering has a gap at `27` (removed as a duplicate). **Do not
  renumber existing tests.**
- Sub-tests use string keys in `pdf_generators` (`'33_1'`, `'34_2'`, …) — not
  floats, to avoid precision issues like `33.10 == 33.1`.
- Special cases: `test11` (EICAR) and `test14` (`.svg`) take no host /
  produce a non-PDF extension; `test29` writes in binary mode due to
  embedded font data.
- Credit injection and obfuscation are post-processing steps applied after
  generation — do **not** call them from inside generators.

## Adding a new test case

Each PDF must exercise exactly one unique technique. Before writing code,
verify the technique is not already covered:

- Is the action type already covered? (e.g., `/GoToR` is `test7` — don't
  add another)
- Is the JS API already covered? (e.g., `this.submitForm()` is `test33_1`)
- UNC variants count as separate from HTTPS variants
  (e.g., `test5` = `/URI` with HTTPS, `test34_4` = `/URI` with UNC)
- Different trigger mechanisms (`OpenAction` vs `/AA/PV` vs `/Names`) count
  as different tests
- `test27` was removed because it combined `test3` + `test23` — do **not**
  create multi-technique PDFs

Then:

1. Add `def create_malpdfN(filename, host)` before `main()`.
2. Register it in the `pdf_generators` dict in `main()`.
3. Update the `README.md` test matrix and the documented file count.
4. Bump `EXPECTED_PDF` (or `EXPECTED_SVG`) in
   `.github/workflows/smoke-test.yml` so the CI count assertion stays
   accurate.
5. Add a short entry under `## [Unreleased]` in `CHANGELOG.md`.

## Testing policy

- Every PR that adds or changes a generator must keep the smoke test green
  (CI runs `python3 malicious-pdf.py https://example.com` on every push and
  asserts the expected number of `.pdf` files is produced).
- New generators should be exercised at all supported obfuscation levels
  (`--obfuscate 0` through `--obfuscate 4`) before merging when feasible.
- Manual viewer testing (Acrobat / PDF.js / Chrome PDFium) is encouraged for
  any change that affects an existing validated payload — note results in the
  PR description.

## Code style

- Pure Python 3, no external PDF libraries — PDFs are constructed as raw
  strings/bytes (see `CLAUDE.md`).
- Match the existing style of nearby code; no large reformatting in functional
  PRs.
- Keep generator functions self-contained; do not apply credit or obfuscation
  inside generators (those are post-processing steps).

## License

By submitting a contribution you agree that it will be released under the
project's [BSD 2-Clause License](LICENSE).
