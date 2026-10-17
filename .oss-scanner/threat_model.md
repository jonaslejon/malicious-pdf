# Threat model

## What this project does and where untrusted input enters

`malicious-pdf` generates a fixed set of PDF files (and one SVG) that a penetration tester serves
to a PDF viewer, converter or processing library to see whether it makes an outbound request to a
callback host such as Burp Collaborator or interact.sh. It is one Python 3 program,
`malicious-pdf.py`, run from the command line, with a single dependency, `validators`.

The program does no networking, starts no subprocesses, and deserializes nothing. Every PDF
structure is built from literal strings in the source, so the whole input surface is the command
line:

- `host`: the callback URL or IP address the generated files should contact. It is checked by
  `validate_url_or_ip_validators()`, normalized by `ensure_scheme()`, and then interpolated into
  the generated files, including into PDF string and URI objects and into JavaScript.
- `--output-dir`: a path, created with `Path.mkdir(parents=True, exist_ok=True)`. The file names
  within it are fixed (`testN.pdf`) and never derived from input.
- `--obfuscate` (integer 0 to 4) and `--no-credit`: these select post-processing passes.

The operator running the command is trusted. The case worth reading for is a wrapper or service
that passes an untrusted `host` through to this program.

## Components that matter most / least

- Matters most: `validate_url_or_ip_validators()` and `ensure_scheme()`, and the interpolation of
  `host` into generated output. A `host` that escapes the PDF string, URI or JavaScript context it
  is placed in would give a caller control over output structure rather than just the callback
  address.
- Also in scope: the post-processing passes, `_inject_credit()` and `obfuscate_pdf()`. Both walk
  `output_dir.iterdir()` and rewrite every file they find there, and both parse the bytes they
  read back.
- Matters least: the individual `create_malpdfN()` generator functions. They make up most of the
  file's length but are nearly all literal text, and differ only in the payload each emits.
- Out of scope: `output/`, `.github/`, and the documentation.

## How to exercise it

The image has a virtualenv on `PATH` with the dependency installed. Generation is offline:

    python3 malicious-pdf.py https://example.com --output-dir /tmp/out
    python3 malicious-pdf.py https://example.com --output-dir /tmp/out --obfuscate 4

This is what CI does (`.github/workflows/smoke-test.yml`): it generates everything on Python 3.10,
3.11 and 3.12 at obfuscation levels 0 and 4, then asserts the output file count and that every PDF
starts with `%PDF-`. There is no unit test suite.

## How you rate severity

Rate a finding by what it lets a caller who controls only the command line do to the machine
running the generator:

- Critical / High: arbitrary code execution, or a write outside `--output-dir` (path traversal, or
  a symlink that the post-processing passes follow), reached from the `host` argument or from a
  file already present in the output directory.
- Medium: a `host` value that breaks out of the PDF string, URI or JavaScript context it is
  interpolated into, giving the caller control over the structure of the generated file.
- Low: an unhandled exception or crash on an unusual but well-formed argument.
- Not a finding: resource consumption. The program writes a bounded set of small files and exits.

## Anything to leave alone

- The content of the generated files is the product, not a defect. Every file is meant to be
  hostile to the viewer that opens it: that is the tool's entire purpose. A report that the
  program emits PDFs containing JavaScript, external entity references, UNC paths or an EICAR test
  string is not a vulnerability in this project. `test11` writes the EICAR antivirus test string
  on purpose, and may trip antivirus software during the build.
- The `eval(...)` text in the source is JavaScript being written into a PDF. Python's own `eval`
  is never called, and no input reaches any of those strings as code.
- The CVE numbers in the source and README identify the viewer bug that each generated file
  probes. They are references to third-party vulnerabilities, not vulnerabilities in this project,
  and are not in scope.
- `KNOWN_SCHEMES` deliberately accepts schemes such as `file:`, `smb:`, `javascript:` and `data:`.
  Accepting them is the feature; it is not a validation gap.
