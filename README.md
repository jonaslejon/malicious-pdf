![malicious-pdf.png](https://triop.se/wp-content/uploads/2021/08/malicious-pdf-e1629197726260.png)

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9599/badge)](https://www.bestpractices.dev/projects/9599)

# Malicious PDF Generator ☠️

Generate 54 different malicious PDF files with phone-home functionality. Can be used with [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Interact.sh](https://github.com/projectdiscovery/interactsh) 

Used for penetration testing and/or red-teaming etc. I created this tool because I needed a tool to generate a bunch of PDF files with various links. Educational and professional purposes only.

## Usage

```
pip install -r requirements.txt
python3 malicious-pdf.py burp-collaborator-url
```

Output will be written to the `output/` directory as: test1.pdf, test2.pdf, test3.pdf etc.

### Options

```
--output-dir DIR    Directory to save generated PDF files (default: output/)
--no-credit         Do not embed credit/attribution metadata in generated PDFs
--obfuscate LEVEL   Obfuscation level (0-3):
                      0 = None (default)
                      1 = PDF name hex encoding + string octal/hex encoding
                      2 = Level 1 + JS bracket notation + javascript: URI case/whitespace obfuscation
                      3 = Level 2 + FlateDecode stream compression
```

Example with obfuscation:
```
python3 malicious-pdf.py https://your-interact-sh-url --obfuscate 2
```

## Purpose
- Test web pages/services accepting PDF files
- Test security products
- Test PDF readers
- Test PDF converters

## Credits
- [Insecure features in PDFs](https://web-in-security.blogspot.com/2021/01/insecure-features-in-pdfs.html)
- [Burp Suite UploadScanner](https://github.com/modzero/mod0BurpUploadScanner/)
- [Bad-Pdf](https://github.com/deepzec/Bad-Pdf)
- [A Curious Exploration of Malicious PDF Documents](https://www.scitepress.org/Papers/2020/89923/89923.pdf)
- ["Portable Document Flaws 101" talk at Black Hat USA 2020](https://github.com/RUB-NDS/PDF101)
- [Adobe Reader - PDF callback via XSLT stylesheet in XFA](https://insert-script.blogspot.com/2019/01/adobe-reader-pdf-callback-via-xslt.html)
- [Foxit PDF Reader PoC, DoHyun Lee](https://twitter.com/l33d0hyun/status/1448342241647366152)
- [Eicar test file by Stas Yakobov](https://github.com/fire1ce/eicar-standard-antivirus-test-files)
- [Multiple PDF Vulnerabilities - FormCalc & XXE](https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html)
- [PDF - Mess with the web - FormCalc header injection](https://insert-script.blogspot.com/2015/05/pdf-mess-with-web.html)
- [Adobe Reader PDF - Client Side Request Injection](https://insert-script.blogspot.com/2018/05/adobe-reader-pdf-client-side-request.html)
- [ImageMagick - Shell injection via PDF password](https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html)
- [Portable Data Exfiltration - PortSwigger Research](https://portswigger.net/research/portable-data-exfiltration)
- [CVE-2024-4367 - Arbitrary JS execution in PDF.js](https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)
- [PDF File Formats Security - Philippe Lagadec](https://www.decalage.info/hugo/file_formats_security/pdf/)

## In Media

- [Brisk Infosec](https://www.briskinfosec.com/tooloftheday/toolofthedaydetail/Malicious-PDF)
- [Daily REDTeam](https://www.linkedin.com/posts/daily-red-team_github-jonaslejonmalicious-pdf-generate-activity-7096476604016582656-d9xM/)
- [Malicious PDF File | Red Team | Penetration Testing](https://www.youtube.com/watch?v=hf3p_t8CPWs)
- [John Hammond - Can a PDF File be Malware?](https://www.youtube.com/watch?v=TP4n8fBl6DA)
- [Black Hat Ethical Hacking](https://www.blackhatethicalhacking.com/tools/malicious-pdf/)
- [0x1 Pentesting Collection](https://0x1.gitlab.io/pentesting/malicious-pdf/)
- [Security Toolkit / WADComs](https://securitytoolkit.github.io/wadcoms/malicious-pdf/)
- [unsafe.sh](https://unsafe.sh/go-111577.html)
- [Cristi Zot on LinkedIn](https://www.linkedin.com/posts/cristivlad_github-jonaslejonmalicious-pdf-generate-activity-7026575045871239169-RKFK)
- [Siva R. on LinkedIn](https://al.linkedin.com/posts/siva-rajendran_github-jonaslejonmalicious-pdf-generate-activity-7026634093891059712-PDcl)

## Test Results (April 2026)

Tested all 47 payloads against latest versions:

### Adobe Acrobat DC v26.001.21367 (macOS)

| Test | Technique | Callback? |
|------|-----------|-----------|
| test31 | `/S /Thread` action | **YES** - HTTP callback |
| All others | Various | Blocked |

Only the **Thread action** (test31) produced a callback on the latest Adobe Acrobat. Classic vectors (GoToE, URI, Launch, JavaScript, SubmitForm, FormCalc, etc.) are all blocked.

### PDF.js v5.6.205 (latest, Chrome)

| Result | Count |
|--------|-------|
| Rendered (no callback) | 45 |
| Parse error | 2 (test10, test14.svg) |
| **Callbacks** | **0** |

PDF.js v5.6.205 blocks all callback vectors. The CVE-2024-4367 FontMatrix injection (test29) is patched since v4.2.67.

### Obfuscation Levels vs Adobe Acrobat DC v26.001.21367 — test31 (Thread action)

| Level | Techniques Applied | Callback? |
|-------|--------------------|-----------|
| 0 | None | **YES** |
| 1 | PDF name hex encoding + string octal/hex | **YES** |
| 2 | + JS bracket notation + javascript: URI case variation | **YES** |
| 3 | + FlateDecode stream compression | **YES** |

### Obfuscation Levels vs PDF.js v4.1.392 (vulnerable) — test29 (CVE-2024-4367)

| Level | Techniques Applied | Callback? |
|-------|--------------------|-----------|
| 0 | None | **YES** |
| 1 | PDF name hex encoding + string octal/hex | **YES** |
| 2 | + JS bracket notation + javascript: URI case variation | **YES** |
| 3 | + FlateDecode stream compression | **YES** |

All obfuscation levels produce callbacks on both viewers. The obfuscation only changes the PDF structural layer (name tokens, string encoding, stream compression) without affecting the actual exploit payloads.

## Complete Test Matrix

<details>
<summary>Click to expand all 54 test cases</summary>

| Test File | Function | CVE/Reference | Attack Vector | Method | Impact |
|-----------|----------|---------------|---------------|---------|---------|
| test1.pdf | `create_malpdf()` | CVE-2018-4993 | External file access | `/GoToE` action with UNC path | Network callback via file system |
| test1_1.pdf | `create_malpdf()` | CVE-2018-4993 | External file access | `/GoToE` action with HTTPS URL | Network callback via HTTPS |
| test2.pdf | `create_malpdf2()` | XFA form submission | Form data exfiltration | XDP form with submit event | Automatic form submission |
| test3.pdf | `create_malpdf3()` | JavaScript injection | Code execution | `/OpenAction` with `app.openDoc()` | External document loading |
| test4.pdf | `create_malpdf4()` | CVE-2019-7089 | XSLT injection | XFA with external XSLT stylesheet | UNC path callback |
| test5.pdf | `create_malpdf5()` | PDF101 research | URI action | `/URI` action type | DNS prefetching/HTTP request |
| test6.pdf | `create_malpdf6()` | PDF101 research | Launch action | `/Launch` with external URL | External resource execution |
| test7.pdf | `create_malpdf7()` | PDF101 research | Remote PDF | `/GoToR` action | Remote PDF loading |
| test8.pdf | `create_malpdf8()` | PDF101 research | Form submission | `/SubmitForm` with HTML flags | Form data submission |
| test9.pdf | `create_malpdf9()` | PDF101 research | Data import | `/ImportData` action | External data import |
| test10.pdf | `create_malpdf10()` | CVE-2017-10951 | JavaScript execution | Foxit `this.getURL()` callback | Network callback via Foxit Reader |
| test11.pdf | `create_malpdf11()` | EICAR test | AV detection | Embedded EICAR string | Anti-virus testing |
| test12.pdf | `create_malpdf12()` | CVE-2014-8453 | FormCalc data exfiltration | XFA FormCalc `Post()` function | Same-origin data exfiltration with cookies |
| test13.pdf | `create_malpdf13()` | Request injection | CRLF header injection | XFA submit `textEncoding` CRLF | HTTP header manipulation |
| test14.svg | `create_malpdf14()` | ImageMagick shell injection | Shell injection via SVG/MSL | SVG-MSL polyglot `authenticate` attribute | Remote code execution via ImageMagick |
| test15.pdf | `create_malpdf15()` | PDF specification | FormCalc header injection | XFA FormCalc `Post()` with custom headers | Arbitrary HTTP header injection |
| test16.pdf | `create_malpdf16()` | PDF specification | JavaScript via GotoE | `/GoToE` with `javascript:` URI | Browser XSS when PDF embedded via `<embed>`/`<object>` |
| test17.pdf | `create_malpdf17()` | CVE-2014-8452 | XXE injection | `XMLData.parse()` external entity | XML external entity resolution |
| test18.pdf | `create_malpdf18()` | PortSwigger research | Annotation URI injection | Unescaped parens inject JS action via duplicate `/A` key | XSS via PDF-Lib/jsPDF output |
| test19.pdf | `create_malpdf19()` | PortSwigger research | PV auto-execution | `/AA /PV` Screen annotation fires JS on page visible | Automatic code execution (Acrobat) |
| test20.pdf | `create_malpdf20()` | PortSwigger research | PC close trigger | `/AA /PC` annotation fires JS on page close | Code execution on close (Acrobat) |
| test21.pdf | `create_malpdf21()` | PortSwigger research | SubmitForm SubmitPDF | `/SubmitForm` with Flags 256 sends entire PDF | Full PDF content exfiltration |
| test22.pdf | `create_malpdf22()` | PortSwigger research | JS submitForm() | `this.submitForm()` with `cSubmitAs: "PDF"` | PDF content submission (Acrobat) |
| test23.pdf | `create_malpdf23()` | PortSwigger research | Widget button injection | Invisible `/Btn` widget covering page, JS on click | Code execution (Chrome/PDFium) |
| test24.pdf | `create_malpdf24()` | PortSwigger research | Text field SSRF | Widget `/Tx` field with `submitForm()` POST | Blind SSRF via form data |
| test25.pdf | `create_malpdf25()` | PortSwigger research | Content extraction | `getPageNthWord()` reads all text and exfiltrates | Rendered text exfiltration |
| test26.pdf | `create_malpdf26()` | PortSwigger research | Mouseover trigger | `/AA /E` annotation fires JS on mouse enter | Code execution on hover (PDFium) |
| ~~test27~~ | — | — | Removed | Duplicate of test3 (Acrobat OpenAction JS) + test23 (Chrome Widget Btn) | — |
| test28.pdf | `create_malpdf28()` | PortSwigger research | URL hijacking | Unescaped parens inject new `/URI` action | Click redirection via PDF-Lib/jsPDF |
| test29.pdf | `create_malpdf29()` | CVE-2024-4367 | FontMatrix injection | Type1 font `FontMatrix` string breaks out of `c.transform()` | Arbitrary JS execution in PDF.js (Firefox < 126) |
| test30.pdf | `create_malpdf30()` | PDF101 research | External XObject stream | Image XObject fetches data from remote URL via `/FS /URL` | Silent callback via page rendering (no actions/JS) |
| test31.pdf | `create_malpdf31()` | PDF101 research | Thread action | `/S /Thread` with remote FileSpec | Network callback via thread reference |
| test32.pdf | `create_malpdf32()` | PDF101 research | Launch with print | `/Launch` with `/Win << /O /print >>` forces remote fetch | Network callback via print operation |
| test33_1.pdf | `create_malpdf33_1()` | PDF101 research | JS: `this.submitForm()` | Acrobat JS form submission callback | Acrobat Reader |
| test33_2.pdf | `create_malpdf33_2()` | PDF101 research | JS: `this.getURL()` | Acrobat JS URL fetch | Acrobat Reader |
| test33_3.pdf | `create_malpdf33_3()` | PDF101 research | JS: `app.launchURL()` | Acrobat JS launch URL | Acrobat Reader |
| test33_4.pdf | `create_malpdf33_4()` | PDF101 research | JS: `app.media.getURLData()` | Acrobat JS media fetch | Acrobat Reader |
| test33_5.pdf | `create_malpdf33_5()` | PDF101 research | JS: `SOAP.connect()` | Acrobat JS SOAP connection | Acrobat Reader |
| test33_6.pdf | `create_malpdf33_6()` | PDF101 research | JS: `SOAP.request()` | Acrobat JS SOAP request | Acrobat Reader |
| test33_7.pdf | `create_malpdf33_7()` | PDF101 research | JS: `this.importDataObject()` | Acrobat JS data import | Acrobat Reader |
| test33_8.pdf | `create_malpdf33_8()` | PDF101 research | JS: `app.openDoc()` | Acrobat JS open document | Acrobat Reader |
| test33_9.pdf | `create_malpdf33_9()` | PDF101 research | JS: `fetch()` | Web API callback (PDF.js/browser) | Firefox/PDF.js |
| test33_10.pdf | `create_malpdf33_10()` | PDF101 research | JS: `XMLHttpRequest` | Web API callback (PDF.js/browser) | Firefox/PDF.js |
| test33_11.pdf | `create_malpdf33_11()` | PDF101 research | JS: `new Image()` | Web API image callback (PDF.js/browser) | Firefox/PDF.js |
| test33_12.pdf | `create_malpdf33_12()` | PDF101 research | JS: `WebSocket` | Web API WebSocket callback (PDF.js/browser) | Firefox/PDF.js |
| test34_1.pdf | `create_malpdf34_1()` | PDF101 research | UNC: XObject stream | Image XObject with UNC path | NTLM theft via page rendering |
| test34_2.pdf | `create_malpdf34_2()` | PDF101 research | UNC: GoToR | `/GoToR` action with UNC FileSpec | NTLM theft via remote PDF |
| test34_3.pdf | `create_malpdf34_3()` | PDF101 research | UNC: Thread | `/Thread` action with UNC FileSpec | NTLM theft via thread reference |
| test34_4.pdf | `create_malpdf34_4()` | PDF101 research | UNC: URI | `/URI` action with UNC path | NTLM theft via URI action |
| test34_5.pdf | `create_malpdf34_5()` | PDF101 research | UNC: JS submitForm | `this.submitForm()` with UNC path | NTLM theft via JS form submission |
| test34_6.pdf | `create_malpdf34_6()` | PDF101 research | UNC: JS getURL | `this.getURL()` with UNC path | NTLM theft via JS URL fetch |
| test34_7.pdf | `create_malpdf34_7()` | PDF101 research | UNC: JS launchURL | `app.launchURL()` with UNC path | NTLM theft via JS launch |
| test34_8.pdf | `create_malpdf34_8()` | PDF101 research | UNC: JS SOAP | `SOAP.connect()` with UNC path | NTLM theft via JS SOAP |
| test34_9.pdf | `create_malpdf34_9()` | PDF101 research | UNC: JS openDoc | `app.openDoc()` with UNC path | NTLM theft via JS open document |
| test35.pdf | `create_malpdf35()` | PDF101 research | Names dictionary | `/Names /JavaScript` catalog-level auto-execute trigger | Alternative JS execution trigger |

</details>

## Todo: Obfuscation methods not yet implemented
- **Empty-password PDF encryption** — Encrypt all strings/streams with empty user password. Document opens without prompting but static analysis tools cannot read content. Biggest gap in current obfuscation. Ref: [Didier Stevens](https://blog.didierstevens.com/category/pdf/), [How secure is PDF encryption?](https://www.decalage.info/hugo/file_formats_security/pdf/)
- **Object streams (ObjStm)** — Hide PDF objects inside compressed stream containers. Simple parsers (including PDFiD without `-O` flag) miss objects entirely. Ref: [PDF spec ISO 32000 §7.5.7](https://www.iso.org/standard/63534.html)
- **getAnnots() code storage** — Split JavaScript payload across annotation metadata fields (subject, author). Retrieve at runtime via `app.doc.getAnnots()[n].subject` and eval. Ref: [Julia Wolf - PDF Obfuscation using getAnnots()](https://blog.didierstevens.com/2010/01/14/)
- **Info dict data extraction** — Store encoded payload in `/Info` trailer fields (`/Title`, `/Author`). Retrieve at runtime via `info.Title` in JS. Ref: [corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **AcroForm field value extraction** — Store payload fragments in form field `/V` values. Retrieve via `getField("name").value` in JS. Ref: [corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **Names tree split execution** — Split JavaScript across multiple `/Names` entries executed sequentially. Ref: [corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **Incremental updates after %%EOF** — Append new objects/actions after the original `%%EOF` marker via incremental update. Ref: [PDF101 content masking](https://github.com/RUB-NDS/PDF101), [Didier Stevens](https://blog.didierstevens.com/2010/05/18/more-malformed-pdfs/)
- **JS `unescape()` encoding** — Wrap JS payload in `eval(unescape("%61%6C%65%72%74..."))`. Ref: [corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **Fake file headers** — Prepend JPEG/HTML/other magic bytes before `%PDF-` header (spec allows header within first 1024 bytes). Confuses file-type detection. Ref: [corkami](https://github.com/corkami/docs/blob/master/PDF/PDF.md), [Decalage](https://www.decalage.info/hugo/file_formats_security/pdf/)
- **Anti-emulation checks** — Detect real Adobe Reader via `event.target.zoomType == "FitPage"` or global variable type checks before executing payload. Ref: [corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

## Won't implement
- ~~CVE-2023-26369 - Adobe Acrobat TTF font heap OOB write~~ — Requires binary exploitation (heap spray, ROP chains, shellcode). No public PoC. Cannot produce a simple callback.
- ~~CVE-2021-28550 - Adobe Acrobat Use-After-Free~~ — Requires binary exploitation chain + sandbox escape (CVE-2021-31199/31201). No public PoC. Cannot produce a simple callback.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=jonaslejon/malicious-pdf&type=Date)](https://www.star-history.com/#jonaslejon/malicious-pdf&Date)
