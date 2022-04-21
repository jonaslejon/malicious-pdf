![malicious-pdf.png](https://triop.se/wp-content/uploads/2021/08/malicious-pdf-e1629197726260.png)

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)

# Malicious PDF Generator ☠️

Generate ten different malicious pdf files with phone-home functionality. Can be used with [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Interact.sh](https://github.com/projectdiscovery/interactsh) 

Used for penetration testing and/or red-teaming etc. I created this tool because i needed a third party tool to generate a bunch of PDF files with various links.

## Usage

`python3 malicious-pdf.py burp-collaborator-url`

Output will be written as: test1.pdf, test2.pdf, test3.pdf etc in the current directory.

Do not use the https:// etc prefix on the url argument.

## Purpose
- Test web pages/services accepting PDF-files
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
