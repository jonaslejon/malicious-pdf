![malicious-pdf.png](https://triop.se/wp-content/uploads/2021/08/malicious-pdf-e1629197726260.png)

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9599/badge)](https://www.bestpractices.dev/projects/9599)

# Malicious PDF Generator ☠️

Generate ten different malicious PDF files with phone-home functionality. Can be used with [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) or [Interact.sh](https://github.com/projectdiscovery/interactsh) 

Used for penetration testing and/or red-teaming etc. I created this tool because I needed a tool to generate a bunch of PDF files with various links. Educational and professional purposes only.

## Usage

```
pip install -r requirements.txt
python3 malicious-pdf.py burp-collaborator-url
```

Output will be written as: test1.pdf, test2.pdf, test3.pdf etc in the current directory.

## Complete Test Matrix

| Test File | Function | CVE/Reference | Attack Vector | Method | Impact |
|-----------|----------|---------------|---------------|---------|---------|
| test1.pdf | `create_malpdf()` | CVE-2018-4993 | External file access | `/GoToE` action with UNC path | Network callback via file system |
| test1bis.pdf | `create_malpdf()` | CVE-2018-4993 | External file access | `/GoToE` action with HTTPS URL | Network callback via HTTPS |
| test2.pdf | `create_malpdf2()` | XFA form submission | Form data exfiltration | XDP form with submit event | Automatic form submission |
| test3.pdf | `create_malpdf3()` | JavaScript injection | Code execution | `/OpenAction` with `app.openDoc()` | External document loading |
| test4.pdf | `create_malpdf4()` | CVE-2019-7089 | XSLT injection | XFA with external XSLT stylesheet | UNC path callback |
| test5.pdf | `create_malpdf5()` | PDF101 research | URI action | `/URI` action type | DNS prefetching/HTTP request |
| test6.pdf | `create_malpdf6()` | PDF101 research | Launch action | `/Launch` with external URL | External resource execution |
| test7.pdf | `create_malpdf7()` | PDF101 research | Remote PDF | `/GoToR` action | Remote PDF loading |
| test8.pdf | `create_malpdf8()` | PDF101 research | Form submission | `/SubmitForm` with HTML flags | Form data submission |
| test9.pdf | `create_malpdf9()` | PDF101 research | Data import | `/ImportData` action | External data import |
| test10.pdf | `create_malpdf10()` | CVE-2017-10951 | JavaScript execution | JavaScript to launch Calculator | Application execution |
| test11.pdf | `create_malpdf11()` | EICAR test | AV detection | Embedded EICAR string | Anti-virus testing |

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

## In Media

- [Brisk Infosec](https://www.briskinfosec.com/tooloftheday/toolofthedaydetail/Malicious-PDF)
- [Daily REDTeam](https://www.linkedin.com/posts/daily-red-team_github-jonaslejonmalicious-pdf-generate-activity-7096476604016582656-d9xM/)
- [Malicious PDF File | Red Team | Penetration Testing](https://www.youtube.com/watch?v=hf3p_t8CPWs)
- [John Hammond - Can a PDF File be Malware?](https://www.youtube.com/watch?v=TP4n8fBl6DA)

## Todo
- Adobe Acrobat PDF Reader RCE when processing TTF fonts, CVE-2023-26369
- Adobe Acrobat and Reader Use-After-Free Vulnerability, CVE-2021-28550

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=jonaslejon/malicious-pdf&type=Date)](https://www.star-history.com/#jonaslejon/malicious-pdf&Date)
