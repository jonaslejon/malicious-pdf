![malicious-pdf.png](https://triop.se/wp-content/uploads/2021/08/malicious-pdf-e1629197726260.png)

[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9599/badge)](https://www.bestpractices.dev/projects/9599)

语言: [English](README.md) | 简体中文

# 恶意 PDF 生成器 ☠️

生成 70 个恶意 PDF/SVG 测试文件，用于测试 PDF 查看器、转换器和 Web 应用中的回连、SSRF、XSS、XXE、NTLM 凭据窃取和数据外传等行为。可配合 [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) 或 [Interact.sh](https://github.com/projectdiscovery/interactsh) 使用。

本工具适用于渗透测试、漏洞赏金、安全研究和红队测试等场景。作者创建它的原因是需要一个可以生成多种 PDF 外链测试样本的工具。仅限教育和专业用途。

## 使用方法

```bash
pip install -r requirements.txt
python3 malicious-pdf.py burp-collaborator-url
```

输出文件会写入 `output/` 目录，例如 `test1.pdf`、`test2.pdf`、`test3.pdf` 等。

### 选项

```text
--output-dir DIR    保存生成文件的目录，默认是 output/
--no-credit         不在生成的 PDF 中嵌入署名/来源元数据
--obfuscate LEVEL   混淆等级，取值 0-4:
                      0 = 不混淆，默认值
                      1 = PDF name 十六进制编码 + 字符串八进制/十六进制编码
                      2 = 等级 1 + JS 方括号表示法 + javascript: URI 大小写/空白混淆
                      3 = 等级 2 + FlateDecode stream 压缩
                      4 = 等级 3 + JS payload staging，使用 base64 decoder wrapper
```

启用混淆的示例：

```bash
python3 malicious-pdf.py https://your-interact-sh-url --obfuscate 2
```

最高混淆等级示例（等级 4 会把 JS payload 包装进 base64 decoder stub，让原始 API 调用不再以明文子串出现）：

```bash
python3 malicious-pdf.py https://your-interact-sh-url --obfuscate 4
```

## 用途

- 测试接受 PDF 文件的网页或服务
- 测试安全产品
- 测试 PDF 阅读器
- 测试 PDF 转换器
- 测试服务端 PDF 处理库，如 PDFBox、iText 等
- 测试 PDF 静态分析工具，staged JS payload（表单字段 `/V`、base64 decoder）可绕过朴素的 `/JS` 正则扫描
- 漏洞赏金测试，适合在文件上传接口、PDF 转图片转换器、文档处理流水线等接受 PDF 输入的场景中发现 SSRF、XXE、盲回连和 NTLM 泄露

## 致谢

- [Insecure features in PDFs](https://web-in-security.blogspot.com/2021/01/insecure-features-in-pdfs.html)
- [Burp Suite UploadScanner](https://github.com/modzero/mod0BurpUploadScanner/)
- [Bad-Pdf](https://github.com/deepzec/Bad-Pdf)
- [A Curious Exploration of Malicious PDF Documents](https://www.scitepress.org/Papers/2020/89923/89923.pdf)
- [Black Hat USA 2020 演讲 "Portable Document Flaws 101"](https://github.com/RUB-NDS/PDF101)
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
- [CVE-2016-2175 - Apache PDFBox XXE](https://nvd.nist.gov/vuln/detail/CVE-2016-2175)
- [CVE-2017-9096 - iText XXE](https://nvd.nist.gov/vuln/detail/CVE-2017-9096)
- [CVE-2020-29075 - Acrobat Reader silent DNS tracking](https://nvd.nist.gov/vuln/detail/CVE-2020-29075)
- [CVE-2022-28244 - Acrobat Reader CSP bypass](https://nvd.nist.gov/vuln/detail/CVE-2022-28244)
- [CVE-2018-5158 - Firefox PDF.js PostScript calculator injection](https://nvd.nist.gov/vuln/detail/CVE-2018-5158)
- [CVE-2018-20065 - PDFium URI action without user gesture](https://nvd.nist.gov/vuln/detail/CVE-2018-20065)
- [ExpMon - Sophisticated Adobe Reader 0-day analysis (April 2026)](https://justhaifei1.blogspot.com/2026/04/expmon-detected-sophisticated-zero-day-adobe-reader.html) — test33_13/14/15 和混淆等级 4 的灵感来源

## 媒体报道

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

## 完整测试矩阵

<details>
<summary>展开全部 70 个测试用例</summary>

| 测试文件 | 函数 | CVE/参考 | 攻击向量 | 方法 | 影响 |
|----------|------|----------|----------|------|------|
| test1.pdf | `create_malpdf()` | CVE-2018-4993 | 外部文件访问 | 带 UNC 路径的 `/GoToE` action | 通过文件系统触发网络回连 |
| test1_1.pdf | `create_malpdf()` | CVE-2018-4993 | 外部文件访问 | 带 HTTPS URL 的 `/GoToE` action | 通过 HTTPS 触发网络回连 |
| test2.pdf | `create_malpdf2()` | XFA form submission | 表单数据外传 | 带 submit event 的 XDP 表单 | 自动提交表单 |
| test3.pdf | `create_malpdf3()` | JavaScript injection | 代码执行 | `/OpenAction` 调用 `app.openDoc()` | 加载外部文档 |
| test4.pdf | `create_malpdf4()` | CVE-2019-7089 | XSLT 注入 | XFA 引用外部 XSLT stylesheet | UNC 路径回连 |
| test5.pdf | `create_malpdf5()` | PDF101 research | URI action | `/URI` action 类型 | DNS prefetch/HTTP 请求 |
| test6.pdf | `create_malpdf6()` | PDF101 research | Launch action | `/Launch` 加载外部 URL | 外部资源执行 |
| test7.pdf | `create_malpdf7()` | PDF101 research | 远程 PDF | `/GoToR` action | 加载远程 PDF |
| test8.pdf | `create_malpdf8()` | PDF101 research | 表单提交 | 带 HTML flags 的 `/SubmitForm` | 表单数据提交 |
| test9.pdf | `create_malpdf9()` | PDF101 research | 数据导入 | `/ImportData` action | 导入外部数据 |
| test10.pdf | `create_malpdf10()` | CVE-2017-10951 | JavaScript 执行 | Foxit `this.getURL()` callback | 通过 Foxit Reader 触发网络回连 |
| test11.pdf | `create_malpdf11()` | EICAR test | 杀毒检测 | 嵌入 EICAR 字符串 | 防病毒检测测试 |
| test12.pdf | `create_malpdf12()` | CVE-2014-8453 | FormCalc 数据外传 | XFA FormCalc `Post()` 函数 | 带 cookie 的同源数据外传 |
| test13.pdf | `create_malpdf13()` | Request injection | CRLF header 注入 | XFA submit `textEncoding` CRLF | HTTP header 操控 |
| test14.svg | `create_malpdf14()` | ImageMagick shell injection | 通过 SVG/MSL 执行 shell 注入 | SVG-MSL polyglot `authenticate` 属性 | 通过 ImageMagick 远程代码执行 |
| test15.pdf | `create_malpdf15()` | PDF specification | FormCalc header 注入 | 带自定义 header 的 XFA FormCalc `Post()` | 任意 HTTP header 注入 |
| test16.pdf | `create_malpdf16()` | PDF specification | 通过 GotoE 执行 JavaScript | 带 `javascript:` URI 的 `/GoToE` | PDF 通过 `<embed>`/`<object>` 嵌入时触发浏览器 XSS |
| test17.pdf | `create_malpdf17()` | CVE-2014-8452 | XXE 注入 | `XMLData.parse()` 外部实体 | XML 外部实体解析 |
| test18.pdf | `create_malpdf18()` | PortSwigger research | 注解 URI 注入 | 未转义括号通过重复 `/A` key 注入 JS action | 通过 PDF-Lib/jsPDF 输出触发 XSS |
| test19.pdf | `create_malpdf19()` | PortSwigger research | PV 自动执行 | `/AA /PV` Screen annotation 在页面可见时触发 JS | 自动代码执行（Acrobat） |
| test20.pdf | `create_malpdf20()` | PortSwigger research | PC close trigger | `/AA /PC` annotation 在页面关闭时触发 JS | 关闭时执行代码（Acrobat） |
| test21.pdf | `create_malpdf21()` | PortSwigger research | SubmitForm SubmitPDF | 带 Flags 256 的 `/SubmitForm` 发送整个 PDF | 完整 PDF 内容外传 |
| test22.pdf | `create_malpdf22()` | PortSwigger research | JS submitForm() | `this.submitForm()` 搭配 `cSubmitAs: "PDF"` | PDF 内容提交（Acrobat） |
| test23.pdf | `create_malpdf23()` | PortSwigger research | Widget button 注入 | 不可见 `/Btn` widget 覆盖页面，点击触发 JS | 代码执行（Chrome/PDFium） |
| test24.pdf | `create_malpdf24()` | PortSwigger research | 文本字段 SSRF | `/Tx` widget 通过 `submitForm()` POST | 通过表单数据触发盲 SSRF |
| test25.pdf | `create_malpdf25()` | PortSwigger research | 内容提取 | `getPageNthWord()` 读取所有文本并外传 | 渲染文本外传 |
| test26.pdf | `create_malpdf26()` | PortSwigger research | 鼠标悬停触发 | `/AA /E` annotation 在 mouse enter 时触发 JS | 悬停触发代码执行（PDFium） |
| ~~test27~~ | — | — | 已移除 | 重复 test3（Acrobat OpenAction JS）和 test23（Chrome Widget Btn） | — |
| test28.pdf | `create_malpdf28()` | PortSwigger research | URL hijacking | 未转义括号注入新的 `/URI` action | 通过 PDF-Lib/jsPDF 点击重定向 |
| test29.pdf | `create_malpdf29()` | CVE-2024-4367 | FontMatrix 注入 | Type1 font `FontMatrix` 字符串逃逸 `c.transform()` | PDF.js 中执行任意 JS（Firefox < 126） |
| test30.pdf | `create_malpdf30()` | PDF101 research | 外部 XObject stream | Image XObject 通过 `/FS /URL` 从远程 URL 获取数据 | 页面渲染时静默回连，无 action/JS |
| test31.pdf | `create_malpdf31()` | PDF101 research | Thread action | `/S /Thread` 搭配远程 FileSpec | 通过 thread reference 触发网络回连 |
| test32.pdf | `create_malpdf32()` | PDF101 research | Launch with print | `/Launch` 搭配 `/Win << /O /print >>` 强制远程 fetch | 通过 print operation 触发网络回连 |
| test33_1.pdf | `create_malpdf33_1()` | PDF101 research | JS: `this.submitForm()` | Acrobat JS 表单提交 callback | Acrobat Reader |
| test33_2.pdf | `create_malpdf33_2()` | PDF101 research | JS: `this.getURL()` | Acrobat JS URL fetch | Acrobat Reader |
| test33_3.pdf | `create_malpdf33_3()` | PDF101 research | JS: `app.launchURL()` | Acrobat JS launch URL | Acrobat Reader |
| test33_4.pdf | `create_malpdf33_4()` | PDF101 research | JS: `app.media.getURLData()` | Acrobat JS media fetch | Acrobat Reader |
| test33_5.pdf | `create_malpdf33_5()` | PDF101 research | JS: `SOAP.connect()` | Acrobat JS SOAP connection | Acrobat Reader |
| test33_6.pdf | `create_malpdf33_6()` | PDF101 research | JS: `SOAP.request()` | Acrobat JS SOAP request | Acrobat Reader |
| test33_7.pdf | `create_malpdf33_7()` | PDF101 research | JS: `this.importDataObject()` | Acrobat JS data import | Acrobat Reader |
| test33_8.pdf | `create_malpdf33_8()` | PDF101 research | JS: `app.openDoc()` | Acrobat JS open document | Acrobat Reader |
| test33_9.pdf | `create_malpdf33_9()` | PDF101 research | JS: `fetch()` | Web API callback（PDF.js/browser） | Firefox/PDF.js |
| test33_10.pdf | `create_malpdf33_10()` | PDF101 research | JS: `XMLHttpRequest` | Web API callback（PDF.js/browser） | Firefox/PDF.js |
| test33_11.pdf | `create_malpdf33_11()` | PDF101 research | JS: `new Image()` | Web API image request callback（PDF.js/browser） | Firefox/PDF.js |
| test33_12.pdf | `create_malpdf33_12()` | PDF101 research | JS: `WebSocket` | Web API WebSocket callback | Firefox/PDF.js |
| test33_13.pdf | `create_malpdf33_13()` | Adobe 0-day blog（2026 年 4 月） | JS: `RSS.addFeed()` | Acrobat JS RSS feed callback | Acrobat Reader |
| test33_14.pdf | `create_malpdf33_14()` | Adobe 0-day blog（2026 年 4 月） | JS: `util.readFileIntoStream()` + `SOAP.request()` | 本地文件读取 + 外传链，try/catch 错误路径也会回连 | Acrobat Reader |
| test33_15.pdf | `create_malpdf33_15()` | Adobe 0-day blog（2026 年 4 月） | 表单字段 staged JS loader | base64 payload 存放在 `/Tx` widget `/V`，通过 `getField()` + `util.stringFromStream` 解码 | Acrobat Reader |
| test34_1.pdf | `create_malpdf34_1()` | PDF101 research | UNC: XObject stream | 带 UNC 路径的 Image XObject | 页面渲染触发 NTLM 窃取 |
| test34_2.pdf | `create_malpdf34_2()` | PDF101 research | UNC: GoToR | 带 UNC FileSpec 的 `/GoToR` action | 通过远程 PDF 触发 NTLM 窃取 |
| test34_3.pdf | `create_malpdf34_3()` | PDF101 research | UNC: Thread | 带 UNC FileSpec 的 `/Thread` action | 通过 thread reference 触发 NTLM 窃取 |
| test34_4.pdf | `create_malpdf34_4()` | PDF101 research | UNC: URI | 带 UNC 路径的 `/URI` action | 通过 URI action 触发 NTLM 窃取 |
| test34_5.pdf | `create_malpdf34_5()` | PDF101 research | UNC: JS submitForm | 带 UNC 路径的 `this.submitForm()` | 通过 JS 表单提交触发 NTLM 窃取 |
| test34_6.pdf | `create_malpdf34_6()` | PDF101 research | UNC: JS getURL | 带 UNC 路径的 `this.getURL()` | 通过 JS URL fetch 触发 NTLM 窃取 |
| test34_7.pdf | `create_malpdf34_7()` | PDF101 research | UNC: JS launchURL | 带 UNC 路径的 `app.launchURL()` | 通过 JS launch 触发 NTLM 窃取 |
| test34_8.pdf | `create_malpdf34_8()` | PDF101 research | UNC: JS SOAP | 带 UNC 路径的 `SOAP.connect()` | 通过 JS SOAP 触发 NTLM 窃取 |
| test34_9.pdf | `create_malpdf34_9()` | PDF101 research | UNC: JS openDoc | 带 UNC 路径的 `app.openDoc()` | 通过 JS open document 触发 NTLM 窃取 |
| test35.pdf | `create_malpdf35()` | PDF101 research | Names dictionary | `/Names /JavaScript` catalog-level auto-execute trigger | 替代 JS 执行触发器 |
| test36.pdf | `create_malpdf36()` | CVE-2016-2175 / CVE-2017-9096 | XMP metadata XXE | `/Metadata` XMP stream 中的 XXE `<!ENTITY>` | 服务端回连（PDFBox、iText） |
| test37.pdf | `create_malpdf37()` | CVE-2016-2175 / CVE-2017-9096 | XFA form data XXE | `/AcroForm /XFA` stream 中的 XXE `<!ENTITY>` | 服务端回连（PDFBox、iText） |
| test38.pdf | `create_malpdf38()` | CVE-2020-29075 | 静默 DNS tracking | Catalog `/AA` 中的 `/WC`、`/WS`、`/DS` 触发器 | 无提示 DNS 回连（Acrobat） |
| test39.pdf | `create_malpdf39()` | CVE-2022-28244 | CSP bypass | 带嵌入 HTML/JS 的 RichMedia annotation | 跨源请求（Acrobat） |
| test40.pdf | `create_malpdf40()` | CVE-2018-5158 | PostScript calculator 注入 | Image XObject 中 `/FunctionType 4` JS 注入 | 在 PDF.js worker 中执行 JS（Firefox） |
| test41.pdf | `create_malpdf41()` | CVE-2018-20065 | 无用户手势 URI | `/OpenAction` 搭配 `/S /URI` 自动导航 | 静默导航（PDFium/Chrome） |
| test42.pdf | `create_malpdf42()` | CVE-2025-66516 | XFA OOB parameter entity XXE | `/AcroForm /XFA` 中 `%xxe;` 参数实体强制 DTD fetch | 服务端盲 XXE（Tika、Confluence、Jira） |
| test43.pdf | `create_malpdf43()` | CVE-2025-70401 | Annotation `/T` 字段 XSS | Text annotation `/T`（author）字段中的 `<img>` 标签 | XSS callback（Apryse WebViewer、Web PDF viewers） |
| test44.pdf | `create_malpdf44()` | CVE-2024-12426 | LibreOffice URL expansion | 带 `vnd.sun.star.expand:` 的 `/URI` 扩展 `${HOME}` | 环境变量外传（LibreOffice < 24.8.4） |
| test45.pdf | `create_malpdf45()` | CVE-2025-59803 | 签名时 OCG JS trigger | `/AA /WP` + `/DP` 在签名流程中通过 OCG 触发 JS | 签名期间回连（Foxit < 2025.2.1） |
| test46.pdf | `create_malpdf46()` | CVE-2026-25755 | jsPDF object injection | 破坏 JS 字符串并注入 `/AA /O` auto-action | 通过任意 viewer 自动回连（jsPDF < 4.2.0） |
| test47.pdf | `create_malpdf47()` | PDF 2.0 spec | Associated Files HTML embed | 通过 catalog `/AF` + `/EF` EmbeddedFile 嵌入 HTML | 通过嵌入 HTML 回连（PDF 2.0 viewers） |
| test48.pdf | `create_malpdf48()` | XFA spec | XFA SOAP callback | 带 `initialize` event 的 `<submit method="soap">` | SOAP HTTP request（Acrobat XFA engine） |

</details>

## 待办：新增测试用例

- **Acrobat JS fingerprinting APIs** — 为 2026 年 4 月 Adobe 0-day 利用链中使用的侦察/指纹识别 API 添加测试用例（[参考](https://x.com/Gi7w0rm/status/2042370775546482815)）：`Collab.isDocReadOnly`（文件系统探测）、`app.plugIns`（枚举已安装插件）、`app.viewerVersion`（版本指纹识别）

## 待办：尚未实现的混淆方法

- **空密码 PDF 加密** — 使用空用户密码加密所有字符串和 stream。文档打开时无需提示，但静态分析工具无法直接读取内容。这是当前混淆能力最大的缺口。参考：[Didier Stevens](https://blog.didierstevens.com/category/pdf/)、[How secure is PDF encryption?](https://www.decalage.info/hugo/file_formats_security/pdf/)
- **对象流（ObjStm）** — 把 PDF 对象隐藏在压缩 stream 容器中。简单解析器（包括未使用 `-O` 参数的 PDFiD）会完全漏掉这些对象。参考：[PDF spec ISO 32000 §7.5.7](https://www.iso.org/standard/63534.html)
- **getAnnots() 代码存储** — 将 JavaScript payload 拆分到 annotation metadata 字段（subject、author）中，运行时通过 `app.doc.getAnnots()[n].subject` 取回并 eval。参考：[Julia Wolf - PDF Obfuscation using getAnnots()](https://blog.didierstevens.com/2010/01/14/)
- **Info dict 数据提取** — 将编码 payload 存入 `/Info` trailer 字段（`/Title`、`/Author`），运行时通过 JS 中的 `info.Title` 取回。参考：[corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **AcroForm 字段值提取** — 将 payload 片段存入表单字段 `/V` 值，运行时通过 `getField("name").value` 取回。参考：[corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **Names tree split execution** — 将 JavaScript 拆分到多个 `/Names` 条目中顺序执行。参考：[corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **`%%EOF` 后的增量更新** — 通过 incremental update 在原始 `%%EOF` 标记后追加新对象/action。参考：[PDF101 content masking](https://github.com/RUB-NDS/PDF101)、[Didier Stevens](https://blog.didierstevens.com/2010/05/18/more-malformed-pdfs/)
- **JS `unescape()` 编码** — 使用 `eval(unescape("%61%6C%65%72%74..."))` 包装 JS payload。参考：[corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- **伪文件头** — 在 `%PDF-` header 前添加 JPEG/HTML/其他 magic bytes（规范允许 header 出现在前 1024 字节内），干扰文件类型识别。参考：[corkami](https://github.com/corkami/docs/blob/master/PDF/PDF.md)、[Decalage](https://www.decalage.info/hugo/file_formats_security/pdf/)
- **反仿真检查** — 在执行 payload 前通过 `event.target.zoomType == "FitPage"` 或全局变量类型检查来识别真实 Adobe Reader。参考：[corkami PDF tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

## 不会实现

- ~~CVE-2023-26369 - Adobe Acrobat TTF font heap OOB write~~ — 需要二进制利用（heap spray、ROP chains、shellcode）。没有公开 PoC，无法生成简单 callback。
- ~~CVE-2021-28550 - Adobe Acrobat Use-After-Free~~ — 需要二进制利用链和沙箱逃逸（CVE-2021-31199/31201）。没有公开 PoC，无法生成简单 callback。

## Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=jonaslejon/malicious-pdf&type=Date)](https://www.star-history.com/#jonaslejon/malicious-pdf&Date)
