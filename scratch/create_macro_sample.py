import io
import urllib.request
import zipfile

ole_url = "https://raw.githubusercontent.com/decalage2/oletools/master/tests/test-data/olevba/sample_with_vba.ppt"
req = urllib.request.Request(ole_url, headers={"User-Agent": "MAVERICK-Forensics/1.0"})
with urllib.request.urlopen(req) as resp:
    ole_data = resp.read()

buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr(
        "[Content_Types].xml",
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/>'
        "</Types>",
    )
    z.writestr(
        "word/document.xml",
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>Quarterly Financial Forecast Document with Automation Macro</w:t></w:r></w:p></w:body>"
        "</w:document>",
    )
    z.writestr("word/vbaProject.bin", ole_data)

with open("samples/sample_macro_benign.docx", "wb") as f:
    f.write(buf.getvalue())

print(f"Created samples/sample_macro_benign.docx ({len(buf.getvalue())} bytes)")
