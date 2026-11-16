# test_campaign.py — ThreatIntel Comprehensive Test Campaign
# Runs all 4 categories without Gmail/Cosmos dependencies

import sys, io, asyncio, time, textwrap
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from agents.agent_auth    import run_auth_agent
from agents.agent_url     import run_url_agent
from agents.agent_nlp_bec import run_nlp_bec_agent, extract_forwarded_sender_domain
from agents.agent_sandbox import run_sandbox_agent
from agents.agent_scoring import run_scoring_agent

# ──────────────────────────────────────────────────────────────────────────────
# TEST CASES
# ──────────────────────────────────────────────────────────────────────────────

TESTS = []

# ════════════════════════════════════════════════════════════════
# CATEGORY 3 — LEGITIMATE (should NOT be flagged)
# ════════════════════════════════════════════════════════════════

TESTS.append({
    "id": 12, "category": 3,
    "name": "Sopra Steria Recruitment",
    "expected": "SAFE",
    "sender":   "Recrutement Sopra Steria <recrutement@soprasteria.com>",
    "subject":  "Votre candidature — Ingénieur Logiciel F/H",
    "body": """\
Madame, Monsieur,

Nous avons bien réceptionné votre candidature pour le poste d'Ingénieur Logiciel F/H
au sein du Groupe Sopra Steria.

Nous vous remercions de l'intérêt que vous portez à notre entreprise et avons le plaisir
de vous inviter à un entretien de présélection.

Merci de confirmer vos disponibilités directement sur notre portail :
https://careers.soprasteria.com/booking/interview-42891

Cordialement,
Service Recrutement — Sopra Steria Group
Tour Pacific — 11-13 cours Valmy, 92800 Puteaux
""",
    "auth": "mx1.soprasteria.com; spf=pass smtp.mailfrom=recrutement@soprasteria.com; dkim=pass header.i=@soprasteria.com; dmarc=pass (p=quarantine) header.from=soprasteria.com",
    "reply_to":    "",
    "return_path": "<bounce-recrutement@soprasteria.com>",
    "attachments": [],
})

TESTS.append({
    "id": 13, "category": 3,
    "name": "GitHub PR Notification",
    "expected": "SAFE",
    "sender":   "GitHub <noreply@github.com>",
    "subject":  "[threatintel/threatintel] Pull request #47 by amira-f",
    "body": """\
@amira-f opened a pull request in threatintel/threatintel

Fix: SPF domain extraction from smtp.mailfrom full address

View the pull request:
https://github.com/threatintel/threatintel/pull/47

You are receiving this because you are subscribed to this thread.
Reply to this email directly or view it on GitHub.
""",
    "auth": "mx.google.com; spf=pass smtp.mailfrom=noreply@github.com; dkim=pass header.i=@github.com; dmarc=pass (p=reject) header.from=github.com",
    "reply_to":    "reply+AABBCC@reply.github.com",
    "return_path": "<noreply@github.com>",
    "attachments": [],
})

TESTS.append({
    "id": 14, "category": 3,
    "name": "AWS Billing Alert",
    "expected": "SAFE",
    "sender":   "Amazon Web Services <billing@amazon.com>",
    "subject":  "Your AWS bill is available for March 2026",
    "body": """\
Hello,

Your AWS bill for March 2026 is now available.

Total amount due: $47.32 USD
Due date: April 15, 2026

To view your invoice and pay your bill:
https://console.aws.amazon.com/billing/home

This message was sent from an address that cannot receive replies.
For help with your account, visit: https://aws.amazon.com/support

Amazon Web Services, Inc.
410 Terry Ave North, Seattle, WA 98109-5210
""",
    "auth": "amazonses.com; spf=pass smtp.mailfrom=billing@amazon.com; dkim=pass header.i=@amazon.com; dmarc=pass (p=quarantine) header.from=amazon.com",
    "reply_to":    "",
    "return_path": "<0100018ea7b3c2a-billing@bounce.amazon.com>",
    "attachments": [],
})

TESTS.append({
    "id": 15, "category": 3,
    "name": "Google Workspace Security Alert",
    "expected": "SAFE",
    "sender":   "Google <no-reply@accounts.google.com>",
    "subject":  "Security alert: New sign-in to your Google Account",
    "body": """\
Hi amira.ferchichi,

Your Google Account was just signed in to from a new Windows device.

Device:   Chrome on Windows
Location: Tunis, Tunisia (approximate)
Time:     Tuesday, April 29, 2026

If this was you, you don't need to do anything.
If not, check your account activity:
https://myaccount.google.com/notifications

Google LLC, 1600 Amphitheatre Pkwy, Mountain View, CA 94043
""",
    "auth": "mx.google.com; spf=pass smtp.mailfrom=no-reply@accounts.google.com; dkim=pass header.i=@accounts.google.com; dmarc=pass (p=reject) header.from=google.com",
    "reply_to":    "",
    "return_path": "<no-reply@accounts.google.com>",
    "attachments": [],
})

TESTS.append({
    "id": 16, "category": 3,
    "name": "LinkedIn InMail Notification",
    "expected": "SAFE",
    "sender":   "LinkedIn <messages-noreply@linkedin.com>",
    "subject":  "Tarek Ben Salah sent you a message on LinkedIn",
    "body": """\
Hi Amira,

Tarek Ben Salah (Senior Engineer at Capgemini Tunisia) sent you a message:

"Hello Amira, I saw your profile and your work on email security is impressive.
 Would you be interested in discussing an open position in our cybersecurity team?"

Reply to Tarek:
https://www.linkedin.com/messaging/thread/2-abc123

LinkedIn Corporation, 1000 West Maude Avenue, Sunnyvale, CA 94085
""",
    "auth": "mx.google.com; spf=pass smtp.mailfrom=messages-noreply@linkedin.com; dkim=pass header.i=@linkedin.com; dmarc=pass (p=reject) header.from=linkedin.com",
    "reply_to":    "",
    "return_path": "<messages-noreply@linkedin.com>",
    "attachments": [],
})

TESTS.append({
    "id": 17, "category": 3,
    "name": "Coursera Newsletter (Mailchimp-delivered)",
    "expected": "SAFE",
    "sender":   "Coursera <no-reply@m.learn.coursera.org>",
    "subject":  "Ends tomorrow: 40% off Coursera Plus — Don't miss it",
    "body": """\
Hi Amira,

Your learning journey continues! Don't miss this limited-time offer:

Lock in 40% off Coursera Plus Annual — ends April 30.
Access 7,000+ courses, Professional Certificates and degrees.

Claim offer: https://www.coursera.org/plus?discount=40off

Already a member? Upgrade your existing plan.

Coursera, Inc. | 381 E Evelyn Ave, Mountain View, CA 94041
Unsubscribe: https://www.coursera.org/email/unsubscribe
""",
    "auth": "mail54.sea77.mcsv.net; spf=pass smtp.mailfrom=no-reply@m.learn.coursera.org; dkim=pass header.i=@m.learn.coursera.org; dmarc=pass (p=none) header.from=coursera.org",
    "reply_to":    "",
    "return_path": "<bounce-mc.us11_1234@mail54.sea77.mcsv.net>",
    "attachments": [],
})

# ════════════════════════════════════════════════════════════════
# CATEGORY 1 — CLASSIC PHISHING (must detect as MALICIOUS)
# ════════════════════════════════════════════════════════════════

TESTS.append({
    "id": 1, "category": 1,
    "name": "PayPal Phishing",
    "expected": "DANGER",
    "sender":   "PayPal Security <service@paypal-security-update.com>",
    "subject":  "Your PayPal account has been limited — Immediate action required",
    "body": """\
Dear Customer,

We have noticed unusual activity on your PayPal account.
Your account has been LIMITED. You must verify your information within 24 hours
or your account will be permanently suspended.

Click here to verify your account immediately:
http://paypal-login-verify.xyz/secure/account/restore?token=abc123

Failure to verify will result in permanent account closure.

PayPal Security Team
""",
    "auth": "mx.google.com; spf=fail smtp.mailfrom=service@paypal-security-update.com; dkim=fail; dmarc=fail header.from=paypal-security-update.com",
    "reply_to":    "support@paypal-security-update.com",
    "return_path": "<service@paypal-security-update.com>",
    "attachments": [],
})

TESTS.append({
    "id": 2, "category": 1,
    "name": "Microsoft 365 Credential Harvesting",
    "expected": "DANGER",
    "sender":   "Microsoft Account Team <no-reply@microsoft-account-alert.com>",
    "subject":  "Action Required: Verify your Microsoft account — MFA update needed",
    "body": """\
Your Microsoft 365 account requires immediate verification.

Due to a security policy update, you must re-authenticate your account.
Failure to complete this step within 48 hours will suspend your access to:
- Outlook, Teams, SharePoint, OneDrive

Re-authenticate now:
http://microsoftonline-login.tk/auth/mfa-verify?session=xB9kZ2

This is an automated message. Do not reply.
Microsoft Account Team
""",
    "auth": "mx1.hotmail.com; spf=softfail smtp.mailfrom=no-reply@microsoft-account-alert.com; dkim=none; dmarc=fail",
    "reply_to":    "",
    "return_path": "<no-reply@microsoft-account-alert.com>",
    "attachments": [],
})

TESTS.append({
    "id": 3, "category": 1,
    "name": "IRS Tax Refund Scam",
    "expected": "DANGER",
    "sender":   "Internal Revenue Service <refund@irs-gov-refund.com>",
    "subject":  "Tax Refund Notice — $2,847 pending — Confirm your details",
    "body": """\
Dear Taxpayer,

Our records show you are eligible for a tax refund of $2,847.00 for fiscal year 2025.

To process your refund, please confirm your information:
- Social Security Number
- Bank routing and account number

Complete your refund claim: http://irs-tax-refund-claim.top/submit

NOTE: You must respond within 5 business days or forfeit your refund.
Refund claim ID: IRS-2025-8847-REFUND

Internal Revenue Service
Washington, D.C. 20224
""",
    "auth": "mx.refundserver.com; spf=none; dkim=none; dmarc=none",
    "reply_to":    "refund-claims@irs-gov-refund.com",
    "return_path": "<refund@irs-gov-refund.com>",
    "attachments": [],
})

TESTS.append({
    "id": 4, "category": 1,
    "name": "DHL Package Phishing",
    "expected": "DANGER",
    "sender":   "DHL Express <tracking@dhl-express-delivery.net>",
    "subject":  "DHL Shipment Notification — Package awaiting customs clearance",
    "body": """\
Your DHL package is awaiting customs clearance.

Tracking number: 1Z999AA10123456784
Status: HELD — Customs fee unpaid

To release your package, pay the customs fee of €2.99:
http://dhl-parcel-release.click/customs?ref=1Z999AA101234

Note: Package will be returned if not claimed within 48 hours.

DHL Express Customer Service
""",
    "auth": "mx.delivery-server.net; spf=pass smtp.mailfrom=tracking@dhl-express-delivery.net; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<noreply@dhl-express-delivery.net>",
    "attachments": [],
})

TESTS.append({
    "id": 5, "category": 1,
    "name": "CEO Fraud / BEC Wire Transfer",
    "expected": "DANGER",
    "sender":   "Mohamed Trabelsi — PDG <m.trabelsi@enit-utm.tn.workers.dev>",
    "subject":  "URGENT — Virement confidentiel à effectuer aujourd'hui",
    "body": """\
Bonjour,

Je suis actuellement en réunion externe et j'ai besoin que vous procédiez
d'urgence à un virement bancaire confidentiel de 47 500 EUR aujourd'hui avant 17h.

Cette opération est strictement confidentielle — ne pas en parler au service comptable.

Coordonnées bancaire :
IBAN : DE89 3704 0044 0532 0130 00
BIC  : COBADEFFXXX
Bénéficiaire : Apex Consulting GmbH

Confirmez-moi par retour de mail dès exécution.

Cordialement,
M. Trabelsi
PDG — ENIT
""",
    "auth": "mx.workers.dev; spf=pass smtp.mailfrom=m.trabelsi@enit-utm.tn.workers.dev; dkim=none; dmarc=none",
    "reply_to":    "m.trabelsi.ceo@protonmail.com",
    "return_path": "<m.trabelsi@enit-utm.tn.workers.dev>",
    "attachments": [],
})

TESTS.append({
    "id": 6, "category": 1,
    "name": "COVID-19 WHO Phishing",
    "expected": "DANGER",
    "sender":   "World Health Organization <messaging@who-health-alert.com>",
    "subject":  "URGENT: COVID-19 Safety Measures — Mandatory Document Enclosed",
    "body": """\
Dear Sir/Madam,

Please find enclosed the latest WHO mandatory COVID-19 safety document.
All recipients are required to review and sign the enclosed form.

Open attachment: covid_safety_measures.doc

For questions, contact: health-alert@who-health-alert.com

Regards,
Dr. Tedros A. Ghebreyesus
Director-General, World Health Organization
""",
    "auth": "mx.who-health-alert.com; spf=pass smtp.mailfrom=messaging@who-health-alert.com; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<messaging@who-health-alert.com>",
    "attachments": [{"name": "covid_safety_measures.doc", "data": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512, "size": 520}],
})

TESTS.append({
    "id": 7, "category": 1,
    "name": "Google Drive Share Phishing",
    "expected": "DANGER",
    "sender":   "Google Drive <drive-shares-noreply@google-drive-notifications.com>",
    "subject":  "Amira Ferchichi shared a document with you",
    "body": """\
Amira Ferchichi has shared the following document with you:

Document: "Q1 2026 Financial Report — CONFIDENTIAL"

Open in Google Drive:
https://docs.google-drive-notifications.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms

This is an automated notification from Google Drive.
""",
    "auth": "mx.google-drive-notifications.com; spf=softfail smtp.mailfrom=drive-shares-noreply@google-drive-notifications.com; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<drive-shares-noreply@google-drive-notifications.com>",
    "attachments": [],
})

# ════════════════════════════════════════════════════════════════
# CATEGORY 2 — MALICIOUS ATTACHMENTS
# ════════════════════════════════════════════════════════════════

TESTS.append({
    "id": 8, "category": 2,
    "name": "Emotet Word Macro Dropper",
    "expected": "DANGER",
    "sender":   "accounting@legit-supplier.com",
    "subject":  "Invoice #2026-0489 — Please review and sign",
    "body": """\
Please find attached our invoice #2026-0489 for services rendered in March 2026.
Kindly open and sign the document at your earliest convenience.

Total amount: $12,450.00
Due date: May 15, 2026

Best regards,
Accounting Department
""",
    "auth": "mx.legit-supplier.com; spf=pass smtp.mailfrom=accounting@legit-supplier.com; dkim=pass header.i=@legit-supplier.com; dmarc=none",
    "reply_to":    "",
    "return_path": "<accounting@legit-supplier.com>",
    # Simulate Emotet .docm: OLE2 header + macro stream markers
    "attachments": [{"name": "invoice_2026-0489.docm", "data": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"VBA" * 50 + b"AutoOpen" * 20 + b"Shell" * 10 + b"\x00" * 200, "size": 1200}],
})

TESTS.append({
    "id": 9, "category": 2,
    "name": "Ryuk Ransomware ZIP+JS Dropper",
    "expected": "DANGER",
    "sender":   "hr@company-payroll.net",
    "subject":  "Your payslip for March 2026 is ready",
    "body": """\
Dear Employee,

Your payslip for March 2026 is now available.
Please extract and open the attached file to view your payslip.

Payroll Department
""",
    "auth": "mx.company-payroll.net; spf=pass smtp.mailfrom=hr@company-payroll.net; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<hr@company-payroll.net>",
    # Simulate ZIP with .js dropper (PK header + JS content)
    "attachments": [{"name": "payslip_march2026.zip", "data": b"PK\x03\x04" + b"payslip.js" + b"WScript.Shell" * 30 + b"http://malware.download/ryuk" + b"\x00" * 100, "size": 600}],
})

TESTS.append({
    "id": 10, "category": 2,
    "name": "AgentTesla Keylogger XLSM",
    "expected": "DANGER",
    "sender":   "finance@trusted-bank-notifications.com",
    "subject":  "Account Statement — Please open to verify",
    "body": """\
Dear Client,

Your monthly account statement is attached.
Please open the file to verify all transactions.

If you notice any discrepancies, contact us immediately.

Finance Department
""",
    "auth": "mx.trusted-bank-notifications.com; spf=pass smtp.mailfrom=finance@trusted-bank-notifications.com; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<finance@trusted-bank-notifications.com>",
    # Simulate XLSM: ZIP (xlsx = ZIP) with VBA macro + keylogger hints
    "attachments": [{"name": "account_statement.xlsm", "data": b"PK\x03\x04" + b"xl/vbaProject.bin" + b"\xd0\xcf\x11\xe0" + b"Private Sub" * 10 + b"keylog" * 5 + b"smtp" * 5 + b"\x00" * 200, "size": 900}],
})

TESTS.append({
    "id": 11, "category": 2,
    "name": "PDF with Embedded JavaScript",
    "expected": "DANGER",
    "sender":   "invoices@business-portal.info",
    "subject":  "Invoice INV-2026-44821 — Payment Confirmation",
    "body": """\
Please find your invoice attached.
Open the PDF to view payment confirmation details.

Business Portal Finance Team
""",
    "auth": "mx.business-portal.info; spf=pass smtp.mailfrom=invoices@business-portal.info; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<invoices@business-portal.info>",
    # Simulate PDF with OpenAction JS: proper PDF header + JS stream
    "attachments": [{"name": "invoice_INV-2026-44821.pdf", "data": b"%PDF-1.4\n" + b"/OpenAction" + b"/JavaScript" + b"(eval(unescape(" * 5 + b"http://exploit.top/payload" + b"\x00" * 200, "size": 600}],
})

# ════════════════════════════════════════════════════════════════
# CATEGORY 4 — EDGE CASES & ADVERSARIAL
# ════════════════════════════════════════════════════════════════

TESTS.append({
    "id": 18, "category": 4,
    "name": "Lookalike Domain (paypa1.com)",
    "expected": "DANGER",
    "sender":   "PayPal <service@paypa1.com>",
    "subject":  "Your account needs verification",
    "body": """\
Your PayPal account needs to be verified.
Click here: http://paypa1.com/secure/verify
""",
    "auth": "mx.paypa1.com; spf=pass smtp.mailfrom=service@paypa1.com; dkim=pass header.i=@paypa1.com; dmarc=none",
    "reply_to":    "",
    "return_path": "<service@paypa1.com>",
    "attachments": [],
})

TESTS.append({
    "id": 19, "category": 4,
    "name": "HTTPS Phishing (valid SSL, malicious site)",
    "expected": "DANGER",
    "sender":   "security@account-verify-secure.com",
    "subject":  "Secure account verification required",
    "body": """\
Your account requires immediate verification.
This is a secure, encrypted process.

Verify now via HTTPS: https://account-verify-secure.com/login?redirect=steal-creds

Our site uses industry-standard SSL encryption.
""",
    "auth": "mx.account-verify-secure.com; spf=pass smtp.mailfrom=security@account-verify-secure.com; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<security@account-verify-secure.com>",
    "attachments": [],
})

TESTS.append({
    "id": 20, "category": 4,
    "name": "Legitimate-looking BEC (no links, hard NLP case)",
    "expected": "DANGER",
    "sender":   "Caroline Martin <c.martin@soprasteria-group.com>",
    "subject":  "Confidential — New banking details for supplier",
    "body": """\
Bonjour,

Suite au changement de notre prestataire bancaire, je vous contacte pour vous informer
que les coordonnées bancaires de notre fournisseur principal ont été modifiées.

Pour tous les virements en cours et à venir, veuillez utiliser les nouvelles coordonnées
ci-dessous en remplacement des anciennes :

IBAN : FR76 3000 6000 0112 3456 7890 189
BIC  : BNPAFRPPXXX
Titulaire : Apex Solutions SARL

Cette demande est confidentielle. Merci de ne pas en informer votre responsable direct
avant que la transition soit complète.

Cordialement,
Caroline Martin
Directrice Administrative et Financière — Sopra Steria
""",
    "auth": "mx.soprasteria-group.com; spf=pass smtp.mailfrom=c.martin@soprasteria-group.com; dkim=pass header.i=@soprasteria-group.com; dmarc=none",
    "reply_to":    "c.martin.daf@protonmail.com",
    "return_path": "<c.martin@soprasteria-group.com>",
    "attachments": [],
})

TESTS.append({
    "id": 21, "category": 4,
    "name": "Spear Phishing (personalized)",
    "expected": "DANGER",
    "sender":   "Prof. Adel Bouhoula <a.bouhoula@enit.rnu.tn.security-alert.xyz>",
    "subject":  "Amira — Urgent access issue with your ENIT thesis portal",
    "body": """\
Chère Amira Ferchichi,

Suite à une maintenance urgente du portail de dépôt des mémoires de l'ENIT,
votre accès a été temporairement suspendu.

Pour rétablir votre accès avant la date limite de soumission (30 avril 2026),
veuillez confirmer vos identifiants via ce formulaire sécurisé :
http://enit-portal-restore.xyz/login?student=amira.ferchichi

Cordialement,
Prof. Adel Bouhoula
Direction des Études — ENIT
""",
    "auth": "mx.security-alert.xyz; spf=pass smtp.mailfrom=a.bouhoula@enit.rnu.tn.security-alert.xyz; dkim=none; dmarc=none",
    "reply_to":    "",
    "return_path": "<a.bouhoula@enit.rnu.tn.security-alert.xyz>",
    "attachments": [],
})

TESTS.append({
    "id": 22, "category": 4,
    "name": "Mixed Trust Email (legit sender, malicious URL)",
    "expected": "DANGER",
    "sender":   "support@amazon.com",
    "subject":  "Important: Review your recent order",
    "body": """\
Hello,

We noticed unusual activity related to your recent Amazon order.
Please review your order details to confirm everything is correct.

Review your order: http://185.220.101.45/amazon/order-confirm?id=9988

Amazon Customer Service
""",
    "auth": "amazonses.com; spf=pass smtp.mailfrom=support@amazon.com; dkim=pass header.i=@amazon.com; dmarc=pass (p=quarantine)",
    "reply_to":    "",
    "return_path": "<support@amazon.com>",
    "attachments": [],
})


# ──────────────────────────────────────────────────────────────────────────────
# RUNNER
# ──────────────────────────────────────────────────────────────────────────────

def run_test(t: dict) -> dict:
    """Run a single test through all agents and return structured results."""
    sender     = t["sender"]
    subject    = t["subject"]
    body       = t["body"]
    auth_hdr   = t["auth"]
    reply_to   = t.get("reply_to", "")
    return_path= t.get("return_path", "")
    attachments= t.get("attachments", [])

    import re
    m = re.search(r'@([\w.\-]+)', sender)
    sender_domain = m.group(1).lower() if m else ""
    forwarded = extract_forwarded_sender_domain(body)
    effective_domain = forwarded if forwarded else sender_domain

    # ── AUTH ──
    auth_result = run_auth_agent(
        sender, subject, "", "", reply_to, return_path, auth_hdr, ""
    )

    # ── URL + NLP (parallel via threading since we're not in async context) ──
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as ex:
        fut_url = ex.submit(run_url_agent, body, 10)
        fut_nlp = ex.submit(run_nlp_bec_agent, subject, body, effective_domain, False)
        url_result = fut_url.result()
        nlp_result = fut_nlp.result()

    # ── SANDBOX ──
    score_provisoire = int(
        (100 - auth_result.get("score_auth", 0)) * 0.25 +
        url_result.get("score_url", 0)            * 0.35 +
        nlp_result.get("score_nlp", 0)            * 0.40
    )
    sandbox_result = run_sandbox_agent(attachments=attachments, score_provisoire=score_provisoire)

    # ── SCORING ──
    final = run_scoring_agent(
        score_auth    = auth_result.get("score_auth", 0),
        score_url     = url_result.get("score_url",   0),
        score_nlp     = nlp_result.get("score_nlp",   0),
        score_sandbox = sandbox_result.get("score_sandbox", 0),
        subject       = subject,
        sender        = sender,
    )

    # Normalize verdict to SAFE / SUSPICIOUS / DANGER
    v = final.get("action", "")
    if v == "BLOCK":        verdict = "DANGER"
    elif v == "QUARANTINE": verdict = "SUSPICIOUS"
    else:                   verdict = "SAFE"

    expected = t["expected"]
    if verdict == expected:
        status = "PASS"
    elif expected == "DANGER" and verdict == "SAFE":
        status = "FN"   # False Negative — missed threat
    elif expected == "DANGER" and verdict == "SUSPICIOUS":
        status = "PARTIAL"  # Detected but under-classified
    elif expected == "SAFE" and verdict in ("DANGER", "SUSPICIOUS"):
        status = "FP"   # False Positive
    else:
        status = "PARTIAL"

    return {
        "id":          t["id"],
        "category":    t["category"],
        "name":        t["name"],
        "expected":    expected,
        "verdict":     verdict,
        "score":       final.get("score_final", 0),
        "status":      status,
        "auth_score":  auth_result.get("score_auth", 0),
        "auth_verdict":auth_result.get("verdict", "—"),
        "auth_detail": auth_result.get("detail", ""),
        "url_score":   url_result.get("score_url", 0),
        "url_verdict": url_result.get("verdict", "—"),
        "nlp_score":   nlp_result.get("score_nlp", 0),
        "nlp_verdict": nlp_result.get("verdict", "—"),
        "sandbox_score":  sandbox_result.get("score_sandbox", 0),
        "sandbox_verdict":sandbox_result.get("verdict", "—"),
        "hard_rule":   final.get("hard_rule", ""),
        "probas":      final.get("probabilites", {}),
    }


def print_result(r: dict):
    cat_names = {1:"PHISHING", 2:"ATTACHMENT", 3:"LEGITIMATE", 4:"EDGE CASE"}
    status_icon = {"PASS":"✅", "FP":"❌ FP", "FN":"❌ FN", "PARTIAL":"⚠️ PARTIAL"}
    icon = status_icon.get(r["status"], "?")

    sep = "═" * 62
    print(f"\n{sep}")
    print(f"  Test #{r['id']} [{cat_names.get(r['category'],'?')}] — {r['name']}")
    print(f"  Expected : {r['expected']}  |  Got : {r['verdict']} ({r['score']}/100)")
    print(f"  Status   : {icon} {r['status']}")
    print(f"  ─── Agents ───────────────────────────────────────────")
    print(f"  AUTH    : {r['auth_score']:3d}/100  {r['auth_verdict'][:50]}")
    if r['auth_detail']:
        # Print detail in chunks
        detail = r['auth_detail']
        chunks = textwrap.wrap(detail, width=55)
        for i, chunk in enumerate(chunks[:3]):
            prefix = "          " if i > 0 else "  DETAIL  : "
            print(f"{prefix}{chunk}")
    print(f"  URL     : {r['url_score']:3d}/100  {r['url_verdict'][:50]}")
    print(f"  NLP     : {r['nlp_score']:3d}/100  {r['nlp_verdict'][:50]}")
    print(f"  SANDBOX : {r['sandbox_score']:3d}/100  {r['sandbox_verdict'][:50]}")
    p = r['probas']
    print(f"  PROBAS  : SAIN={p.get('sain',0):.1f}%  SUSPECT={p.get('suspect',0):.1f}%  DANGER={p.get('danger',0):.1f}%")
    if r['hard_rule']:
        rule = textwrap.shorten(r['hard_rule'], width=55, placeholder="...")
        print(f"  RULE    : {rule}")
    print(sep)


def print_summary(results: list):
    print("\n\n" + "═" * 62)
    print("  SUMMARY TABLE")
    print("═" * 62)
    hdr = f"{'#':>3}  {'Name':<35} {'Exp':<11} {'Got':<11} {'Score':>5}  {'Status'}"
    print(f"  {hdr}")
    print("  " + "─" * 60)

    passes = fps = fns = partials = 0
    failures = []

    for r in results:
        s = r["status"]
        if s == "PASS":       passes   += 1; icon = "✅"
        elif s == "FP":       fps      += 1; icon = "❌ FP"
        elif s == "FN":       fns      += 1; icon = "❌ FN"
        else:                 partials += 1; icon = "⚠️"

        row = f"#{r['id']:>2}  {r['name']:<35} {r['expected']:<11} {r['verdict']:<11} {r['score']:>5}/100  {icon}"
        print(f"  {row}")

        if s in ("FP", "FN", "PARTIAL"):
            failures.append(r)

    print("  " + "─" * 60)
    total = len(results)
    print(f"\n  PASS={passes}/{total}  |  FP={fps}  |  FN={fns}  |  PARTIAL={partials}")
    print("═" * 62)

    if failures:
        print("\n\n  FAILURES — ROOT CAUSE ANALYSIS")
        print("═" * 62)
        for r in failures:
            print(f"\n  ❌ Test #{r['id']} — {r['name']}")
            print(f"     Expected {r['expected']} → Got {r['verdict']} ({r['score']}/100)")
            # Identify responsible agent
            issues = []
            if r["expected"] == "SAFE":
                if r["auth_score"] < 55:
                    issues.append(f"AUTH too low ({r['auth_score']}) — possible false penalty")
                if r["url_score"] >= 40:
                    issues.append(f"URL flagged ({r['url_score']}) — check if URL is benign")
                if r["nlp_score"] >= 40:
                    issues.append(f"NLP flagged ({r['nlp_score']}) — model sensitivity too high")
            else:  # expected DANGER
                if r["auth_score"] >= 70:
                    issues.append(f"AUTH score too high ({r['auth_score']}) — not penalizing enough")
                if r["url_score"] < 40:
                    issues.append(f"URL missed ({r['url_score']}) — malicious URLs not detected")
                if r["nlp_score"] < 40:
                    issues.append(f"NLP missed ({r['nlp_score']}) — content not flagged")
                if r["sandbox_score"] < 40 and r["category"] == 2:
                    issues.append(f"SANDBOX missed ({r['sandbox_score']}) — attachment not detected")
            if r["hard_rule"]:
                issues.append(f"Hard rule applied: {r['hard_rule'][:60]}")
            for issue in issues:
                print(f"     → {issue}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--category", type=int, default=0, help="Run only category N (0=all)")
    parser.add_argument("--id", type=int, default=0, help="Run only test #N")
    args = parser.parse_args()

    to_run = TESTS
    if args.id:
        to_run = [t for t in TESTS if t["id"] == args.id]
    elif args.category:
        to_run = [t for t in TESTS if t["category"] == args.category]

    print(f"\n{'#'*62}")
    print(f"  ThreatIntel Test Campaign — {len(to_run)} test(s)")
    cat_label = {0:"ALL", 1:"PHISHING", 2:"ATTACHMENTS", 3:"LEGITIMATE", 4:"EDGE CASES"}
    label = cat_label.get(args.category if not args.id else 0, str(args.category))
    if args.id: label = f"Test #{args.id}"
    print(f"  Category : {label}")
    print(f"{'#'*62}\n")

    results = []
    for i, t in enumerate(to_run, 1):
        cat_names = {1:"PHISHING", 2:"ATTACHMENT", 3:"LEGITIMATE", 4:"EDGE CASE"}
        print(f"[{i}/{len(to_run)}] Running: #{t['id']} {t['name']}...", flush=True)
        t0 = time.time()
        r = run_test(t)
        elapsed = time.time() - t0
        print(f"        → {r['verdict']} ({r['score']}/100) [{elapsed:.1f}s]")
        results.append(r)

    # Detailed output
    for r in results:
        print_result(r)

    # Summary
    print_summary(results)
