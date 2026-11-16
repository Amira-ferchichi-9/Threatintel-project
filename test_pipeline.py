# test_pipeline.py — Tests mails dangereux connus
import asyncio
from orchestrator import orchestrate

TESTS = [
    # ─── BEC / PHISHING ACADÉMIQUE ───────────────────────
    {
        "label": "🎯 Spear Phishing Académique (goacadco.info)",
        "expected": "DANGER",
        "email": {
            "message_id": "test-001",
            "source_folder": "INBOX",
            "subject": "Fwd: Thinking of you and wishing you safety",
            "sender": "Faouzi BAHLOUL <faouzi.bahloul@enit.utm.tn>",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "",
            "arc_authentication_results": "",
            "to_header": "amira.ferchichi@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
---------- Forwarded message ---------
De : Chinatsu Yui <asianspeech.b@goacadco.info>
Date: mar. 31 mars 2026
Subject: Thinking of you and wishing you safety
To: faouzi.bahloul@enit.utm.tn

Dear Professor Faouzi Bahloul,
I hope this message finds you safe. Given the recent developments in the Middle East,
I imagine the situation may bring significant challenges and uncertainty.
My name is Chinatsu Yui, I am a medical doctor based in Japan keen to explore
opportunities for meaningful collaboration between scholars.
With my medical background and academic network in Asia, I am keen to explore
opportunities for meaningful collaboration. Trust-based, long-term friendships
that transcend borders are my goal.
With greatest respect,
Chinatsu Yui — Former Surgeon & Scientist, Expert in International Academic Exchange
""",
        }
    },

    # ─── BEC VIREMENT URGENT ─────────────────────────────
    {
        "label": "💸 BEC Wire Transfer (CFO Fraud)",
        "expected": "DANGER",
        "email": {
            "message_id": "test-002",
            "source_folder": "INBOX",
            "subject": "URGENT - Wire Transfer Required Today - Confidential",
            "sender": "CFO John Smith <azizbouazzi312@gmail.com>",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "",
            "arc_authentication_results": "",
            "to_header": "amira.ferchichi@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Aziz,
I need you to process an urgent wire transfer of $48,500 to our new vendor account immediately.
This is time-sensitive and must be completed before end of business today.
Please do not discuss this with anyone else in the office.
Wire details:
Bank: First International Bank
Account: 4716-2891-0034-5567
Routing: 021000021
Best regards,
John Smith
Chief Financial Officer
""",
        }
    },

    # ─── PHISHING PAYPAL CLASSIQUE ────────────────────────
    {
        "label": "🎣 Phishing PayPal classique",
        "expected": "DANGER",
        "email": {
            "message_id": "test-003",
            "source_folder": "INBOX",
            "subject": "Your PayPal account has been limited",
            "sender": "PayPal <service@paypal-secure-login.xyz>",
            "reply_to": "",
            "return_path": "bounce@paypal-secure-login.xyz",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Customer,
Your PayPal account has been limited due to suspicious activity.
Please verify your account immediately to avoid permanent suspension.
Click here to verify: https://paypal.login-secure.xyz/verify?account=amira
Enter your password and billing information to restore access.
Failure to verify within 24 hours will result in account termination.
PayPal Security Team
""",
        }
    },

    # ─── PHISHING MICROSOFT 365 ───────────────────────────
    {
        "label": "🔐 Phishing Microsoft 365",
        "expected": "DANGER",
        "email": {
            "message_id": "test-004",
            "source_folder": "INBOX",
            "subject": "Action Required: Your Microsoft 365 password expires today",
            "sender": "Microsoft Security <security@microsoft-365-update.club>",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "spf=fail; dkim=none; dmarc=fail",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Your Microsoft 365 password expires today.
Click the link below to update your password and keep your account active.
https://microsoft.365-update.club/reset?user=amira
If you do not update your password within 24 hours, your account will be suspended.
Microsoft Security Team
""",
        }
    },
    # ─── NIGERIAN PRINCE SCAM ────────────────────────────
    {
        "label": "👑 Nigerian Prince Scam (419 fraud)",
        "expected": "DANGER",
        "email": {
            "message_id": "test-009",
            "source_folder": "INBOX",
            "subject": "URGENT BUSINESS PROPOSAL - STRICTLY CONFIDENTIAL",
            "sender": "Prince Hakeem Abdul <prince.hakeem@yahoo.com>",
            "reply_to": "hakeem.transfer@gmail.com",
            "return_path": "",
            "authentication_results": "",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Friend,
I am Prince Hakeem Abdul, son of the late King of Nigeria.
I have $45,000,000 USD that I need to transfer out of the country urgently.
I need your bank account details to transfer this money.
You will receive 30% commission for your assistance.
This is strictly confidential, do not tell anyone.
Please reply only to me with your full name, bank account number and routing number.
God bless you,
Prince Hakeem Abdul
""",
        }
    },

    # ─── SEXTORTION ──────────────────────────────────────
    {
        "label": "😈 Sextortion / Blackmail scam",
        "expected": "DANGER",
        "email": {
            "message_id": "test-010",
            "source_folder": "INBOX",
            "subject": "I know your password — pay now",
            "sender": "hacker@protonmail.com",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
I hacked your device and recorded you visiting adult websites.
I have a video of you. If you don't pay me $1500 in Bitcoin within 48 hours,
I will send this video to all your contacts.
Send Bitcoin to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf
Do not reply to this email. Do not contact police.
You have 48 hours.
""",
        }
    },

    # ─── FAKE DHL / LIVRAISON ────────────────────────────
    {
        "label": "📦 Fake DHL delivery phishing",
        "expected": "DANGER",
        "email": {
            "message_id": "test-011",
            "source_folder": "INBOX",
            "subject": "Your DHL package is waiting — action required",
            "sender": "DHL Express <delivery@dhl-express-tracking.xyz>",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Customer,
Your DHL package #TN482910 is on hold due to unpaid customs fees.
You must pay $2.99 to release your package within 24 hours or it will be returned.
Click here to pay: https://dhl-delivery-confirm.xyz/pay?id=TN482910
Enter your credit card details to complete the payment.
DHL Express Customer Service
""",
        }
    },

    # ─── RANSOMWARE PAR MAIL ─────────────────────────────
    {
        "label": "🔒 Ransomware dropper email",
        "expected": "DANGER",
        "email": {
            "message_id": "test-012",
            "source_folder": "INBOX",
            "subject": "Invoice #INV-2024-00892 — Payment Overdue",
            "sender": "accounts@billing-invoices.top",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "spf=fail; dkim=none; dmarc=fail",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear valued customer,
Please find attached your overdue invoice #INV-2024-00892 for $12,450.
Your account is now 30 days past due. Immediate payment is required.
Download your invoice here: https://billing-invoices.top/download/invoice.exe
Failure to pay within 48 hours will result in legal action.
Accounts Receivable Department
""",
        }
    },

    # ─── COVID / EMERGENCY SCAM ──────────────────────────
    {
        "label": "🦠 Emergency/COVID relief scam",
        "expected": "DANGER",
        "email": {
            "message_id": "test-013",
            "source_folder": "INBOX",
            "subject": "COVID-19 Relief Fund — You are eligible for $5,000",
            "sender": "Government Relief <relief@covid-aid-program.tk>",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Citizen,
You have been selected to receive $5,000 COVID-19 relief funds.
To claim your payment, verify your identity immediately.
Click here: https://covid-aid-program.tk/claim?id=482910
Provide your bank account number and routing number to receive funds.
This offer expires in 24 hours. Act now.
Government Relief Program
""",
        }
    },

    # ─── FAKE JOB OFFER ──────────────────────────────────
    {
        "label": "💼 Fake job offer scam",
        "expected": "DANGER",
        "email": {
            "message_id": "test-014",
            "source_folder": "INBOX",
            "subject": "Job Offer — $5000/month work from home",
            "sender": "HR Manager <hr.recruitment@jobs-worldwide.xyz>",
            "reply_to": "jobs.apply@gmail.com",
            "return_path": "",
            "authentication_results": "",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Amira,
Congratulations! You have been selected for a remote position paying $5000/month.
No experience required. Work from home. Flexible hours.
To confirm your position, send us your:
- Full name and address
- Bank account number for salary deposit
- Copy of your ID
Reply only to me and keep this confidential until contract is signed.
HR Department — WorldWide Jobs
""",
        }
    },

    # ─── MAIL LÉGITIME ÉTUDIANT ENIT ─────────────────────
    {
        "label": "✅ Mail légitime étudiant ENIT",
        "expected": "SAIN",
        "email": {
            "message_id": "test-015",
            "source_folder": "INBOX",
            "subject": "Réunion projet PFA — jeudi 14h",
            "sender": "Med Aziz Bouazzi <medaziz.bouazzi@etudiant-enit.utm.tn>",
            "reply_to": "",
            "return_path": "medaziz.bouazzi@etudiant-enit.utm.tn",
            "authentication_results": "spf=pass smtp.mailfrom=etudiant-enit.utm.tn; dkim=pass; dmarc=pass",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Bonjour Amira,
Je te confirme notre réunion pour le projet PFA jeudi à 14h en salle B204.
Merci de préparer la partie NLP pour la présentation.
Nous avons bien reçu les retours du professeur et nous allons examiner les corrections.
Cordialement,
Med Aziz
""",
        }
    },


    # ─── MALWARE PAR LIEN ─────────────────────────────────
    {
        "label": "☣️ Malware link connu (Google Safe Browsing test)",
        "expected": "DANGER",
        "email": {
            "message_id": "test-005",
            "source_folder": "INBOX",
            "subject": "Your invoice is ready",
            "sender": "billing@suspicious-invoice.xyz",
            "reply_to": "",
            "return_path": "",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Dear Customer,
Your invoice #INV-2024-8821 is ready for download.
Please click the link below to download your invoice:
http://malware.testing.google.test/testing/malware/
Also verify your account: http://testsafebrowsing.appspot.com/s/phishing.html
Thank you for your business.
""",
        }
    },

    # ─── GIFT CARD SCAM ──────────────────────────────────
    {
        "label": "🎁 Gift Card Scam (CEO fraud)",
        "expected": "DANGER",
        "email": {
            "message_id": "test-006",
            "source_folder": "INBOX",
            "subject": "Urgent Request",
            "sender": "CEO Robert Martin <robert.martin@gmail.com>",
            "reply_to": "robert.ceo.request@gmail.com",
            "return_path": "",
            "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass; dmarc=pass",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Hi,
Are you available? I need you to do something for me urgently.
I need you to buy some Google Play gift cards worth $500.
Buy them from any store nearby and send me the redemption codes.
Do not tell anyone about this, keep this between us.
I will reimburse you as soon as I am back.
Thanks,
Robert Martin
CEO
""",
        }
    },

    # ─── MAIL LÉGITIME ENIT ───────────────────────────────
    {
        "label": "✅ Mail légitime prof ENIT",
        "expected": "SAIN",
        "email": {
            "message_id": "test-007",
            "source_folder": "INBOX",
            "subject": "Nouveau support de cours disponible",
            "sender": "Tarek Kouki <tarek.kouki@enit.utm.tn>",
            "reply_to": "",
            "return_path": "tarek.kouki@enit.utm.tn",
            "authentication_results": "spf=pass smtp.mailfrom=enit.utm.tn; dkim=pass header.i=@enit.utm.tn; dmarc=pass",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Bonjour,
Je vous informe que le nouveau support de cours pour le module Réseaux est disponible
sur la plateforme Moodle de l'ENIT.
Vous pouvez le télécharger depuis votre espace étudiant.
Cordialement,
Dr. Tarek Kouki
Département TIC, ENIT
""",
        }
    },

    # ─── MAIL LÉGITIME CANDIDATURE ───────────────────────
    {
        "label": "✅ Mail légitime accusé réception candidature",
        "expected": "SAIN",
        "email": {
            "message_id": "test-008",
            "source_folder": "INBOX",
            "subject": "Accusé de réception — Votre candidature chez Sopra Steria",
            "sender": "RH Sopra Steria <rh@soprasteria.com>",
            "reply_to": "",
            "return_path": "rh@soprasteria.com",
            "authentication_results": "spf=pass smtp.mailfrom=soprasteria.com; dkim=pass header.i=@soprasteria.com; dmarc=pass",
            "arc_authentication_results": "",
            "to_header": "amira@etudiant-enit.utm.tn",
            "cc_header": "",
            "attachments": [],
            "body_text": """
Bonjour Amira,
Nous avons bien reçu votre candidature pour le poste d'ingénieure en cybersécurité.
Nous vous remercions de l'intérêt que vous portez à notre entreprise.
Votre candidature sera examinée dans les plus brefs délais.
Conformément au RGPD, vos données personnelles seront traitées de manière confidentielle.
Cordialement,
L'équipe RH — Sopra Steria
""",
        }
    },
]


async def run_tests():
    print("\n" + "🧪 " * 20)
    print("  THREATINTEL — TESTS PIPELINE COMPLET")
    print("🧪 " * 20)

    passed = 0
    failed = 0
    results = []

    for t in TESTS:
        print(f"\n{'─'*55}")
        print(f"  TEST : {t['label']}")
        print(f"  ATTENDU : {t['expected']}")
        print(f"{'─'*55}")

        result = await orchestrate(t["email"], reports_dir="reports/tests")
        scoring = result["scoring"]

        verdict = scoring.get("verdict", "")
        action = scoring.get("action", "")
        score = scoring.get("score_final", 0)

        if t["expected"] == "DANGER":
            ok = action == "BLOCK"
        elif t["expected"] == "SAIN":
            ok = action == "DELIVER"
        else:
            ok = action == "QUARANTINE"

        status = "✅ PASS" if ok else "❌ FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        results.append({
            "label": t["label"],
            "expected": t["expected"],
            "got": action,
            "score": score,
            "verdict": verdict,
            "ok": ok
        })

        print(f"\n  {status}")
        print(f"  Score    : {score}/100")
        print(f"  Verdict  : {verdict}")
        if scoring.get("hard_rule"):
            print(f"  Règle    : {scoring['hard_rule']}")

    # ─── RÉSUMÉ ───────────────────────────────────────────
    print(f"\n{'═'*55}")
    print(f"  RÉSULTATS : {passed}/{len(TESTS)} tests passés")
    print(f"{'═'*55}")
    for r in results:
        icon = "✅" if r["ok"] else "❌"
        print(f"  {icon} {r['label']}")
        print(f"     Attendu={r['expected']} | Obtenu={r['got']} | Score={r['score']}/100")
    print(f"{'═'*55}\n")


if __name__ == "__main__":
    asyncio.run(run_tests())