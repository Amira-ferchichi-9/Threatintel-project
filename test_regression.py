from agents.agent_nlp_bec import run_nlp_bec_agent

# Self-tests originaux (5 cas)
tests = [
    {
        "subject": "URGENT - Wire Transfer Required Today - Confidential",
        "body": "Dear Aziz, I need you to process an urgent wire transfer of $48,500 to our new vendor account immediately. This is time-sensitive and must be completed before end of business today. Please do not discuss this with anyone else in the office. Wire details: Bank: First International Bank | Account: 4716-2891 | Routing: 021000021 Best regards, John Smith CFO",
        "domain": "gmail.com",
        "institutional": False,
        "url_malicious": True,
        "expected": "MALVEILLANT",
        "label": "Test 1: Wire Transfer + URL",
    },
    {
        "subject": "Fwd: Thinking of you and wishing you safety",
        "body": "---------- Forwarded message ---------\nDe : Chinatsu Yui <asianspeech.b@goacadco.info>\nDate: mar. 31 mars 2026\nSubject: Thinking of you\nDear Professor, I am a medical doctor based in Japan keen to explore collaboration.\nWith greatest respect, Chinatsu Yui",
        "domain": "enit.utm.tn",
        "institutional": True,
        "url_malicious": False,
        "expected": "SUSPECT",
        "label": "Test 2: Forwarded collaboration",
    },
    {
        "subject": "Nouveau message : Numero 45 d'ENIT INFO",
        "body": "Bonjour, ceci est une information de l'ENIT. Cordialement, l'equipe.",
        "domain": "enit.rnu.tn",
        "institutional": True,
        "url_malicious": False,
        "expected": "SAIN",
        "label": "Test 3: ENIT institutional short",
    },
    {
        "subject": "Demande confidentielle - Action immediate requise",
        "body": "Bonjour, je suis le Directeur General. Je vous contacte depuis mon adresse personnelle car je suis en deplacement. J'ai besoin que vous effectuiez un virement urgent de 32 000EUR avant la fin de journee. Ne mettez personne en copie et repondez uniquement a moi. Gardez le secret, cette instruction est confidentielle. Cordialement, M. Dupont DG",
        "domain": "gmail.com",
        "institutional": False,
        "url_malicious": False,
        "expected": "MALVEILLANT",
        "label": "Test 4: DG impersonation Gmail",
    },
    {
        "subject": "Invitation conference ENIT - Jeudi 24 avril",
        "body": "Vous etes cordialement invites a la table ronde organisee par l'ENIT. Programme : amphi principal, 14h-17h. Conformement au reglement interieur, merci de confirmer votre presence. Cordialement, la Direction.",
        "domain": "enit.rnu.tn",
        "institutional": True,
        "url_malicious": False,
        "expected": "SAIN",
        "label": "Test 5: ENIT invitation",
    },
]

print("\nREGRESSION TEST - v3.2+ HARDENED\n" + "-"*70)
passed = 0
for t in tests:
    r = run_nlp_bec_agent(t["subject"], t["body"], t["domain"], t["institutional"], t["url_malicious"])
    verdict_short = "MALVEILLANT" if r["verdict"].startswith("CONTENT MALVEILLANT") or "MALVEILLANT" in r["verdict"] else ("SUSPECT" if "SUSPECT" in r["verdict"] else "SAIN")
    ok = "OK" if (t["expected"] == "MALVEILLANT" and "MALVEILLANT" in r["verdict"]) or (t["expected"] == "SUSPECT" and "SUSPECT" in r["verdict"]) or (t["expected"] == "SAIN" and r["verdict"].startswith("OK")) else "FAIL"
    if ok == "OK":
        passed += 1
    print(f"\n{ok} {t['label']}")
    print(f"    Expected: {t['expected']}, Got: {verdict_short}, Score: {r['score_nlp']}/100")
    print(f"    Breakdown: R={r['score_roberta']} D={r['score_distilbert']} B={r['score_bec']} (HIGH={r['nb_high_bec_patterns']})")

print(f"\n{'-'*70}")
print(f"Regression Test Result: {passed}/{len(tests)} PASSED")
