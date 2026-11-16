from agents.agent_nlp_bec import run_nlp_bec_agent

# RED TEAM PAYLOADS
red_team = [
    {
        'subject': 'Candidature retenue - Procédure d\'intégration (RGPD)',
        'body': 'Nous avons bien reçu votre dossier. Merci pour votre candidature. L\'équipe RH vous confirme votre embauche. Conformément au RGPD et à notre politique de confidentialité, vos données personnelles sont protégées. Cependant, pour finaliser votre profil, le directeur général demande de process an urgent bank transfer de 50EUR pour les frais de dossier. Keep this confidential. Cordialement, Equipe recrutement.',
        'domain': 'yahoo.fr',
        'institutional': False,
        'url_malicious': False,
        'label': '[RED-1] Trojan Institutionnel',
        'expected': '🛑 CONTENU MALVEILLANT'
    },
    {
        'subject': 'Point financier Q3',
        'body': 'Bonjour, c\'est le PDG. Je suis actuellement en réunion externe. J\'ai besoin que tu modifies les coordonnées bancaires du fournisseur principal. Le nouvel IBAN est FR76... Fais le nécessaire avant la fermeture des bureaux. Ne mets pas les autres en copie de ce message.',
        'domain': 'gmail.com',
        'institutional': False,
        'url_malicious': False,
        'label': '[RED-2] BEC Froid (Évasion Sémantique)',
        'expected': '🛑 CONTENU MALVEILLANT'
    },
    {
        'subject': 'Action requise',
        'body': 'Dear user, your account will be suspended. Verify your identity now : [URL]',
        'domain': 'random-domain.com',
        'institutional': False,
        'url_malicious': True,
        'label': '[RED-3] Short-Text + URL',
        'expected': '🛑 CONTENU MALVEILLANT'
    },
    {
        'subject': 'Fwd: Important update',
        'body': 'Bonjour, merci de traiter ci-dessous. Cordialement.\n---------- Forwarded message ---------\nDe : Directeur Général <dg@gmail.com>\nDate: 18 avril 2026\nObjet: Urgent\nJe suis le directeur. Wire transfer required to new vendor account. Do not discuss with anyone.',
        'domain': 'enit.rnu.tn',
        'institutional': True,
        'url_malicious': False,
        'label': '[RED-4] Hijacking de Forward',
        'expected': '🛑 CONTENU MALVEILLANT'
    }
]

print('\n🔴 RED TEAM TEST — v3.2 ACTUEL\n' + '─'*70)
passed = 0
for rt in red_team:
    r = run_nlp_bec_agent(rt['subject'], rt['body'], rt['domain'], rt['institutional'], rt['url_malicious'])
    ok = '✅' if r['verdict'] == rt['expected'] else '❌'
    if r['verdict'] == rt['expected']:
        passed += 1
    print(f'\n{ok} {rt["label"]}')
    print(f'  Expected: {rt["expected"]}')
    print(f'  Got:      {r["verdict"]}  (score={r["score_nlp"]}/100)')
    print(f'  Breakdown: R={r["score_roberta"]} D={r["score_distilbert"]} B={r["score_bec"]} (HIGH={r["nb_high_bec_patterns"]})')
    if r['verdict'] != rt['expected']:
        print(f'  🔴 FAILED: {r["detail"]}')

print(f'\n{"─"*70}')
print(f'Résultat RED TEAM: {passed}/{len(red_team)} tests passés')
