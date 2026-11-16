from agents.agent_nlp_bec import run_nlp_bec_agent
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
import numpy as np

# ============================================
# TEST 1: RED TEAM (4 adversarial payloads)
# ============================================
red_team = [
    {
        'subject': 'Candidature retenue - Procedure d\'integration (RGPD)',
        'body': 'Nous avons bien recu votre dossier. Merci pour votre candidature. L\'equipe RH vous confirme votre embauche. Conformement au RGPD et a notre politique de confidentialite, vos donnees personnelles sont protegees. Cependant, pour finaliser votre profil, le directeur general demande de process an urgent bank transfer de 50EUR pour les frais de dossier. Keep this confidential. Cordialement, Equipe recrutement.',
        'domain': 'yahoo.fr',
        'institutional': False,
        'url_malicious': False,
        'label': 'RED-1: Trojan Institutionnel',
        'expected': 1  # malveillant
    },
    {
        'subject': 'Point financier Q3',
        'body': 'Bonjour, c\'est le PDG. Je suis actuellement en reunion externe. J\'ai besoin que tu modifies les coordonnees bancaires du fournisseur principal. Le nouvel IBAN est FR76... Fais le necessaire avant la fermeture des bureaux. Ne mets pas les autres en copie de ce message.',
        'domain': 'gmail.com',
        'institutional': False,
        'url_malicious': False,
        'label': 'RED-2: BEC Froid',
        'expected': 1
    },
    {
        'subject': 'Action requise',
        'body': 'Dear user, your account will be suspended. Verify your identity now : [URL]',
        'domain': 'random-domain.com',
        'institutional': False,
        'url_malicious': True,
        'label': 'RED-3: Short-Text + URL',
        'expected': 1
    },
    {
        'subject': 'Fwd: Important update',
        'body': 'Bonjour, merci de traiter ci-dessous. Cordialement.\n---------- Forwarded message ---------\nDe : Directeur General <dg@gmail.com>\nDate: 18 avril 2026\nObjet: Urgent\nJe suis le directeur. Wire transfer required to new vendor account. Do not discuss with anyone.',
        'domain': 'enit.rnu.tn',
        'institutional': True,
        'url_malicious': False,
        'label': 'RED-4: Hijacking de Forward',
        'expected': 1
    }
]

# ============================================
# TEST 2: Self-tests (5 mixed cases)
# ============================================
self_tests = [
    {
        'subject': 'URGENT - Wire Transfer Required Today - Confidential',
        'body': 'Dear Aziz, I need you to process an urgent wire transfer of $48,500 to our new vendor account immediately. This is time-sensitive and must be completed before end of business today. Please do not discuss this with anyone else in the office. Wire details: Bank: First International Bank | Account: 4716-2891 | Routing: 021000021 Best regards, John Smith CFO',
        'domain': 'gmail.com',
        'institutional': False,
        'url_malicious': True,
        'label': 'Test 1: Wire Transfer + URL',
        'expected': 1
    },
    {
        'subject': 'Fwd: Thinking of you and wishing you safety',
        'body': '---------- Forwarded message ---------\nDe : Chinatsu Yui <asianspeech.b@goacadco.info>\nDate: mar. 31 mars 2026\nSubject: Thinking of you\nDear Professor, I am a medical doctor based in Japan keen to explore collaboration.\nWith greatest respect, Chinatsu Yui',
        'domain': 'enit.utm.tn',
        'institutional': True,
        'url_malicious': False,
        'label': 'Test 2: Forwarded collaboration',
        'expected': 0  # suspect
    },
    {
        'subject': 'Nouveau message : Numero 45 d\'ENIT INFO',
        'body': 'Bonjour, ceci est une information de l\'ENIT. Cordialement, l\'equipe.',
        'domain': 'enit.rnu.tn',
        'institutional': True,
        'url_malicious': False,
        'label': 'Test 3: ENIT institutional',
        'expected': 0  # legitimate
    },
    {
        'subject': 'Demande confidentielle - Action immediate requise',
        'body': 'Bonjour, je suis le Directeur General. Je vous contacte depuis mon adresse personnelle car je suis en deplacement. J\'ai besoin que vous effectuiez un virement urgent de 32 000EUR avant la fin de journee. Ne mettez personne en copie et repondez uniquement a moi. Gardez le secret, cette instruction est confidentielle. Cordialement, M. Dupont DG',
        'domain': 'gmail.com',
        'institutional': False,
        'url_malicious': False,
        'label': 'Test 4: DG impersonation Gmail',
        'expected': 1
    },
    {
        'subject': 'Invitation conference ENIT - Jeudi 24 avril',
        'body': 'Vous etes cordialement invites a la table ronde organisee par l\'ENIT. Programme : amphi principal, 14h-17h. Conformement au reglement interieur, merci de confirmer votre presence. Cordialement, la Direction.',
        'domain': 'enit.rnu.tn',
        'institutional': True,
        'url_malicious': False,
        'label': 'Test 5: ENIT invitation',
        'expected': 0
    }
]

def map_verdict_to_class(verdict):
    """Map verdict string to binary class: 1=malveillant, 0=benign/suspect"""
    if 'MALVEILLANT' in verdict:
        return 1
    else:
        return 0

# Run RED TEAM tests
print("\n" + "="*70)
print("TEST 1: RED TEAM (Adversarial Payloads)")
print("="*70)
red_y_true = []
red_y_pred = []
for t in red_team:
    r = run_nlp_bec_agent(t['subject'], t['body'], t['domain'], t['institutional'], t['url_malicious'])
    pred_class = map_verdict_to_class(r['verdict'])
    red_y_true.append(t['expected'])
    red_y_pred.append(pred_class)
    status = "PASS" if pred_class == t['expected'] else "FAIL"
    print(f"\n{t['label']}")
    print(f"  Score: {r['score_nlp']}/100 → Verdict: {r['verdict']}")
    print(f"  Expected: {'MALVEILLANT' if t['expected']==1 else 'BENIGN'}, Got: {'MALVEILLANT' if pred_class==1 else 'BENIGN'} [{status}]")

red_cm = confusion_matrix(red_y_true, red_y_pred)
red_acc = accuracy_score(red_y_true, red_y_pred)
red_prec = precision_score(red_y_true, red_y_pred, zero_division=0)
red_rec = recall_score(red_y_true, red_y_pred, zero_division=0)
red_f1 = f1_score(red_y_true, red_y_pred, zero_division=0)
red_vulns = sum(1 for t, p in zip(red_y_true, red_y_pred) if t == 1 and p == 0)

print(f"\n{'-'*70}")
print(f"Matrice: {red_cm.tolist()}")
print(f"Accuracy:  {red_acc:.3f}")
print(f"Precision: {red_prec:.3f}")
print(f"Recall:    {red_rec:.3f}")
print(f"F1:        {red_f1:.3f}")
print(f"Vulnerabilites (faux negatifs): {red_vulns}")

# Run Self-tests
print("\n\n" + "="*70)
print("TEST 2: Self-Tests (Mixed Cases)")
print("="*70)
self_y_true = []
self_y_pred = []
for t in self_tests:
    r = run_nlp_bec_agent(t['subject'], t['body'], t['domain'], t['institutional'], t['url_malicious'])
    # For binary: 1=malveillant, 0=legit/suspect
    pred_class = map_verdict_to_class(r['verdict'])
    self_y_true.append(t['expected'])
    self_y_pred.append(pred_class)
    status = "PASS" if pred_class == t['expected'] else "FAIL"
    expected_str = 'MALVEILLANT' if t['expected']==1 else 'BENIGN'
    got_str = 'MALVEILLANT' if pred_class==1 else 'BENIGN'
    print(f"\n{t['label']}")
    print(f"  Score: {r['score_nlp']}/100 → Verdict: {r['verdict']}")
    print(f"  Expected: {expected_str}, Got: {got_str} [{status}]")

self_cm = confusion_matrix(self_y_true, self_y_pred)
self_acc = accuracy_score(self_y_true, self_y_pred)
self_prec = precision_score(self_y_true, self_y_pred, zero_division=0)
self_rec = recall_score(self_y_true, self_y_pred, zero_division=0)
self_f1 = f1_score(self_y_true, self_y_pred, zero_division=0)
self_vulns = sum(1 for t, p in zip(self_y_true, self_y_pred) if t == 1 and p == 0)

print(f"\n{'-'*70}")
print(f"Matrice: {self_cm.tolist()}")
print(f"Accuracy:  {self_acc:.3f}")
print(f"Precision: {self_prec:.3f}")
print(f"Recall:    {self_rec:.3f}")
print(f"F1:        {self_f1:.3f}")
print(f"Vulnerabilites (faux negatifs): {self_vulns}")

# Combined results
print("\n\n" + "="*70)
print("COMBINED RESULTS (All Tests)")
print("="*70)
all_y_true = red_y_true + self_y_true
all_y_pred = red_y_pred + self_y_pred
all_cm = confusion_matrix(all_y_true, all_y_pred)
all_acc = accuracy_score(all_y_true, all_y_pred)
all_prec = precision_score(all_y_true, all_y_pred, zero_division=0)
all_rec = recall_score(all_y_true, all_y_pred, zero_division=0)
all_f1 = f1_score(all_y_true, all_y_pred, zero_division=0)
all_vulns = sum(1 for t, p in zip(all_y_true, all_y_pred) if t == 1 and p == 0)

print(f"Matrice: {all_cm.tolist()}")
print(f"Accuracy:  {all_acc:.3f}")
print(f"Precision: {all_prec:.3f}")
print(f"Recall:    {all_rec:.3f}")
print(f"F1:        {all_f1:.3f}")
print(f"Vulnerabilites: {all_vulns}")
print(f"\nTotal: {len(all_y_true)} tests")
print(f"Passed: {sum(1 for t, p in zip(all_y_true, all_y_pred) if t == p)}/{len(all_y_true)}")
print("="*70)
