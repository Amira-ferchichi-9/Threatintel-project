import os
import re
import random
import pandas as pd
import torch
from email import policy
from email.parser import BytesParser
from transformers import pipeline
from tqdm import tqdm
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# ── Config ────────────────────────────────────────────────
DATASETS_DIR  = "datasets"
OUTPUT_CSV    = "datasets/threatintel_training_dataset_v2.csv"
BATCH_SIZE    = 32
RANDOM_SEED   = 42
random.seed(RANDOM_SEED)

# ── Dossiers SpamAssassin ─────────────────────────────────
HAM_DIRS  = [
    os.path.join(DATASETS_DIR, "easy_ham"),
    os.path.join(DATASETS_DIR, "easy_ham_2"),
]
SPAM_DIR  = os.path.join(DATASETS_DIR, "spam")

# ── Parser email ──────────────────────────────────────────
def parse_email_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        from_field   = str(msg.get('From', ''))
        reply_to     = str(msg.get('Reply-To', ''))
        received     = str(msg.get('Received', ''))
        subject      = str(msg.get('Subject', ''))
        body         = _get_body(msg)
        urls         = _extract_urls(str(msg))
        return {
            'from':     from_field,
            'reply_to': reply_to,
            'received': received,
            'subject':  subject,
            'body':     body,
            'urls':     urls,
        }
    except Exception:
        return None

def _get_body(msg):
    body = ''
    try:
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == 'text/plain':
                    body += str(part.get_content() or '')
                elif ct == 'text/html' and not body:
                    html = str(part.get_content() or '')
                    body += re.sub(r'<[^>]+>', ' ', html)
        else:
            body = str(msg.get_content() or '')
    except Exception:
        pass
    return body[:2000].strip()

def _extract_urls(raw_text):
    return re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', raw_text)[:20]

# ── Agent AUTH (vrais headers) ────────────────────────────
LEGIT_DOMAINS = {
    'gmail.com','yahoo.com','hotmail.com','outlook.com',
    'microsoft.com','apple.com','amazon.com','google.com',
    'linkedin.com','paypal.com','enron.com','hp.com',
    'ibm.com','oracle.com','sun.com','mozilla.org',
}
PHISHING_PATTERNS = [
    r'paypal.*@(?!paypal\.com)',
    r'ebay.*@(?!ebay\.com)',
    r'amazon.*@(?!amazon\.com)',
    r'microsoft.*@(?!microsoft\.com)',
    r'apple.*@(?!apple\.com)',
    r'verify.*@', r'secure.*@',
    r'noreply.*@\d+\.\d+\.\d+',
]

def score_auth(email_data: dict) -> int:
    score      = 50
    from_field = email_data.get('from', '').lower()
    reply_to   = email_data.get('reply_to', '').lower()
    received   = email_data.get('received', '').lower()
    subject    = email_data.get('subject', '').lower()

    # Domaine From
    dom = re.search(r'@([\w.-]+)', from_field)
    if dom and dom.group(1) in LEGIT_DOMAINS:
        score += 25

    # From bien formé
    if re.search(r'.+@[\w.-]+\.[a-z]{2,}', from_field):
        score += 10
    else:
        score -= 15

    # Display name spoofing
    disp = re.match(r'^(.+?)\s*<(.+?)>', from_field)
    if disp:
        dname = disp.group(1).strip()
        adom  = re.search(r'@([\w.-]+)', disp.group(2))
        if adom:
            for lg in LEGIT_DOMAINS:
                brand = lg.split('.')[0]
                if brand in dname and adom.group(1) != lg:
                    score -= 40
                    break

    # Reply-To mismatch
    if reply_to and from_field:
        fd = re.search(r'@([\w.-]+)', from_field)
        rd = re.search(r'@([\w.-]+)', reply_to)
        if fd and rd and fd.group(1) != rd.group(1):
            score -= 25

    # Patterns phishing
    for p in PHISHING_PATTERNS:
        if re.search(p, from_field):
            score -= 30
            break

    # IP dans From
    if re.search(r'@\d{1,3}\.\d{1,3}', from_field):
        score -= 35

    # Received headers présents
    if received and len(received) > 20:
        score += 5

    # Urgence dans sujet
    urgency = ['urgent','verify','suspend','confirm','winner','free','click']
    if any(w in subject for w in urgency):
        score -= 15

    # From vide
    if not from_field.strip():
        score -= 30

    return max(0, min(100, score))

# ── Agent URL (vrais URLs extraites) ─────────────────────
SUSP_TLDS  = {'.tk','.ml','.ga','.cf','.gq','.ru','.xyz',
              '.top','.click','.link','.work','.loan'}
PHISH_KW   = ['verify','secure','update','confirm','account',
              'login','signin','banking','password','webscr',
              'suspended','validate','unlock','credential']
LEGIT_URLS = {'google.com','microsoft.com','apple.com','amazon.com',
              'linkedin.com','github.com','wikipedia.org','paypal.com',
              'yahoo.com','mozilla.org','sourceforge.net'}

def score_url(urls: list) -> int:
    if not urls:
        return 0
    max_score = 0
    for url in urls[:10]:
        s     = 0
        url_l = url.lower()
        try:
            domain = re.search(r'https?://([^/]+)', url_l)
            domain = domain.group(1) if domain else ''
        except Exception:
            continue
        base = '.'.join(domain.split('.')[-2:])
        if base in LEGIT_URLS:
            continue
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            s += 70
        for tld in SUSP_TLDS:
            if domain.endswith(tld):
                s += 40
                break
        hits = sum(1 for kw in PHISH_KW if kw in url_l)
        s   += min(hits * 15, 45)
        if len(domain.split('.')) > 4:
            s += 20
        if len(url) > 200:
            s += 15
        if url_l.startswith('http://') and any(
            k in url_l for k in ['login','verify','account','secure']
        ):
            s += 25
        max_score = max(max_score, s)
    return max(0, min(100, max_score))

# ── Chargement NLP ────────────────────────────────────────
print("Chargement DistilBERT sur GPU...")
device = 0 if torch.cuda.is_available() else -1
print(f"  Device : {'RTX 3050 GPU' if device==0 else 'CPU'}")

nlp = pipeline(
    "text-classification",
    model="Amira789/distilbert-phishing-pfa2",
    device=device,
    truncation=True,
    max_length=512,
)
probe = nlp("Click here to verify your PayPal account immediately")[0]
PHISHING_LABEL = probe['label']
print(f"  Label phishing : {PHISHING_LABEL} | Probe score : {probe['score']:.3f}")

def nlp_batch(texts):
    results = []
    for i in range(0, len(texts), BATCH_SIZE):
        batch = [t[:512] for t in texts[i:i+BATCH_SIZE]]
        try:
            preds = nlp(batch, truncation=True, batch_size=BATCH_SIZE)
            for res in preds:
                r     = res if isinstance(res, dict) else res[0]
                label = r['label']
                score = r['score']
                if label == PHISHING_LABEL:
                    if score >= 0.90:   results.append(int(score * 99))
                    elif score >= 0.75: results.append(int(score * 80))
                    else:               results.append(int(score * 40))
                else:
                    results.append(int((1 - score) * 30))
        except Exception as e:
            print(f"  Batch erreur: {e}")
            results.extend([20] * len(batch))
    return results

# ── PARTIE 1 : SpamAssassin (vrais headers) ───────────────
print("\n=== PARTIE 1 : SpamAssassin (vrais headers) ===")

# Ham
print("Chargement ham emails...")
ham_emails = []
for ham_dir in HAM_DIRS:
    files = [f for f in os.listdir(ham_dir)
             if not f.startswith('.') and not f.endswith('.txt')]
    for fname in files:
        parsed = parse_email_file(os.path.join(ham_dir, fname))
        if parsed and parsed['body']:
            ham_emails.append(parsed)
random.shuffle(ham_emails)
print(f"  {len(ham_emails)} ham emails parsés")

# Spam
print("Chargement spam emails...")
spam_emails = []
files = [f for f in os.listdir(SPAM_DIR)
         if not f.startswith('.') and not f.endswith('.txt')]
for fname in files:
    parsed = parse_email_file(os.path.join(SPAM_DIR, fname))
    if parsed and parsed['body']:
        spam_emails.append(parsed)
print(f"  {len(spam_emails)} spam emails parsés")

# Features SpamAssassin
print("\nExtraction features SpamAssassin...")
sa_rows = []

all_sa = [(e, 0) for e in ham_emails] + [(e, 2) for e in spam_emails]
random.shuffle(all_sa)

sa_texts     = [e['body'] for e, _ in all_sa]
sa_auth      = [score_auth(e) for e, _ in tqdm(all_sa, desc="  AUTH")]
sa_url       = [score_url(e['urls']) for e, _ in tqdm(all_sa, desc="  URL")]
print("  NLP (GPU batches)...")
sa_nlp       = nlp_batch(sa_texts)

for i, (email_data, label) in enumerate(all_sa):
    sa_rows.append({
        'auth_score':    sa_auth[i],
        'url_score':     sa_url[i],
        'nlp_score':     sa_nlp[i] if i < len(sa_nlp) else 20,
        'sandbox_score': 0,
        'label':         label,
        'source':        'spamassassin',
    })

print(f"  SpamAssassin : {len(sa_rows)} exemples générés")

# ── PARTIE 2 : zefang-liu (NLP fort) ─────────────────────
print("\n=== PARTIE 2 : zefang-liu phishing dataset (NLP) ===")
df_zef = pd.read_csv(os.path.join(DATASETS_DIR, "phishing_emails.csv"))
df_zef = df_zef[['Email Text','Email Type']].dropna()

zef_texts  = df_zef['Email Text'].tolist()
zef_labels = df_zef['Email Type'].apply(
    lambda x: 2 if x == 'Phishing Email' else 0
).tolist()

print("  NLP (GPU batches)...")
zef_nlp = nlp_batch(zef_texts)

zef_rows = []
for i, (text, label) in enumerate(zip(zef_texts, zef_labels)):
    # Auth + URL simulés avec bruit réaliste
    # (pas de vrais headers dans ce dataset)
    if label == 0:  # sain
        auth = random.randint(55, 100)
        url  = random.randint(0, 15)
    else:           # phishing
        auth = random.randint(0, 40)
        url  = random.randint(0, 80)

    zef_rows.append({
        'auth_score':    auth,
        'url_score':     url,
        'nlp_score':     zef_nlp[i] if i < len(zef_nlp) else 20,
        'sandbox_score': 0,
        'label':         label,
        'source':        'zefang',
    })

print(f"  zefang-liu : {len(zef_rows)} exemples générés")

# ── FUSION ────────────────────────────────────────────────
print("\n=== FUSION des deux datasets ===")
all_rows = sa_rows + zef_rows
random.shuffle(all_rows)

out = pd.DataFrame(all_rows)

# Génère classe SUSPECT depuis cas borderline
suspect_mask = (
    ((out.label == 0) & (out.nlp_score >= 35) & (out.nlp_score <= 65)) |
    ((out.label == 2) & (out.auth_score >= 35) & (out.nlp_score < 65))
)
out.loc[suspect_mask, 'label'] = 1

print(f"\nDistribution finale :")
counts = out['label'].value_counts().sort_index()
print(f"  Sain    (0) : {counts.get(0, 0)}")
print(f"  Suspect (1) : {counts.get(1, 0)}")
print(f"  Danger  (2) : {counts.get(2, 0)}")
print(f"  TOTAL       : {len(out)}")

# Export sans colonne source
out_final = out[['auth_score','url_score','nlp_score','sandbox_score','label']]
out_final.to_csv(OUTPUT_CSV, index=False)
print(f"\nDataset sauvegardé : {OUTPUT_CSV}")

# ── TEST RF ───────────────────────────────────────────────
print("\n=== TEST RANDOM FOREST ===")
X = out_final[['auth_score','url_score','nlp_score','sandbox_score']].values
y = out_final['label'].values

X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
sc   = StandardScaler()
X_tr = sc.fit_transform(X_tr)
X_te = sc.transform(X_te)

rf = RandomForestClassifier(
    n_estimators=200, max_depth=8,
    class_weight='balanced', random_state=42,
    min_samples_leaf=2,
)
rf.fit(X_tr, y_tr)

print(classification_report(
    y_te, rf.predict(X_te),
    target_names=['Sain','Suspect','Danger']
))

print("FEATURE IMPORTANCES :")
for name, imp in zip(['auth','url','nlp','sandbox'], rf.feature_importances_):
    print(f"  {name:8s} : {imp*100:.1f}%")