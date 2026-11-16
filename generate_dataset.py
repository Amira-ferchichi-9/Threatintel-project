import pandas as pd
import re
import torch
from transformers import pipeline
from tqdm import tqdm

# ── Config ────────────────────────────────────────────────
INPUT_CSV  = "datasets/phishing_emails.csv"
OUTPUT_CSV = "datasets/threatintel_training_dataset.csv"
BATCH_SIZE = 32

# ── Chargement dataset ────────────────────────────────────
print("Chargement dataset...")
df = pd.read_csv(INPUT_CSV)
df = df[['Email Text', 'Email Type']].dropna()
df['label'] = df['Email Type'].apply(
    lambda x: 2 if x == 'Phishing Email' else 0
)
print(f"  {len(df)} emails chargés")
print(f"  Safe: {(df.label==0).sum()} | Phishing: {(df.label==2).sum()}")

# ── Agent AUTH simulé (analyse headers dans le texte) ─────
LEGIT_DOMAINS = {
    'gmail.com','yahoo.com','hotmail.com','outlook.com',
    'microsoft.com','apple.com','amazon.com','google.com',
    'linkedin.com','paypal.com','enron.com','hp.com',
}
PHISHING_PATTERNS = [
    r'paypal.*@(?!paypal\.com)',
    r'ebay.*@(?!ebay\.com)',
    r'amazon.*@(?!amazon\.com)',
    r'microsoft.*@(?!microsoft\.com)',
    r'apple.*@(?!apple\.com)',
    r'verify.*@', r'secure.*@', r'update.*account.*@',
    r'noreply.*@\d+\.\d+\.\d+',
]

def score_auth(text: str) -> int:
    score = 50
    text_lower = text.lower()[:500]

    # Cherche un From dans le texte
    from_match = re.search(r'from\s*:\s*(.+?)[\n\r]', text_lower)
    from_field  = from_match.group(1) if from_match else ''

    reply_match = re.search(r'reply-to\s*:\s*(.+?)[\n\r]', text_lower)
    reply_field  = reply_match.group(1) if reply_match else ''

    # Domaine légitime
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
    if reply_field and from_field:
        fd = re.search(r'@([\w.-]+)', from_field)
        rd = re.search(r'@([\w.-]+)', reply_field)
        if fd and rd and fd.group(1) != rd.group(1):
            score -= 25

    # Patterns phishing
    for p in PHISHING_PATTERNS:
        if re.search(p, from_field):
            score -= 30
            break

    # IP dans from
    if re.search(r'@\d{1,3}\.\d{1,3}', from_field):
        score -= 35

    # Mots urgence dans sujet
    subj = re.search(r'subject\s*:\s*(.+?)[\n\r]', text_lower)
    if subj:
        urgency = ['urgent','verify','suspend','confirm','click','winner','free']
        if any(w in subj.group(1) for w in urgency):
            score -= 15

    return max(0, min(100, score))

# ── Agent URL simulé (heuristiques) ──────────────────────
SUSP_TLDS    = {'.tk','.ml','.ga','.cf','.gq','.ru','.xyz','.top','.click'}
PHISH_KW     = ['verify','secure','update','confirm','account','login',
                'signin','banking','password','webscr','suspended','validate']
LEGIT_URLS   = {'google.com','microsoft.com','apple.com','amazon.com',
                'linkedin.com','github.com','wikipedia.org','paypal.com'}

def score_url(text: str) -> int:
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
    if not urls:
        return 0
    max_score = 0
    for url in urls[:10]:
        s = 0
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
        s += min(hits * 15, 45)
        if len(domain.split('.')) > 4:
            s += 20
        if len(url) > 200:
            s += 15
        if url_l.startswith('http://') and any(k in url_l for k in ['login','verify','account']):
            s += 25
        max_score = max(max_score, s)
    return max(0, min(100, max_score))

# ── Agent NLP — DistilBERT GPU ────────────────────────────
print("\nChargement DistilBERT (GPU)...")
device = 0 if torch.cuda.is_available() else -1
print(f"  Device : {'GPU RTX 3050' if device==0 else 'CPU'}")

nlp = pipeline(
    "text-classification",
    model="Amira789/distilbert-phishing-pfa2",
    device=device,
    truncation=True,
    max_length=512,
)

# Probe pour détecter le label phishing
probe = nlp("Click here to verify your PayPal account immediately")[0]
PHISHING_LABEL = probe['label']
print(f"  Label phishing détecté : {PHISHING_LABEL}")
print(f"  Probe score : {probe['score']:.3f}")

def nlp_score_from_result(result):
    r     = result if isinstance(result, dict) else result[0]
    label = r['label']
    score = r['score']
    if label == PHISHING_LABEL:
        if score >= 0.90: return int(score * 99)
        elif score >= 0.75: return int(score * 80)
        else: return int(score * 40)
    else:
        return int((1 - score) * 30)

# ── Feature extraction ────────────────────────────────────
print(f"\nExtraction features sur {len(df)} emails...")
texts      = df['Email Text'].fillna('').tolist()
labels     = df['label'].tolist()

auth_scores = []
url_scores  = []
nlp_scores  = []

# AUTH + URL (CPU, rapide)
print("  AUTH + URL...")
for text in tqdm(texts, desc="  AUTH+URL"):
    auth_scores.append(score_auth(text))
    url_scores.append(score_url(text))

# NLP en batches GPU
print("  NLP (batches GPU)...")
for i in tqdm(range(0, len(texts), BATCH_SIZE), desc="  NLP"):
    batch   = [t[:512] for t in texts[i:i+BATCH_SIZE]]
    try:
        results = nlp(batch, truncation=True, batch_size=BATCH_SIZE)
        for res in results:
            nlp_scores.append(nlp_score_from_result(res))
    except Exception as e:
        print(f"  Batch erreur: {e}")
        nlp_scores.extend([20] * len(batch))

# ── Assemblage + export ───────────────────────────────────
print("\nAssemblage dataset...")
out = pd.DataFrame({
    'auth_score':    auth_scores,
    'url_score':     url_scores,
    'nlp_score':     nlp_scores,
    'sandbox_score': 0,
    'label':         labels,
})

# Génère classe SUSPECT (label=1) depuis cas borderline
suspect_mask = (
    ((out.label == 0) & (out.nlp_score >= 35) & (out.nlp_score <= 65)) |
    ((out.label == 2) & (out.auth_score >= 30) & (out.nlp_score < 70))
)
out.loc[suspect_mask, 'label'] = 1

print(f"\nDistribution finale :")
print(out['label'].value_counts().rename({0:'Sain',1:'Suspect',2:'Danger'}))

out.to_csv(OUTPUT_CSV, index=False)
print(f"\nDataset sauvegardé : {OUTPUT_CSV}")
print(f"Shape : {out.shape}")

# ── Test RF rapide ────────────────────────────────────────
print("\nTest Random Forest...")
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

X = out[['auth_score','url_score','nlp_score','sandbox_score']].values
y = out['label'].values

X_tr, X_te, y_tr, y_te = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
sc   = StandardScaler()
X_tr = sc.fit_transform(X_tr)
X_te = sc.transform(X_te)

rf = RandomForestClassifier(
    n_estimators=200, max_depth=8,
    class_weight='balanced', random_state=42
)
rf.fit(X_tr, y_tr)
print(classification_report(y_te, rf.predict(X_te),
      target_names=['Sain','Suspect','Danger']))

print("\nFEATURE IMPORTANCES :")
for name, imp in zip(['auth','url','nlp','sandbox'], rf.feature_importances_):
    print(f"  {name:8s} : {imp*100:.1f}%")