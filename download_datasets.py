# download_datasets.py — v3 FIXED
import os
import glob
import pandas as pd

os.makedirs("data/raw", exist_ok=True)

from kaggle.api.kaggle_api_extended import KaggleApi
api = KaggleApi()
api.authenticate()
print("✓ Kaggle API authentifiée\n")


def download_and_extract(dataset: str, dest: str) -> list:
    print(f"  Téléchargement : {dataset}")
    api.dataset_download_files(dataset, path=dest, unzip=True, quiet=False)
    csvs = glob.glob(os.path.join(dest, "**/*.csv"), recursive=True)
    print(f"  Fichiers extraits : {[os.path.basename(c) for c in csvs]}")
    return csvs


# ════════════════════════════════════════════════════════════
# Dataset 1 — SMS Spam (colonnes v1=label, v2=text → inversées !)
# ════════════════════════════════════════════════════════════
print("━━━ Dataset 1 — SMS Spam ━━━")
try:
    csvs = download_and_extract("uciml/sms-spam-collection-dataset", "data/raw/sms")
    df = pd.read_csv(csvs[0], encoding='latin-1')
    print(f"  Colonnes brutes : {df.columns.tolist()}")
    # v1 = ham/spam, v2 = texte du SMS
    df = df.rename(columns={'v1': 'label_raw', 'v2': 'text'})
    df['label'] = df['label_raw'].map({'ham': 0, 'spam': 1})
    df = df[['text', 'label']].dropna()
    df['label'] = df['label'].astype(int)
    df['text'] = df['text'].astype(str).str.strip()
    df = df[df['text'].str.len() > 10]
    df.to_csv("data/sms_spam.csv", index=False)
    print(f"  ✓ {len(df)} lignes | safe={sum(df.label==0)} | spam={sum(df.label==1)}\n")
except Exception as e:
    print(f"  ✗ {e}\n")


# ════════════════════════════════════════════════════════════
# Dataset 2 — Email Spam (balaka18) — format bag-of-words, pas de colonne texte
# On skippe ce dataset et on prend un meilleur remplaçant
# ════════════════════════════════════════════════════════════
print("━━━ Dataset 2 — Email Spam (ManishKumar) ━━━")
try:
    csvs = download_and_extract("purusinghvi/email-spam-classification", "data/raw/email_spam2")
    df = pd.read_csv(csvs[0])
    print(f"  Colonnes : {df.columns.tolist()}")
    print(f"  Head : {df.head(2)}")
    col_text  = [c for c in df.columns if any(k in c.lower() for k in ['text','body','message','email','subject'])][0]
    col_label = [c for c in df.columns if any(k in c.lower() for k in ['label','spam','class','category'])][0]
    df = df.rename(columns={col_text: 'text', col_label: 'label'})
    if df['label'].dtype == object:
        df['label'] = df['label'].apply(lambda x: 1 if 'spam' in str(x).lower() else 0)
    df = df[['text', 'label']].dropna()
    df['label'] = df['label'].astype(int)
    df['text'] = df['text'].astype(str).str.strip()
    df = df[df['text'].str.len() > 10]
    df.to_csv("data/email_spam2.csv", index=False)
    print(f"  ✓ {len(df)} lignes | safe={sum(df.label==0)} | spam={sum(df.label==1)}\n")
except Exception as e:
    print(f"  ✗ {e}\n")


# ════════════════════════════════════════════════════════════
# Dataset 3 — Phishing Emails (naserabdullahalam) — DÉJÀ OK, on re-sauvegarde
# ════════════════════════════════════════════════════════════
print("━━━ Dataset 3 — Phishing Emails (naserabdullahalam) — déjà téléchargé ━━━")
try:
    # Fichier déjà dans data/raw/phishing/
    csv_path = "data/raw/phishing/phishing_email.csv"
    df = pd.read_csv(csv_path)
    print(f"  Colonnes : {df.columns.tolist()}")
    df = df.rename(columns={'text_combined': 'text'})
    df = df[['text', 'label']].dropna()
    df['label'] = df['label'].astype(int)
    df['text'] = df['text'].astype(str).str.strip()
    df = df[df['text'].str.len() > 10]
    df.to_csv("data/phishing_emails.csv", index=False)
    print(f"  ✓ {len(df)} lignes | safe={sum(df.label==0)} | phishing={sum(df.label==1)}\n")
except Exception as e:
    print(f"  ✗ {e}\n")


# ════════════════════════════════════════════════════════════
# Dataset 4 — Phishing Emails 2 (subhajournal) — label string à mapper
# ════════════════════════════════════════════════════════════
print("━━━ Dataset 4 — Phishing Emails 2 (subhajournal) — déjà téléchargé ━━━")
try:
    csv_path = "data/raw/phishing2/Phishing_Email.csv"
    df = pd.read_csv(csv_path)
    print(f"  Colonnes : {df.columns.tolist()}")
    print(f"  Valeurs label : {df['Email Type'].unique()}")
    df = df.rename(columns={'Email Text': 'text', 'Email Type': 'label'})
    # "Safe Email" → 0, "Phishing Email" → 1
    df['label'] = df['label'].map({'Safe Email': 0, 'Phishing Email': 1})
    df = df[['text', 'label']].dropna()
    df['label'] = df['label'].astype(int)
    df['text'] = df['text'].astype(str).str.strip()
    df = df[df['text'].str.len() > 10]
    df.to_csv("data/phishing_emails2.csv", index=False)
    print(f"  ✓ {len(df)} lignes | safe={sum(df.label==0)} | phishing={sum(df.label==1)}\n")
except Exception as e:
    print(f"  ✗ {e}\n")


# ════════════════════════════════════════════════════════════
# Résumé
# ════════════════════════════════════════════════════════════
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
total = 0
for f in sorted(glob.glob("data/*.csv")):
    try:
        tmp = pd.read_csv(f)
        n   = len(tmp)
        total += n
        s0  = sum(tmp.label == 0)
        s1  = sum(tmp.label == 1)
        ratio = round(s1/n*100, 1) if n > 0 else 0
        print(f"  {os.path.basename(f):35s} {n:>6} lignes  safe={s0:>5} | threat={s1:>5} | threat%={ratio}%")
    except Exception as ex:
        print(f"  {f}: erreur — {ex}")
print(f"\n  TOTAL : {total} exemples")