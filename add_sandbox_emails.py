"""
add_sandbox_emails.py
═══════════════════════════════════════════════════════════════════════
Télécharge des malware samples depuis MalwareBazaar API,
les emballe dans de faux emails avec PJ, les passe par run_sandbox_agent,
et ajoute les lignes au dataset v4 → v5.csv

Usage :
  python add_sandbox_emails.py
  python add_sandbox_emails.py --limit 50
═══════════════════════════════════════════════════════════════════════
"""

import os
import sys
import time
import logging
import argparse
import requests
import zipfile
import io
import pandas as pd
from pathlib import Path
from tqdm import tqdm

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from agents.agent_auth    import run_auth_agent
from agents.agent_url     import run_url_agent
from agents.agent_nlp_bec import run_nlp_bec_agent
from agents.agent_sandbox import run_sandbox_agent

# ─────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────
BAZAAR_API_KEY = "2ee86c9e8230ba72ebd3f3a045dee007c9ffe4f4075183bd"
BAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD   = b"infected"

INPUT_CSV  = ROOT / "datasets" / "threatintel_training_dataset_v4.csv"
OUTPUT_CSV = ROOT / "datasets" / "threatintel_training_dataset_v5.csv"

# Types de malware Office/PDF ciblés
MALWARE_TAGS = ["doc", "docx", "xlsx", "pdf", "macro"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(ROOT / "add_sandbox_emails.log"), encoding="utf-8"),
    ]
)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
# MALWAREBAZAAR API
# ─────────────────────────────────────────────────────────────────────
def query_bazaar_samples(tag: str, limit: int = 50) -> list[dict]:
    """Récupère les métadonnées de samples par tag."""
    try:
        resp = requests.post(
            BAZAAR_API_URL,
            data={
                "query":    "get_taginfo",
                "tag":      tag,
                "limit":    limit,
                "api_key":  BAZAAR_API_KEY,
            },
            timeout=30
        )
        data = resp.json()
        if data.get("query_status") == "ok":
            return data.get("data", [])
        else:
            logger.warning(f"Bazaar tag '{tag}': {data.get('query_status')}")
            return []
    except Exception as e:
        logger.warning(f"Bazaar query error: {e}")
        return []


def download_sample(sha256: str) -> bytes | None:
    """Télécharge un sample ZIP protégé depuis MalwareBazaar."""
    try:
        resp = requests.post(
            BAZAAR_API_URL,
            data={
                "query":   "get_file",
                "sha256_hash": sha256,
                "api_key": BAZAAR_API_KEY,
            },
            timeout=60,
            stream=True
        )
        if resp.status_code == 200 and resp.headers.get("Content-Type") == "application/zip":
            return resp.content
        else:
            logger.debug(f"Download failed {sha256[:16]}: {resp.status_code}")
            return None
    except Exception as e:
        logger.debug(f"Download error {sha256[:16]}: {e}")
        return None


def extract_from_zip(zip_data: bytes, filename: str) -> bytes | None:
    """Extrait le fichier malveillant du ZIP protégé par 'infected'."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            z.setpassword(ZIP_PASSWORD)
            names = z.namelist()
            # Cherche le fichier qui correspond
            for name in names:
                if not name.endswith(".txt"):
                    return z.read(name)
            # Fallback : premier fichier
            if names:
                return z.read(names[0])
    except Exception as e:
        logger.debug(f"Extract error: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────
# CONSTRUCTION FAUX EMAIL AVEC PJ
# ─────────────────────────────────────────────────────────────────────
def build_fake_email(filename: str, file_data: bytes, malware_family: str) -> dict:
    """Construit un faux email avec PJ malveillante."""
    return {
        "sender":   "invoice@billing-system.net",
        "subject":  f"Invoice - {filename}",
        "to":       "victim@company.com",
        "cc":       "",
        "reply_to": "noreply@billing-system.net",
        "body":     f"Please find attached the invoice document. "
                    f"Open the attachment to review your payment details. "
                    f"Family: {malware_family}",
        "attachments": [{"name": filename, "data": file_data}]
    }


# ─────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────
def process_malware_email(fields: dict) -> dict | None:
    try:
        sender   = fields["sender"]
        subject  = fields["subject"]
        body     = fields["body"]
        attachments = fields["attachments"]

        # Agent AUTH
        auth_result = run_auth_agent(
            sender=sender, subject=subject,
            to_header=fields["to"], cc_header=fields["cc"],
            reply_to=fields["reply_to"],
        )
        score_auth = int(auth_result.get("score_auth", 0))

        # Agent URL
        url_result = run_url_agent(body_text=body, max_urls=2)
        score_url  = int(url_result.get("score_url", 0))

        # Agent NLP
        sender_domain = sender.split("@")[-1] if "@" in sender else ""
        nlp_result = run_nlp_bec_agent(
            subject=subject, body_text=body,
            sender_domain=sender_domain,
            institutional=False,
            url_malicious=score_url >= 50,
        )
        score_nlp = int(nlp_result.get("score_nlp", 0))

        # Agent SANDBOX — c'est le point clé
        score_provisoire = score_url + score_nlp
        sandbox_result = run_sandbox_agent(
            attachments=attachments,
            score_provisoire=score_provisoire,
        )
        score_sandbox = int(sandbox_result.get("score_sandbox", 0))

        # Label : Danger (2) si sandbox élevé, Suspect (1) sinon
        label = 2 if score_sandbox >= 40 else 1

        return {
            "auth_score":    score_auth,
            "url_score":     score_url,
            "nlp_score":     score_nlp,
            "sandbox_score": score_sandbox,
            "label":         label,
        }

    except Exception as e:
        logger.warning(f"Erreur: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=200, help="Nb samples à télécharger")
    args = parser.parse_args()

    logger.info("═══ Add Sandbox Emails ═══")

    # Charge v4
    df_v4 = pd.read_csv(INPUT_CSV)
    logger.info(f"Dataset v4 chargé : {len(df_v4)} lignes")

    # Collecte samples depuis MalwareBazaar
    all_samples = []
    per_tag = max(1, args.limit // len(MALWARE_TAGS))

    for tag in MALWARE_TAGS:
        samples = query_bazaar_samples(tag, limit=per_tag)
        logger.info(f"Tag '{tag}': {len(samples)} samples trouvés")
        all_samples.extend(samples)

    # Déduplique par sha256
    seen = set()
    unique_samples = []
    for s in all_samples:
        h = s.get("sha256_hash", "")
        if h and h not in seen:
            seen.add(h)
            unique_samples.append(s)

    unique_samples = unique_samples[:args.limit]
    logger.info(f"Total samples uniques : {len(unique_samples)}")

    results = []
    errors  = 0

    for sample in tqdm(unique_samples, desc="Malware samples", unit="sample"):
        sha256   = sample.get("sha256_hash", "")
        filename = sample.get("file_name", f"{sha256[:8]}.bin") or f"{sha256[:8]}.bin"
        family   = sample.get("signature", "unknown") or "unknown"

        # Filtre extensions supportées uniquement
        ext = os.path.splitext(filename)[1].lower()
        if ext not in [".pdf", ".docx", ".xlsx"]:
            # Essaie de deviner depuis le file_type
            file_type = sample.get("file_type", "").lower()
            if "pdf" in file_type:
                filename = f"{sha256[:8]}.pdf"
                ext = ".pdf"
            elif "docx" in file_type or "doc" in file_type:
                filename = f"{sha256[:8]}.docx"
                ext = ".docx"
            elif "xlsx" in file_type or "xls" in file_type:
                filename = f"{sha256[:8]}.xlsx"
                ext = ".xlsx"
            else:
                logger.debug(f"Extension ignorée : {filename}")
                continue

        # Télécharge
        zip_data = download_sample(sha256)
        if not zip_data:
            errors += 1
            continue

        # Extrait du ZIP
        file_data = extract_from_zip(zip_data, filename)
        if not file_data:
            errors += 1
            continue

        # Construit faux email + pipeline
        fields = build_fake_email(filename, file_data, family)
        row    = process_malware_email(fields)

        if row:
            results.append(row)
            logger.debug(f"✅ {filename} | sandbox={row['sandbox_score']} | label={row['label']}")
        else:
            errors += 1

        time.sleep(0.5)  # rate limit MalwareBazaar

    if not results:
        logger.error("Aucun résultat sandbox !")
        return

    # Stats sandbox
    df_new = pd.DataFrame(results)
    logger.info(f"\nSandbox scores distribution:")
    logger.info(f"  Mean : {df_new['sandbox_score'].mean():.1f}")
    logger.info(f"  Max  : {df_new['sandbox_score'].max()}")
    logger.info(f"  >40  : {(df_new['sandbox_score'] >= 40).sum()}")
    logger.info(f"  >75  : {(df_new['sandbox_score'] >= 75).sum()}")

    # Merge v4 + sandbox rows → v5
    df_v5 = pd.concat([df_v4, df_new], ignore_index=True)
    df_v5.to_csv(OUTPUT_CSV, index=False)

    logger.info(f"\n{'═'*55}")
    logger.info(f"Dataset v5 sauvegardé → {OUTPUT_CSV}")
    logger.info(f"Total lignes : {len(df_v5)}")
    logger.info(f"Erreurs      : {errors}")
    logger.info(f"Distribution :")
    logger.info(f"  Sain    (0) : {(df_v5.label==0).sum()}")
    logger.info(f"  Suspect (1) : {(df_v5.label==1).sum()}")
    logger.info(f"  Danger  (2) : {(df_v5.label==2).sum()}")
    logger.info(f"{'═'*55}")

    print(f"\n✅ Dataset v5 prêt : {OUTPUT_CSV}")
    print(f"   Sain={( df_v5.label==0).sum()} | Suspect={(df_v5.label==1).sum()} | Danger={(df_v5.label==2).sum()}")
    print(f"   Sandbox scores variés : mean={df_new['sandbox_score'].mean():.1f}")


if __name__ == "__main__":
    main()
    