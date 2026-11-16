"""
add_suspect_emails.py
═══════════════════════════════════════════════════════════════════════
Ajoute les emails frauduleux (Suspect=1) au dataset v3
Source  : datasets/fradulent_emails.txt (4075 emails Nigerian Fraud)
Entrée  : datasets/threatintel_training_dataset_v3.csv
Sortie  : datasets/threatintel_training_dataset_v4.csv

Usage :
  python add_suspect_emails.py
  python add_suspect_emails.py --limit 500   # test rapide
═══════════════════════════════════════════════════════════════════════
"""

import os
import sys
import re
import logging
import argparse
import traceback
from pathlib import Path
from email.parser import Parser
from email import policy as email_policy

import pandas as pd
from tqdm import tqdm

# ── Path racine ───────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from agents.agent_auth    import run_auth_agent
from agents.agent_url     import run_url_agent
from agents.agent_nlp_bec import run_nlp_bec_agent

# ─────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────
FRAUD_TXT   = ROOT / "datasets" / "fradulent_emails.txt"
INPUT_CSV   = ROOT / "datasets" / "threatintel_training_dataset_v3.csv"
OUTPUT_CSV  = ROOT / "datasets" / "threatintel_training_dataset_v4.csv"
LABEL_SUSPECT = 1

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(ROOT / "add_suspect_emails.log"), encoding="utf-8"),
    ]
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# PARSING DU FICHIER FRAUD TXT
# Le fichier contient plusieurs emails séparés par "From r  " ou "From "
# ─────────────────────────────────────────────────────────────────────
def split_emails(filepath: Path) -> list[str]:
    """Découpe le fichier .txt en emails individuels."""
    text = filepath.read_text(encoding="utf-8", errors="replace")

    # Séparateur : ligne commençant par "From " (format mbox)
    parts = re.split(r'\nFrom \S+.*?\n', text)
    parts = [p.strip() for p in parts if len(p.strip()) > 100]

    logger.info(f"Emails détectés dans le fichier : {len(parts)}")
    return parts


def parse_fraud_email(raw: str) -> dict:
    """Parse un email brut en champs utiles."""
    try:
        msg = Parser(policy=email_policy.compat32).parsestr(raw)

        sender   = str(msg.get("From",     "") or "")
        subject  = str(msg.get("Subject",  "") or "")
        to       = str(msg.get("To",       "") or "")
        cc       = str(msg.get("Cc",       "") or "")
        reply_to = str(msg.get("Reply-To", "") or "")

        # Corps
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body = payload.decode("utf-8", errors="replace")
                        break
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode("utf-8", errors="replace")

        # Fallback : si body vide, prend le texte brut après les headers
        if not body:
            lines = raw.split("\n")
            in_body = False
            body_lines = []
            for line in lines:
                if in_body:
                    body_lines.append(line)
                elif line.strip() == "":
                    in_body = True
            body = "\n".join(body_lines[:200])

        return {
            "sender":   sender.strip(),
            "subject":  subject.strip(),
            "to":       to.strip(),
            "cc":       cc.strip(),
            "reply_to": reply_to.strip(),
            "body":     body[:8000],
        }

    except Exception as e:
        logger.debug(f"Parse échoué : {e}")
        return {
            "sender": "", "subject": "", "to": "",
            "cc": "", "reply_to": "", "body": raw[:3000],
        }


# ─────────────────────────────────────────────────────────────────────
# PIPELINE AGENTS (sans sandbox — fraud emails n'ont pas de PJ)
# ─────────────────────────────────────────────────────────────────────
def process_fraud_email(fields: dict) -> dict | None:
    try:
        sender   = fields["sender"]
        subject  = fields["subject"]
        body     = fields["body"]

        # Agent AUTH
        auth_result = run_auth_agent(
            sender=sender,
            subject=subject,
            to_header=fields["to"],
            cc_header=fields["cc"],
            reply_to=fields["reply_to"],
        )
        score_auth = int(auth_result.get("score_auth", 0))

        # Agent URL
        url_result    = run_url_agent(body_text=body, max_urls=2)
        score_url     = int(url_result.get("score_url", 0))
        url_malicious = score_url >= 50

        # Agent NLP
        sender_domain = ""
        if "@" in sender:
            sender_domain = sender.split("@")[-1].strip(">").strip()

        nlp_result = run_nlp_bec_agent(
            subject=subject,
            body_text=body,
            sender_domain=sender_domain,
            institutional=False,      # fraud emails ne sont jamais institutionnels
            url_malicious=url_malicious,
        )
        score_nlp = int(nlp_result.get("score_nlp", 0))

        # Sandbox = 0 (pas de PJ dans ce corpus)
        return {
            "auth_score":    score_auth,
            "url_score":     score_url,
            "nlp_score":     score_nlp,
            "sandbox_score": 0,
            "label":         LABEL_SUSPECT,
        }

    except Exception as e:
        logger.warning(f"Erreur : {e}")
        logger.debug(traceback.format_exc())
        return None


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Add suspect emails to dataset")
    parser.add_argument("--limit", type=int, default=None, help="Limite emails (test)")
    args = parser.parse_args()

    logger.info("═══ Add Suspect Emails ═══")

    # Charge le dataset v3
    if not INPUT_CSV.exists():
        logger.error(f"Dataset v3 introuvable : {INPUT_CSV}")
        return

    df_v3 = pd.read_csv(INPUT_CSV)
    logger.info(f"Dataset v3 chargé : {len(df_v3)} lignes")
    logger.info(f"  Sain    (0) : {(df_v3.label==0).sum()}")
    logger.info(f"  Suspect (1) : {(df_v3.label==1).sum()}")
    logger.info(f"  Danger  (2) : {(df_v3.label==2).sum()}")

    # Parse les emails fraud
    raw_emails = split_emails(FRAUD_TXT)
    if args.limit:
        raw_emails = raw_emails[:args.limit]
    logger.info(f"Emails fraud à traiter : {len(raw_emails)}")

    # Traitement
    results = []
    errors  = 0

    for raw in tqdm(raw_emails, desc="Fraud emails", unit="email"):
        fields = parse_fraud_email(raw)
        row    = process_fraud_email(fields)
        if row:
            results.append(row)
        else:
            errors += 1

    if not results:
        logger.error("Aucun résultat !")
        return

    # Merge
    df_suspect = pd.DataFrame(results, columns=["auth_score","url_score","nlp_score","sandbox_score","label"])
    df_v4      = pd.concat([df_v3, df_suspect], ignore_index=True)
    df_v4.to_csv(OUTPUT_CSV, index=False)

    # Stats finales
    logger.info(f"\n{'═'*55}")
    logger.info(f"Dataset v4 sauvegardé → {OUTPUT_CSV}")
    logger.info(f"Total lignes : {len(df_v4)}")
    logger.info(f"Erreurs      : {errors}")
    logger.info(f"Distribution finale :")
    logger.info(f"  Sain    (0) : {(df_v4.label==0).sum()}")
    logger.info(f"  Suspect (1) : {(df_v4.label==1).sum()}")
    logger.info(f"  Danger  (2) : {(df_v4.label==2).sum()}")
    logger.info(f"{'═'*55}")

    print(f"\n✅ Dataset v4 prêt : {OUTPUT_CSV}")
    print(f"   Sain={( df_v4.label==0).sum()} | Suspect={(df_v4.label==1).sum()} | Danger={(df_v4.label==2).sum()}")
    print(f"   Erreurs : {errors}")


if __name__ == "__main__":
    main()