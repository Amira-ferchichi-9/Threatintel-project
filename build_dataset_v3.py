"""
build_dataset_v3.py
═══════════════════════════════════════════════════════════════════════
Pipeline batch ThreatIntel — Reconstruction dataset via vrais agents

Sources :
  - SpamAssassin : datasets/easy_ham/, easy_ham_2/, spam/
  - Phishing CSV : datasets/phishing_emails.csv

Sortie :
  - datasets/threatintel_training_dataset_v3.csv

Usage :
  python build_dataset_v3.py
  python build_dataset_v3.py --limit 500          # test rapide
  python build_dataset_v3.py --no-sandbox         # skip Azure
  python build_dataset_v3.py --resume             # reprend après crash
═══════════════════════════════════════════════════════════════════════
"""

import os
import sys
import csv
import time
import email
import asyncio
import logging
import argparse
import traceback
from pathlib import Path
from email import policy as email_policy
from email.parser import BytesParser, Parser

import pandas as pd
from tqdm import tqdm

# ── Ajout du dossier racine au path ──────────────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from agents.agent_auth    import run_auth_agent
from agents.agent_url     import run_url_agent
from agents.agent_nlp_bec import run_nlp_bec_agent
from agents.agent_sandbox  import run_sandbox_agent

# ─────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────
DATASETS_DIR   = ROOT / "datasets"
OUTPUT_CSV     = DATASETS_DIR / "threatintel_training_dataset_v3.csv"
CHECKPOINT_CSV = DATASETS_DIR / "_checkpoint_v3.csv"

# Dossiers SpamAssassin → label
SPAMASSASSIN_SOURCES = {
    "easy_ham":   0,   # Sain
    "easy_ham_2": 0,   # Sain
    "spam":       2,   # Danger
}

# Colonnes CSV phishing
PHISHING_CSV_PATH = DATASETS_DIR / "phishing_emails.csv"
PHISHING_LABEL_MAP = {
    "Safe Email":     0,
    "Phishing Email": 2,
}

# Score sandbox provisoire minimal pour déclencher Azure
SANDBOX_TRIGGER_THRESHOLD = 40   # si url+nlp > seuil → on soumet

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(ROOT / "build_dataset_v3.log"), encoding="utf-8"),
    ]
)
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────
# PARSING EMAIL
# ─────────────────────────────────────────────────────────────────────
def parse_eml_file(filepath: Path) -> dict:
    """Parse un fichier email SpamAssassin (RFC 822, sans extension)."""
    try:
        raw = filepath.read_bytes()
        msg = BytesParser(policy=email_policy.compat32).parsebytes(raw)
    except Exception:
        try:
            raw_text = filepath.read_text(encoding="utf-8", errors="replace")
            msg = Parser(policy=email_policy.compat32).parsestr(raw_text)
        except Exception as e:
            logger.warning(f"Parse échoué : {filepath.name} — {e}")
            return {}

    return extract_email_fields(msg)


def parse_csv_row(row_text: str) -> dict:
    """Construit un dict email depuis une ligne du CSV phishing."""
    # Le CSV n'a pas de headers email structurés — on parse le texte brut
    try:
        msg = Parser(policy=email_policy.compat32).parsestr(row_text)
        fields = extract_email_fields(msg)
        # Si le parsing ne trouve pas de body, utilise le texte brut entier
        if not fields.get("body"):
            fields["body"] = row_text[:5000]
        return fields
    except Exception:
        return {
            "sender":   "",
            "subject":  "",
            "to":       "",
            "cc":       "",
            "reply_to": "",
            "body":     row_text[:5000],
            "attachments": [],
        }


def extract_email_fields(msg) -> dict:
    """Extrait les champs utiles d'un objet email.message."""
    sender   = str(msg.get("From",     "") or "")
    subject  = str(msg.get("Subject",  "") or "")
    to       = str(msg.get("To",       "") or "")
    cc       = str(msg.get("Cc",       "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")

    # Corps texte
    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype    = part.get_content_type()
            cdispos  = str(part.get("Content-Disposition", ""))
            if "attachment" in cdispos:
                fname   = part.get_filename() or "attachment"
                payload = part.get_payload(decode=True) or b""
                attachments.append({"name": fname, "data": payload})
            elif ctype == "text/plain" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")
            elif ctype == "text/html" and not body:
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="replace")

    return {
        "sender":      sender.strip(),
        "subject":     subject.strip(),
        "to":          to.strip(),
        "cc":          cc.strip(),
        "reply_to":    reply_to.strip(),
        "body":        body[:8000],   # limite pour performance
        "attachments": attachments,
    }


# ─────────────────────────────────────────────────────────────────────
# PIPELINE AGENT PAR EMAIL
# ─────────────────────────────────────────────────────────────────────
def process_email(fields: dict, label: int, use_sandbox: bool) -> dict | None:
    """
    Passe un email par les 4 agents et retourne la ligne CSV.
    Retourne None si une erreur bloque le traitement.
    """
    try:
        sender   = fields.get("sender",   "")
        subject  = fields.get("subject",  "")
        to       = fields.get("to",       "")
        cc       = fields.get("cc",       "")
        reply_to = fields.get("reply_to", "")
        body     = fields.get("body",     "")
        attachments = fields.get("attachments", [])

        # ── Agent AUTH ──────────────────────────────────────────────
        auth_result  = run_auth_agent(
            sender=sender,
            subject=subject,
            to_header=to,
            cc_header=cc,
            reply_to=reply_to,
        )
        score_auth = int(auth_result.get("score_auth", 0))


        # ── Agent URL ───────────────────────────────────────────────
        url_result  = run_url_agent(body_text=body, max_urls=2)
        score_url  = int(url_result.get("score_url", 0))
        url_malicious = score_url >= 50

        # ── Agent NLP ───────────────────────────────────────────────
        # Détermine domaine expéditeur
        sender_domain = ""
        if "@" in sender:
            sender_domain = sender.split("@")[-1].strip(">").strip()

        # Heuristique institutionnel : auth élevée
        institutional = score_auth >= 70

        nlp_result  = run_nlp_bec_agent(
            subject=subject,
            body_text=body,
            sender_domain=sender_domain,
            institutional=institutional,
            url_malicious=url_malicious,
        )
        score_nlp  = int(nlp_result.get("score_nlp", 0))

        # ── Agent SANDBOX ───────────────────────────────────────────
        score_sandbox = 0
        if use_sandbox:
            # Déclenchement conditionnel : économise les appels Azure
            score_provisoire = score_url + score_nlp
            if score_provisoire >= SANDBOX_TRIGGER_THRESHOLD or attachments:
                sandbox_result = run_sandbox_agent(
                    attachments=attachments,
                    score_provisoire=score_provisoire,
                )
            score_sandbox = int(sandbox_result.get("score_sandbox", 0))  
        # Si pas de sandbox → 0 (cohérent avec la majorité du dataset existant)

        return {
            "auth_score":    score_auth,
            "url_score":     score_url,
            "nlp_score":     score_nlp,
            "sandbox_score": score_sandbox,
            "label":         label,
        }

    except Exception as e:
        logger.warning(f"Erreur traitement email : {e}")
        logger.debug(traceback.format_exc())
        return None


# ─────────────────────────────────────────────────────────────────────
# CHARGEMENT DES SOURCES
# ─────────────────────────────────────────────────────────────────────
def load_spamassassin(limit_per_folder: int | None = None) -> list[tuple[Path, int]]:
    """Retourne liste de (filepath, label) pour tous les dossiers SpamAssassin."""
    items = []
    for folder_name, label in SPAMASSASSIN_SOURCES.items():
        folder = DATASETS_DIR / folder_name
        if not folder.exists():
            logger.warning(f"Dossier introuvable : {folder}")
            continue
        files = [f for f in folder.iterdir() if f.is_file()]
        if limit_per_folder:
            files = files[:limit_per_folder]
        for f in files:
            items.append((f, label))
        logger.info(f"SpamAssassin '{folder_name}' : {len(files)} emails (label={label})")
    return items


def load_phishing_csv(limit: int | None = None) -> list[tuple[str, int]]:
    """Retourne liste de (email_text, label) depuis le CSV phishing."""
    if not PHISHING_CSV_PATH.exists():
        logger.warning(f"CSV phishing introuvable : {PHISHING_CSV_PATH}")
        return []

    df = pd.read_csv(PHISHING_CSV_PATH)
    items = []
    for _, row in df.iterrows():
        text       = str(row.get("Email Text", ""))
        email_type = str(row.get("Email Type", ""))
        label      = PHISHING_LABEL_MAP.get(email_type)
        if label is None:
            continue
        items.append((text, label))

    if limit:
        items = items[:limit]

    safe_count    = sum(1 for _, l in items if l == 0)
    phishing_count = sum(1 for _, l in items if l == 2)
    logger.info(f"CSV Phishing : {len(items)} emails (Sain={safe_count}, Phishing={phishing_count})")
    return items


# ─────────────────────────────────────────────────────────────────────
# CHECKPOINT — reprise après crash
# ─────────────────────────────────────────────────────────────────────
def load_checkpoint() -> set[str]:
    """Retourne les IDs déjà traités (pour reprise)."""
    processed = set()
    if CHECKPOINT_CSV.exists():
        try:
            df = pd.read_csv(CHECKPOINT_CSV)
            if "email_id" in df.columns:
                processed = set(df["email_id"].astype(str))
                logger.info(f"Checkpoint : {len(processed)} emails déjà traités")
        except Exception:
            pass
    return processed


def save_row_checkpoint(email_id: str, row: dict):
    """Ajoute une ligne au checkpoint CSV."""
    row_with_id = {"email_id": email_id, **row}
    file_exists = CHECKPOINT_CSV.exists()
    with open(CHECKPOINT_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["email_id","auth_score","url_score","nlp_score","sandbox_score","label"])
        if not file_exists:
            writer.writeheader()
        writer.writerow(row_with_id)


# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Build ThreatIntel dataset v3")
    parser.add_argument("--limit",      type=int, default=None,  help="Limite emails par source (test)")
    parser.add_argument("--no-sandbox", action="store_true",     help="Désactive l'agent sandbox Azure")
    parser.add_argument("--resume",     action="store_true",     help="Reprend depuis le checkpoint")
    args = parser.parse_args()

    use_sandbox = not args.no_sandbox
    logger.info(f"═══ Build Dataset v3 ═══")
    logger.info(f"Sandbox Azure : {'ACTIVÉ' if use_sandbox else 'DÉSACTIVÉ'}")
    logger.info(f"Limite        : {args.limit or 'aucune'}")
    logger.info(f"Reprise       : {'OUI' if args.resume else 'NON'}")

    # Checkpoint
    processed_ids = load_checkpoint() if args.resume else set()

    # ── Collecte des sources ─────────────────────────────────────────
    spam_items    = load_spamassassin(limit_per_folder=args.limit)
    phishing_items = load_phishing_csv(limit=args.limit)

    total = len(spam_items) + len(phishing_items)
    logger.info(f"Total emails à traiter : {total}")

    results = []
    errors  = 0

    # ── Traitement SpamAssassin ──────────────────────────────────────
    logger.info("Traitement SpamAssassin...")
    for filepath, label in tqdm(spam_items, desc="SpamAssassin", unit="email"):
        email_id = f"sa_{filepath.parent.name}_{filepath.name}"

        if args.resume and email_id in processed_ids:
            continue

        fields = parse_eml_file(filepath)
        if not fields:
            errors += 1
            continue

        row = process_email(fields, label, use_sandbox)
        if row:
            results.append(row)
            if args.resume:
                save_row_checkpoint(email_id, row)
        else:
            errors += 1

    # ── Traitement CSV Phishing ──────────────────────────────────────
    logger.info("Traitement CSV Phishing...")
    for idx, (text, label) in enumerate(tqdm(phishing_items, desc="Phishing CSV", unit="email")):
        email_id = f"ph_{idx}"

        if args.resume and email_id in processed_ids:
            continue

        fields = parse_csv_row(text)
        row    = process_email(fields, label, use_sandbox)
        if row:
            results.append(row)
            if args.resume:
                save_row_checkpoint(email_id, row)
        else:
            errors += 1

    # ── Sauvegarde finale ────────────────────────────────────────────
    if not results:
        logger.error("Aucun résultat — vérifier les agents et les sources.")
        return

    df_out = pd.DataFrame(results, columns=["auth_score","url_score","nlp_score","sandbox_score","label"])
    df_out.to_csv(OUTPUT_CSV, index=False)

    # Stats
    logger.info(f"\n{'═'*55}")
    logger.info(f"Dataset v3 sauvegardé → {OUTPUT_CSV}")
    logger.info(f"Total lignes : {len(df_out)}")
    logger.info(f"Erreurs      : {errors}")
    logger.info(f"Distribution :")
    logger.info(f"  Sain    (0) : {(df_out.label==0).sum()}")
    logger.info(f"  Suspect (1) : {(df_out.label==1).sum()}")
    logger.info(f"  Danger  (2) : {(df_out.label==2).sum()}")
    logger.info(f"{'═'*55}")

    # Nettoyage checkpoint si succès
    if args.resume and CHECKPOINT_CSV.exists():
        CHECKPOINT_CSV.unlink()
        logger.info("Checkpoint supprimé ✅")

    print(f"\n✅ Dataset v3 prêt : {OUTPUT_CSV}")
    print(f"   {len(df_out)} emails | {errors} erreurs")


if __name__ == "__main__":
    main()