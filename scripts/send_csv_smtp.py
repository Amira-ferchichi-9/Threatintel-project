#!/usr/bin/env python3
"""Send phishing samples from CSV via Gmail SMTP using env vars.

Required env vars in .env:
  SMTP_USER, SMTP_PASS, SMTP_HOST, SMTP_PORT
"""

import os
import sys
import csv
import ssl
import smtplib
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CSV = ROOT / "phishing_email.csv"


def load_env():
    try:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    except Exception:
        pass


def require_env(name: str) -> str:
    val = os.getenv(name, "").strip()
    if not val:
        raise SystemExit(f"Missing env var: {name}")
    return val


def iter_phishing_rows(csv_path: Path):
    with csv_path.open(newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("label") == "1":
                yield row


def main() -> int:
    load_env()

    sender = require_env("SMTP_USER")
    password = require_env("SMTP_PASS")
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))

    if len(sys.argv) < 3:
        print("Usage: python scripts/send_csv_smtp.py <recipient> <count> [csv_path]")
        return 2

    recipient = sys.argv[1]
    count = int(sys.argv[2])
    csv_path = Path(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_CSV

    if not csv_path.exists():
        print(f"CSV not found: {csv_path}")
        return 2

    rows = []
    for row in iter_phishing_rows(csv_path):
        rows.append(row)
        if len(rows) >= count:
            break

    if not rows:
        print("No phishing samples found (label=1).")
        return 2

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls(context=context)
        smtp.login(sender, password)

        for i, row in enumerate(rows, start=1):
            msg = EmailMessage()
            msg["From"] = sender
            msg["To"] = recipient
            msg["Subject"] = f"Phishing sample #{i}"
            msg.set_content(row.get("text_combined", "(empty)")[:4000])
            smtp.send_message(msg)
            print(f"Sent: phishing sample #{i}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
