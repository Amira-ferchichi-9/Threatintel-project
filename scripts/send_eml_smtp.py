#!/usr/bin/env python3
"""Send .eml files via Gmail SMTP using env vars.

Required env vars in .env:
  SMTP_USER, SMTP_PASS, SMTP_HOST, SMTP_PORT
"""

import os
import sys
import ssl
import smtplib
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "phishing_pot" / "e-mail"


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


def read_eml(path: Path) -> EmailMessage:
    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg


def build_message(src: EmailMessage, sender: str, recipient: str) -> EmailMessage:
    # Create a clean message to avoid issues with raw headers in .eml files.
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = src.get("Subject", "(no subject)")

    body = src.get_body(preferencelist=("plain",))
    if body:
        msg.set_content(body.get_content())
    else:
        payload = src.get_payload(decode=True)
        msg.set_content((payload or b"").decode(errors="ignore"))

    return msg


def main() -> int:
    load_env()

    sender = require_env("SMTP_USER")
    password = require_env("SMTP_PASS")
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))

    if len(sys.argv) < 3:
        print("Usage: python scripts/send_eml_smtp.py <recipient> <count> [eml_dir]")
        return 2

    recipient = sys.argv[1]
    count = int(sys.argv[2])
    eml_dir = Path(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_DIR

    if not eml_dir.exists():
        print(f"EML dir not found: {eml_dir}")
        return 2

    eml_files = sorted(p for p in eml_dir.iterdir() if p.suffix.lower() == ".eml")
    if not eml_files:
        print(f"No .eml files in: {eml_dir}")
        return 2

    to_send = eml_files[:count]

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port) as smtp:
        smtp.starttls(context=context)
        smtp.login(sender, password)

        for path in to_send:
            src = read_eml(path)
            msg = build_message(src, sender, recipient)
            smtp.send_message(msg)
            print(f"Sent: {path.name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
