#!/usr/bin/env python3
"""Fetch last 10 Gmail emails (INBOX+SPAM), run orchestrator in parallel, return JSON."""
import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def normalize_verdict(raw: str) -> str:
    v = str(raw).upper()
    if "DANGER" in v:
        return "DANGER"
    if "SUSPECT" in v or "QUARANT" in v:
        return "SUSPICIOUS"
    return "SAFE"


def _prewarm_nlp():
    """Import NLP agent so models are loaded before parallel analysis starts."""
    try:
        import agents.agent_nlp_bec  # triggers model loading
    except Exception:
        pass


SCORE_KEYS = {"auth": "score_auth", "url": "score_url", "nlp": "score_nlp", "sandbox": "score_sandbox"}


async def _analyze_one(m: dict, service, execute, orchestrate, build_email_context) -> dict | None:
    msg_id = m["id"]
    try:
        meta = m.get("_meta") or execute(
            service.users().messages().get(
                userId="me", id=msg_id, format="metadata",
                metadataHeaders=["From", "Subject"]
            )
        )
        ts_ms = int(meta.get("internalDate", 0))
        timestamp = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat()

        folder = m.get("_folder", "INBOX")
        ctx = build_email_context(msg_id, service, folder)
        if not ctx:
            return None

        ctx.setdefault("email_hash", hashlib.sha256(
            f"{ctx.get('sender','')}{ctx.get('subject','')}{ctx.get('body_text','')[:200]}".encode()
        ).hexdigest())

        result     = await orchestrate(ctx, reports_dir="reports")
        scoring    = result.get("scoring", {})
        agents_raw = result.get("agents", {})
        verdict    = normalize_verdict(scoring.get("verdict", ""))

        agents = []
        for name, data in agents_raw.items():
            if not isinstance(data, dict):
                continue
            sk = SCORE_KEYS.get(name, "")
            agents.append({
                "name":    name.upper(),
                "score":   data.get(sk),
                "verdict": str(data.get("verdict", "")).replace("⚠️ ", "").strip(),
                "detail":  str(data.get("detail", data.get("hard_rule", "")))[:120],
            })

        return {
            "id":        ctx["email_hash"],
            "from":      ctx.get("sender", "unknown"),
            "subject":   ctx.get("subject", "(no subject)"),
            "verdict":   verdict,
            "score":     round(float(scoring.get("score_final", 0)), 1),
            "folder":    folder,
            "timestamp": timestamp,
            "action":    scoring.get("action", ""),
            "hard_rule": scoring.get("hard_rule", ""),
            "agents":    agents,
        }

    except Exception as e:
        return {
            "id": msg_id, "from": "?", "subject": "(analysis error)",
            "verdict": "SAFE", "score": 0, "folder": "INBOX",
            "timestamp": "", "error": str(e),
        }


async def _run_all(messages, service, execute, orchestrate, build_email_context):
    tasks = [_analyze_one(m, service, execute, orchestrate, build_email_context) for m in messages]
    return await asyncio.gather(*tasks)


def main():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    try:
        from orchestrator import get_gmail_service, build_email_context, orchestrate, _gmail_execute_with_retry
    except ImportError as e:
        print(json.dumps({"error": f"Import error: {e}"}))
        return

    # Pre-warm NLP models so first email doesn't pay cold-start cost
    _prewarm_nlp()

    # Find a working Gmail session
    service = None
    for session in ["amira", "default"]:
        try:
            s = get_gmail_service(session)
            _gmail_execute_with_retry(s.users().getProfile(userId="me"))
            service = s
            break
        except Exception:
            continue

    if service is None:
        try:
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build
            for fname in ["token.json", "token_amira.json"]:
                if os.path.exists(fname):
                    creds   = Credentials.from_authorized_user_file(fname)
                    service = build("gmail", "v1", credentials=creds)
                    break
        except Exception:
            pass

    if service is None:
        print(json.dumps({"error": "No valid Gmail token found. Run the auth script first."}))
        return

    # Fetch from both INBOX and SPAM, merge by date, keep 10 most recent
    raw_messages = []
    for label in ["INBOX", "SPAM"]:
        try:
            resp = _gmail_execute_with_retry(
                service.users().messages().list(userId="me", labelIds=[label], maxResults=10)
            )
            for m in resp.get("messages", []):
                m["_folder"] = label
                raw_messages.append(m)
        except Exception:
            continue

    if not raw_messages:
        print(json.dumps({"results": []}))
        return

    # Deduplicate and sort by internalDate descending
    seen_ids, dated = set(), []
    for m in raw_messages:
        if m["id"] in seen_ids:
            continue
        seen_ids.add(m["id"])
        try:
            meta = _gmail_execute_with_retry(
                service.users().messages().get(
                    userId="me", id=m["id"], format="metadata",
                    metadataHeaders=["From", "Subject"]
                )
            )
            m["_date"] = int(meta.get("internalDate", 0))
            m["_meta"] = meta
        except Exception:
            m["_date"] = 0
            m["_meta"] = None
        dated.append(m)

    dated.sort(key=lambda x: x["_date"], reverse=True)
    messages = dated[:10]

    # Analyse all emails in parallel
    raw_results = asyncio.run(_run_all(messages, service, _gmail_execute_with_retry, orchestrate, build_email_context))
    results = [r for r in raw_results if r is not None]

    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
