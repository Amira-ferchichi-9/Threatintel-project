#!/usr/bin/env python3
"""Run the ThreatIntel orchestrator on raw email text and return JSON."""
import asyncio
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

VERDICT_MAP = {
    "SAIN":    "SAFE",
    "SUSPECT": "SUSPICIOUS",
    "DANGER":  "DANGER",
}

def normalize_verdict(raw: str) -> str:
    v = str(raw).upper()
    for key, val in VERDICT_MAP.items():
        if key in v:
            return val
    if "QUARANT" in v or "DELIVER" not in v:
        pass
    return "SAFE"

def action_to_verdict(action: str) -> str:
    a = str(action).upper()
    if "QUARANT" in a or "BLOCK" in a:
        return "SUSPICIOUS"
    if "DANGER" in a:
        return "DANGER"
    return "SAFE"


def main():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    args = sys.argv[1:]
    content = ""

    if "--file" in args:
        idx = args.index("--file")
        try:
            with open(args[idx + 1], "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as exc:
            print(json.dumps({"error": f"Cannot read file: {exc}"}))
            return
    else:
        content = sys.stdin.read()

    if not content.strip():
        print(json.dumps({"error": "Empty email content"}))
        return

    # Parse basic fields from raw email text
    lines = content.splitlines()
    subject, sender = "", ""
    body_lines = []
    in_body = False
    for line in lines:
        if not in_body:
            low = line.lower()
            if low.startswith("from:"):
                sender = line[5:].strip()
            elif low.startswith("subject:"):
                subject = line[8:].strip()
            elif line.strip() == "":
                in_body = True
        else:
            body_lines.append(line)

    body_text = "\n".join(body_lines) if body_lines else content
    if not subject:
        subject = "(manual analysis)"
    if not sender:
        sender = "unknown@manual"

    email_hash = hashlib.sha256(f"{sender}{subject}{body_text[:200]}".encode()).hexdigest()

    email_context = {
        "sender":       sender,
        "subject":      subject,
        "body_text":    body_text,
        "attachments":  [],
        "email_hash":   email_hash,
        "source_folder": "MANUAL",
        "to_header":    "",
        "cc_header":    "",
        "reply_to":     "",
        "return_path":  "",
        "authentication_results":     "",
        "arc_authentication_results": "",
    }

    try:
        from orchestrator import orchestrate

        result = asyncio.run(orchestrate(email_context, reports_dir="reports"))
        scoring = result.get("scoring", {})
        agents_raw = result.get("agents", {})

        verdict_raw = scoring.get("verdict", "")
        verdict_by_verdict = normalize_verdict(verdict_raw)
        verdict_by_action  = action_to_verdict(scoring.get("action", "DELIVER"))
        verdict = "DANGER" if "DANGER" in verdict_raw.upper() else verdict_by_verdict

        agents = []
        score_keys = {"auth": "score_auth", "url": "score_url", "nlp": "score_nlp", "sandbox": "score_sandbox"}
        for name, data in agents_raw.items():
            if not isinstance(data, dict):
                continue
            score_key = score_keys.get(name, "")
            score_val = data.get(score_key, None)
            agents.append({
                "name":   name.upper(),
                "score":  score_val,
                "verdict": str(data.get("verdict", "")).replace("⚠️ ", "").strip(),
                "detail": str(data.get("detail", data.get("hard_rule", "")))[:120],
            })

        print(json.dumps({
            "verdict":    verdict,
            "score":      scoring.get("score_final", 0),
            "confidence": min(100, max(0, int(scoring.get("score_final", 0)))),
            "action":     scoring.get("action", ""),
            "hard_rule":  scoring.get("hard_rule", ""),
            "agents":     agents,
        }))

    except Exception as exc:
        print(json.dumps({"error": str(exc)}))


if __name__ == "__main__":
    main()
