#!/usr/bin/env python3
"""Return dashboard stats and recent emails from Cosmos DB as JSON."""
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
    if "QUARANT" in v:
        return "SUSPICIOUS"
    return "SAFE"


def main():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    try:
        import cosmos_client as cc

        recent = cc.get_recent_analyses(limit=50)

        emails = []
        scores = []
        for item in recent:
            verdict_raw = item.get("verdict", "")
            v = normalize_verdict(verdict_raw)
            score = round(float(item.get("final", item.get("scores", {}).get("final", 0)) or 0), 1)
            scores.append(score)
            emails.append({
                "id":        item.get("id", ""),
                "from":      item.get("sender", "unknown"),
                "subject":   item.get("subject", "(no subject)"),
                "verdict":   v,
                "score":     score,
                "folder":    item.get("source_folder", "INBOX"),
                "timestamp": item.get("timestamp", ""),
            })

        stats = {
            "total":      len(emails),
            "danger":     sum(1 for e in emails if e["verdict"] == "DANGER"),
            "suspicious": sum(1 for e in emails if e["verdict"] == "SUSPICIOUS"),
            "safe":       sum(1 for e in emails if e["verdict"] == "SAFE"),
            "avg_score":  round(sum(scores) / len(scores), 2) if scores else 0,
        }

        print(json.dumps({"stats": stats, "recent": emails}))

    except Exception as exc:
        print(json.dumps({"error": str(exc)}))


if __name__ == "__main__":
    main()
