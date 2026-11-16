# api.py — FastAPI v5.0
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from orchestrator import orchestrate
from cache import get_cache
from cosmos_client import get_recent_analyses
import uuid
from datetime import datetime, timezone

app = FastAPI(title="PFA Email Threat Detection", version="5.0")


class EmailRequest(BaseModel):
    subject: str
    sender: str
    body: str
    source_folder: str = "INBOX"
    has_attachment: bool = False
    callback_url: Optional[str] = None
    message_id: Optional[str] = None


@app.post("/analyze")
async def analyze_email(req: EmailRequest):
    email_id = req.message_id or str(uuid.uuid4())
    email_context = {
        "subject":       req.subject,
        "sender":        req.sender,
        "body_text":     req.body,
        "source_folder": req.source_folder,
        "attachments":   [],
        "message_id":    email_id,
        "callback_url":  req.callback_url,
    }
    result  = await orchestrate(email_context)
    scoring = result.get("scoring", {})
    agents  = result.get("agents", {})

    return {
        "email_id":   email_id,
        "timestamp":  datetime.now(timezone.utc).isoformat(),
        "subject":    req.subject,
        "sender":     req.sender,
        "verdict":    scoring.get("verdict", "INCONNU"),
        "action":     scoring.get("action", ""),
        "score":      scoring.get("score_final", 0),
        "hard_rule":  scoring.get("hard_rule"),
        "report_url": result.get("report_path", ""),
        "agents": {
            "auth":    agents.get("auth",    {}).get("score_auth",    0),
            "url":     agents.get("url",     {}).get("score_url",     0),
            "nlp":     agents.get("nlp",     {}).get("score_nlp",     0),
            "sandbox": agents.get("sandbox", {}).get("score_sandbox", 0),
        },
    }


@app.get("/verdicts/latest")
def get_latest_verdicts(limit: int = 10):
    verdicts = get_recent_analyses(limit=max(1, min(limit, 100)))
    return {"verdicts": verdicts, "count": len(verdicts)}


@app.get("/history")
def get_history():
    cache = get_cache()
    return {"message": "Cache Redis actif", "available": cache.available}


@app.get("/stats")
def get_statistics():
    cache = get_cache()
    return cache.stats()


@app.get("/health")
def health():
    return {"status": "ok", "version": "5.0"}
