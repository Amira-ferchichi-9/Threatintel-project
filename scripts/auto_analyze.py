#!/usr/bin/env python3
"""
auto_analyze.py — Poller Gmail automatique (INBOX + SPAM).
- Au demarrage : analyse immediate des 10 derniers mails existants
- Ensuite : surveille les nouveaux mails toutes les 60s
- Sauvegarde dans json-server (port 3001) pour mise a jour automatique
"""
import asyncio
import hashlib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

POLL_INTERVAL  = 30
JSON_SERVER    = "http://localhost:3001"
STATE_FILE     = os.path.join(os.path.dirname(os.path.abspath(__file__)), "poll_state.json")
SCORE_KEYS     = {"auth": "score_auth", "url": "score_url",
                  "nlp": "score_nlp", "sandbox": "score_sandbox"}
INITIAL_FETCH  = 15   # mails par dossier au demarrage (INBOX + SPAM = 30 max)


# ── State persistence ──────────────────────────────────────────────────────────

def load_state() -> dict:
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"historyId": ""}


def save_state(state: dict):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


# ── json-server helpers ────────────────────────────────────────────────────────

def _json_request(url: str, method: str, data: bytes | None = None) -> int:
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"} if data else {},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def save_to_json_server(doc: dict):
    email_id = doc["id"]
    exists   = _json_request(f"{JSON_SERVER}/emails/{email_id}", "GET") == 200
    if exists:
        _json_request(f"{JSON_SERVER}/emails/{email_id}", "PUT",  json.dumps(doc).encode())
    else:
        _json_request(f"{JSON_SERVER}/emails",            "POST", json.dumps(doc).encode())


# ── Verdict normalisation ──────────────────────────────────────────────────────

def normalize_verdict(raw: str) -> str:
    v = str(raw).upper()
    if "DANGER"  in v:                    return "DANGER"
    if "SUSPECT" in v or "QUARANT" in v:  return "SUSPICIOUS"
    return "SAFE"


# ── Wrapper avec timeout ──────────────────────────────────────────────────────

async def _safe(coro, timeout: int = 90):
    try:
        await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        print(f"[AUTO SKIP] timeout {timeout}s depasse")
    except Exception as e:
        print(f"[AUTO ERR] {e}")


# ── Analyse d'un seul mail ────────────────────────────────────────────────────

async def analyze_and_save(msg_id: str, folder: str, service, execute):
    from orchestrator import build_email_context, orchestrate
    from datetime import datetime, timezone

    try:
        meta  = execute(service.users().messages().get(
            userId="me", id=msg_id, format="metadata",
            metadataHeaders=["From", "Subject"],
        ))
        ts_ms = int(meta.get("internalDate", 0))
        ts    = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).isoformat()

        folder_detected = folder
        labels = meta.get("labelIds", [])
        if not folder_detected:
            folder_detected = "SPAM" if "SPAM" in labels else "INBOX"

        ctx = build_email_context(msg_id, service, folder_detected)
        if not ctx:
            return

        ctx.setdefault("email_hash", hashlib.sha256(
            f"{ctx.get('sender','')}{ctx.get('subject','')}{ctx.get('body_text','')[:200]}".encode()
        ).hexdigest())

        result     = await orchestrate(ctx, reports_dir="reports")
        scoring    = result.get("scoring", {})
        agents_raw = result.get("agents", {})

        agents_obj = {}
        for name, data in agents_raw.items():
            if isinstance(data, dict):
                sk = SCORE_KEYS.get(name, "")
                agents_obj[name] = {
                    "score":   data.get(sk, 0),
                    "verdict": str(data.get("verdict", "")),
                    "detail":  str(data.get("detail", ""))[:120],
                }

        doc = {
            "id":        ctx["email_hash"],
            "from":      ctx.get("sender",  "unknown"),
            "subject":   ctx.get("subject", "(no subject)"),
            "to":        "amira.ferchichi@etudiant-enit.utm.tn",
            "verdict":   normalize_verdict(scoring.get("verdict", "")),
            "score":     round(float(scoring.get("score_final", 0)), 1),
            "folder":    folder_detected,
            "timestamp": ts,
            "action":    scoring.get("action", ""),
            "hard_rule": scoring.get("hard_rule") or None,
            "agents":    agents_obj,
            "headers":   {},
        }

        save_to_json_server(doc)
        print(f"[AUTO] {folder_detected:5s} | {doc['verdict']:10s} | {doc['score']:5.1f}/100 | {ctx.get('subject','')[:55]}")

    except Exception as e:
        print(f"[AUTO ERR] {msg_id}: {e}")


# ── Analyse initiale des mails existants ──────────────────────────────────────

async def initial_batch(service, execute):
    """Au demarrage : recupere et analyse les N derniers mails INBOX+SPAM.
    Gmail retourne les messages du plus recent au plus ancien — pas besoin de tri."""
    print(f"[AUTO] Analyse initiale ({INITIAL_FETCH} mails par dossier)...")

    raw, seen = [], set()
    for label in ["INBOX", "SPAM"]:
        try:
            resp = execute(service.users().messages().list(
                userId="me", labelIds=[label], maxResults=INITIAL_FETCH
            ))
            for m in resp.get("messages", []):
                if m["id"] not in seen:
                    seen.add(m["id"])
                    m["_folder"] = label
                    raw.append(m)
        except Exception:
            continue

    if not raw:
        print("[AUTO] Aucun mail trouve pour l'analyse initiale.")
        return

    # Gmail retourne deja du plus recent au plus ancien — on prend les 10 premiers
    to_analyze = raw[:10]

    print(f"[AUTO] {len(to_analyze)} mail(s) a analyser en parallele...")
    tasks = [_safe(analyze_and_save(m["id"], m.get("_folder", "INBOX"), service, execute))
             for m in to_analyze]
    await asyncio.gather(*tasks)
    print("[AUTO] Analyse initiale terminee.")


# ── Un cycle de polling (nouveaux mails) ──────────────────────────────────────

async def poll_once(service, execute, state: dict):
    history_id = state.get("historyId", "")

    if not history_id:
        profile            = execute(service.users().getProfile(userId="me"))
        state["historyId"] = profile.get("historyId", "")
        save_state(state)
        return

    try:
        resp = execute(service.users().history().list(
            userId="me",
            startHistoryId=history_id,
            historyTypes=["messageAdded"],
        ))
    except Exception as e:
        profile            = execute(service.users().getProfile(userId="me"))
        state["historyId"] = profile.get("historyId", history_id)
        save_state(state)
        print(f"[AUTO] History expiree, reinitialisation: {e}")
        return

    tasks, seen = [], set()
    for record in resp.get("history", []):
        for added in record.get("messagesAdded", []):
            msg    = added.get("message", {})
            labels = msg.get("labelIds", [])
            mid    = msg.get("id", "")

            if not mid or mid in seen:
                continue

            # Forwarded/sent-to-self messages start with SENT label only in history.
            # Re-fetch current labels to catch messages that moved to INBOX after creation.
            if "INBOX" not in labels and "SPAM" not in labels:
                try:
                    current = execute(service.users().messages().get(
                        userId="me", id=mid, format="metadata", metadataHeaders=[],
                    ))
                    labels = current.get("labelIds", labels)
                except Exception:
                    pass

            if   "INBOX" in labels: folder = "INBOX"
            elif "SPAM"  in labels: folder = "SPAM"
            else:                   continue

            seen.add(mid)
            tasks.append(analyze_and_save(mid, folder, service, execute))

    if tasks:
        print(f"[AUTO] {len(tasks)} nouveau(x) mail(s) detecte(s) — analyse en cours...")
        await asyncio.gather(*[_safe(t) for t in tasks])

    state["historyId"] = resp.get("historyId", history_id)
    save_state(state)


# ── Boucle principale ──────────────────────────────────────────────────────────

async def main():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from orchestrator import get_gmail_service, _gmail_execute_with_retry

    service, execute = None, None
    for session in ["amira", "default"]:
        try:
            svc = get_gmail_service(session)
            _gmail_execute_with_retry(svc.users().getProfile(userId="me"))
            service = svc
            execute = _gmail_execute_with_retry
            break
        except Exception:
            continue

    if service is None:
        print("[AUTO] Impossible de se connecter a Gmail. Verifie ton token.")
        return

    # Supprimer l'ancien poll_state pour forcer une reinitialisation propre
    try:
        os.remove(STATE_FILE)
    except FileNotFoundError:
        pass

    print(f"[AUTO] Poller actif — verification toutes les {POLL_INTERVAL}s (INBOX + SPAM)")

    # Initialiser le historyId AVANT de lancer l'analyse initiale
    # pour ne rater aucun mail qui arrive pendant le batch
    state = {"historyId": ""}
    profile            = execute(service.users().getProfile(userId="me"))
    state["historyId"] = profile.get("historyId", "")
    save_state(state)
    print(f"[AUTO] Surveillance active (historyId={state['historyId']})")

    # Lancer l'analyse initiale en arriere-plan (ne bloque pas le polling)
    asyncio.create_task(initial_batch(service, execute))

    # Boucle de polling — demarre immediatement, n'attend pas le batch
    while True:
        try:
            await asyncio.sleep(POLL_INTERVAL)
            await poll_once(service, execute, state)
        except Exception as e:
            print(f"[AUTO ERR] {e}")


if __name__ == "__main__":
    asyncio.run(main())
