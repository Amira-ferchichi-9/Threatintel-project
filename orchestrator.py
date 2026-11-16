# orchestrator.py — v4.3
# Fix v4.3 :
#   - subject + sender passés à run_scoring_agent pour hard rules BEC
#   - apply_hard_rules supprimée (elle appartient à agent_scoring.py)
#   - email_data → email_context / subject / sender (variables locales)
#   - guardrail INBOX : auth absente + NLP suspect => quarantaine forcée
#   - fetch INBOX : 10 derniers mails
#   - robustesse Gmail : retry + skip message en erreur (ConnectionResetError)

import asyncio
import logging
import re
import os
import base64
import time
from agents.agent_auth    import run_auth_agent
from agents.agent_url     import run_url_agent
from agents.agent_nlp_bec import run_nlp_bec_agent
from agents.agent_sandbox import run_sandbox_agent
from agents.agent_scoring import run_scoring_agent
from report_generator     import generate_report
from cache                import get_cache
from cosmos_client import save_analysis

logging.basicConfig(level=logging.ERROR)


def extract_sender_domain(sender: str) -> str:
    match = re.search(r"@([\w.\-]+)", sender)
    return match.group(1).lower() if match else ""


def apply_inbox_guardrail(
    final_result: dict,
    auth_result: dict,
    nlp_result: dict,
    source_folder: str,
) -> dict:
    """
    Guardrail opérationnel côté orchestration.

    Objectif : éviter la livraison d'un email INBOX quand l'authentification
    est absente et le contenu est déjà jugé suspect par l'agent NLP.
    """
    if str(source_folder).upper() != "INBOX":
        return final_result

    score_auth = int(auth_result.get("score_auth", 0) or 0)
    score_nlp = int(nlp_result.get("score_nlp", 0) or 0)
    action = final_result.get("action", "")

    if score_auth <= 10 and score_nlp >= 40 and action == "DELIVER":
        final_result["prediction"] = 1
        final_result["verdict"] = "⚠️ SUSPECT — QUARANTAINE"
        final_result["action"] = "QUARANTINE"
        final_result["score_final"] = max(int(final_result.get("score_final", 0) or 0), 45)
        reason = "Guardrail INBOX : auth absente + NLP suspect"
        previous_rule = final_result.get("hard_rule")
        final_result["hard_rule"] = f"{previous_rule} | {reason}" if previous_rule else reason

    return final_result


async def orchestrate(email_context: dict, reports_dir: str = "reports") -> dict:
    print("\n" + "═" * 55)
    print(f"  📧 {email_context.get('subject', 'Sans sujet')[:50]}")
    print(f"  📤 {email_context.get('sender',  'Inconnu')[:50]}")
    folder = email_context.get("source_folder", "INBOX")
    print(f"  📁 Dossier : {folder}")
    print("═" * 55)

    cache      = get_cache()
    message_id = email_context.get("message_id", "")

    # ── CACHE CHECK : email déjà analysé ? ────────────────
    if message_id:
        cached = cache.get_email(message_id)
        if cached:
            print(f"  [CACHE HIT] Email déjà analysé — résultat instantané")
            print(f"  SCORE FINAL : {cached['scoring'].get('score_final')}/100")
            print(f"  VERDICT     : {cached['scoring'].get('verdict')}")
            print("═" * 55)
            return cached
        
    # ── HASH EMAIL (pour Cosmos DB save) ─────────────────
    email_hash = email_context.get("email_hash", "")
    if not email_hash:
        import hashlib
        raw = f"{email_context.get('sender','')}{email_context.get('subject','')}{email_context.get('body_text','')[:200]}"
        email_hash = hashlib.sha256(raw.encode()).hexdigest()
        email_context["email_hash"] = email_hash

    sender        = email_context.get("sender",    "")
    subject       = email_context.get("subject",   "")
    body_text     = email_context.get("body_text", "")
    attachments   = email_context.get("attachments", [])
    to_header     = email_context.get("to_header", "")
    cc_header     = email_context.get("cc_header", "")
    reply_to      = email_context.get("reply_to",  "")
    return_path   = email_context.get("return_path", "")
    auth_results  = email_context.get("authentication_results", "")
    arc_results   = email_context.get("arc_authentication_results", "")
    sender_domain = extract_sender_domain(sender)

    # ── ÉTAPE 1 : AUTH ────────────────────────────────────
    print("\n[⚡] Analyse authentification...")
    loop = asyncio.get_event_loop()

    cached_auth = cache.get_auth(sender_domain) if sender_domain else None
    if cached_auth:
        auth_result = cached_auth
        print(f"  [AUTH CACHE] {sender_domain}")
    else:
        auth_result = await loop.run_in_executor(
            None, run_auth_agent,
            sender, subject, to_header, cc_header,
            reply_to, return_path, auth_results, arc_results
        )
        if isinstance(auth_result, Exception):
            print(f"  [AUTH ERR] {auth_result}")
            auth_result = {
                "score_auth": 0, "verdict": "ERREUR AUTH",
                "detail": str(auth_result), "institutional_bonus": 0,
                "needs_nlp_review": False, "confidence_ceiling": 100,
            }
        elif sender_domain:
            cache.set_auth(
                sender_domain,
                auth_result.get("score_auth", 0),
                auth_result.get("detail", ""),
                auth_result.get("verdict", ""),
                auth_result.get("needs_nlp_review", False),
                auth_result.get("confidence_ceiling", 100),
            )

    print(f"  [AUTH]   {auth_result.get('verdict', '—')}")
    print(f"  [DETAIL] {auth_result.get('detail', '')[:160]}")

    institutional = False

    # ── ÉTAPE 2 : URL + NLP EN PARALLÈLE ─────────────────
    print("\n[⚡] Lancement agents URL + NLP...")

    cached_nlp = cache.get_nlp(body_text) if body_text else None
    if cached_nlp:
        nlp_result = cached_nlp
        print(f"  [NLP CACHE] body déjà connu")
        url_result = await loop.run_in_executor(None, run_url_agent, body_text, 5)
        if isinstance(url_result, Exception):
            url_result = {"score_url": 0, "verdict": "ERREUR URL"}
    else:
        # Extraire le vrai domaine si mail forwardé
        from agents.agent_nlp_bec import extract_forwarded_sender_domain
        forwarded_domain = extract_forwarded_sender_domain(body_text)
        effective_domain = forwarded_domain if forwarded_domain else sender_domain

        url_result, nlp_result = await asyncio.gather(
            loop.run_in_executor(None, run_url_agent, body_text, 5),
    loop.run_in_executor(None, run_nlp_bec_agent, subject, body_text,
                         effective_domain, institutional),
    return_exceptions=True
)
        
        if isinstance(url_result, Exception):
            print(f"  [URL ERR] {url_result}")
            url_result = {"score_url": 0, "verdict": "ERREUR URL"}
        if isinstance(nlp_result, Exception):
            print(f"  [NLP ERR] {nlp_result}")
            nlp_result = {"score_nlp": 0, "verdict": "ERREUR NLP"}
        else:
            cache.set_nlp(
                body_text,
                nlp_result.get("score_nlp", 0),
                nlp_result.get("verdict", ""),
                nlp_result.get("detail", "")
            )

    print(f"  [URL]   {url_result.get('verdict')}")
    print(f"  [NLP]   {nlp_result.get('verdict')}")

    # ── ÉTAPE 3 : SCORE PROVISOIRE → SANDBOX ─────────────
    score_provisoire = int(
        (100 - auth_result.get("score_auth", 0)) * 0.25 +
        url_result.get("score_url", 0)            * 0.35 +
        nlp_result.get("score_nlp", 0)            * 0.40
    )

    print(f"\n[🔬] Sandbox (score provisoire : {score_provisoire}/100)...")
    sandbox_result = run_sandbox_agent(
        attachments=attachments,
        score_provisoire=score_provisoire
    )
    print(f"  [SANDBOX] {sandbox_result.get('verdict')}")

    # ── ÉTAPE 4 : SCORING FINAL ───────────────────────────
    print("\n[🌲] Scoring final...")
    final_result = run_scoring_agent(
        score_auth    = auth_result.get("score_auth",      0),
        score_url     = url_result.get("score_url",        0),
        score_nlp     = nlp_result.get("score_nlp",        0),
        score_sandbox = sandbox_result.get("score_sandbox", 0),
        subject       = subject,
        sender        = sender
    )

    final_result = apply_inbox_guardrail(
        final_result=final_result,
        auth_result=auth_result,
        nlp_result=nlp_result,
        source_folder=folder,
    )

    print(f"\n{'═' * 55}")
    print(f"  SCORE FINAL : {final_result['score_final']}/100")
    print(f"  VERDICT     : {final_result['verdict']}")
    print(f"  ACTION      : {final_result['action']}")
    if final_result.get("hard_rule"):
        print(f"  REGLE       : {final_result['hard_rule']}")
    print("═" * 55)

    # ── ÉTAPE 5 : RAPPORT ─────────────────────────────────
    agents_results = {
        "auth":    auth_result,
        "url":     url_result,
        "nlp":     nlp_result,
        "sandbox": sandbox_result,
    }

    report_path = generate_report(
        email_context  = email_context,
        agents_results = agents_results,
        scoring        = final_result,
        output_dir     = reports_dir,
    )
    report_docx_path = os.path.splitext(report_path)[0] + ".docx"

    result = {
        "email":            email_context,
        "agents":           agents_results,
        "scoring":          final_result,
        "report_path":      report_path,
        "report_docx_path": report_docx_path,
    }

    if message_id:
        cache.set_email(message_id, result)
    # ── SAUVEGARDE COSMOS ─────────────────────────────────
    try:
        cosmos_result = {
            "auth_score":    auth_result.get("score_auth", 0),
            "url_score":     url_result.get("score_url", 0),
            "nlp_score":     nlp_result.get("score_nlp", 0),
            "sandbox_score": sandbox_result.get("score_sandbox", 0),
            "final_score":   final_result.get("score_final", 0),
            "verdict":       final_result.get("verdict", ""),
            "verdict_label": final_result.get("action", ""),
            "agent_details": agents_results,
            "report_path":   report_path,
        }
        doc_id = save_analysis(email_context, cosmos_result)
        print(f"  [COSMOS] Sauvegardé → {doc_id[:8]}...")
    except Exception as e:
        print(f"  [COSMOS ERR] {e}")

    # ── WEBHOOK CALLBACK (Logic App / external caller) ────────────────────────
    callback_url = email_context.get("callback_url")
    if callback_url:
        try:
            import requests as _req
            from datetime import datetime as _dt, timezone as _tz
            _payload = {
                "email_id":  message_id or email_hash[:16],
                "timestamp": _dt.now(_tz.utc).isoformat(),
                "subject":   subject,
                "sender":    sender,
                "verdict":   final_result.get("verdict", ""),
                "action":    final_result.get("action", ""),
                "score":     final_result.get("score_final", 0),
                "hard_rule": final_result.get("hard_rule"),
            }
            # fire-and-forget — don't block orchestrator on network latency
            loop.run_in_executor(None, lambda: _req.post(callback_url, json=_payload, timeout=10))
            print(f"  [WEBHOOK] Callback → {callback_url[:60]}")
        except Exception as _we:
            print(f"  [WEBHOOK ERR] {_we}")

    return result


# ─────────────────────────────────────────────────────────
# CONNEXION GMAIL
# ─────────────────────────────────────────────────────────
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def _is_retryable_http_error(exc: HttpError) -> bool:
    """Retourne True si l'erreur HTTP Gmail mérite un retry."""
    status = getattr(getattr(exc, "resp", None), "status", None)
    if status in (429, 500, 502, 503, 504):
        return True

    try:
        content = exc.content.decode("utf-8", errors="ignore").lower()
    except Exception:
        content = ""

    retry_tokens = ["rate", "backenderror", "temporarily", "timeout", "quota"]
    return any(token in content for token in retry_tokens)


def _gmail_execute_with_retry(request, retries: int = 4, base_delay: float = 1.2):
    """
    Exécute une requête Gmail API avec retries exponentiels.
    Évite l'arrêt global du pipeline sur erreurs réseau transitoires.
    """
    last_exc = None
    for attempt in range(retries):
        try:
            return request.execute()
        except HttpError as e:
            last_exc = e
            if not _is_retryable_http_error(e) or attempt == retries - 1:
                raise
        except (ConnectionResetError, TimeoutError, OSError) as e:
            last_exc = e
            if attempt == retries - 1:
                raise

        sleep_s = base_delay * (2 ** attempt)
        print(f"  [GMAIL RETRY] tentative {attempt + 1}/{retries} échouée, retry dans {sleep_s:.1f}s")
        time.sleep(sleep_s)

    if last_exc:
        raise last_exc


def get_gmail_service(session: str):
    creds      = None
    token_file = f'token_{session}.json'
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow  = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_file, 'w') as f:
            f.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)


def extract_body(payload: dict) -> str:
    def get_text(parts):
        text = ""
        for part in parts:
            if part.get('mimeType') == 'text/plain' and 'data' in part.get('body', {}):
                text += base64.urlsafe_b64decode(
                    part['body']['data']
                ).decode('utf-8', errors='ignore')
            elif 'parts' in part:
                text += get_text(part['parts'])
        return text
    if 'parts' in payload:
        return get_text(payload['parts'])
    elif 'data' in payload.get('body', {}):
        return base64.urlsafe_b64decode(
            payload['body']['data']
        ).decode('utf-8', errors='ignore')
    return ""


def extract_attachments(payload: dict, service, msg_id: str) -> list:
    allowed     = [".pdf", ".docx", ".xlsx", ".zip"]
    attachments = []

    def scan_parts(parts):
        for part in parts:
            filename = part.get('filename', '').lower()
            if any(filename.endswith(ext) for ext in allowed):
                att_id = part['body'].get('attachmentId')
                if att_id:
                    try:
                        att  = _gmail_execute_with_retry(
                            service.users().messages().attachments().get(
                                userId='me', messageId=msg_id, id=att_id
                            )
                        )
                        data = base64.urlsafe_b64decode(att['data'])
                        attachments.append({"name": filename, "data": data, "size": len(data)})
                    except Exception as e:
                        print(f"   [PJ ERR] {filename} : {e}")
            if 'parts' in part:
                scan_parts(part['parts'])

    scan_parts(payload.get('parts', []))
    return attachments


def build_email_context(msg_id: str, service, source_folder: str = "INBOX") -> dict:
    try:
        msg = _gmail_execute_with_retry(
            service.users().messages().get(userId='me', id=msg_id, format='full')
        )
    except Exception as e:
        print(f"  [GMAIL ERR] Lecture message {msg_id} échouée: {e}")
        return {}

    payload = msg['payload']
    headers = payload['headers']

    def get_header(name):
        return next(
            (h['value'] for h in headers if h['name'].lower() == name.lower()), ""
        )

    auth_results_list = [
        h['value'] for h in headers
        if h['name'].lower() == 'authentication-results'
    ]
    arc_auth_list = [
        h['value'] for h in headers
        if h['name'].lower() == 'arc-authentication-results'
    ]

    return {
        "message_id":                 msg_id,
        "source_folder":              source_folder,
        "subject":                    get_header("Subject"),
        "sender":                     get_header("From"),
        "reply_to":                   get_header("Reply-To"),
        "return_path":                get_header("Return-Path"),
        "authentication_results":     auth_results_list[0] if auth_results_list else "",
        "arc_authentication_results": arc_auth_list[0]     if arc_auth_list     else "",
        "body_text":                  extract_body(payload),
        "attachments":                extract_attachments(payload, service, msg_id),
        "to_header":                  get_header("To"),
        "cc_header":                  get_header("Cc"),
    }


def fetch_messages(service, max_inbox: int = 10, max_spam: int = 5) -> list:
    """
    Politique de collecte:
    - INBOX  : toujours les N derniers emails.
    - SPAM   : seulement les spams non lus (nouveaux), pour éviter
               de retraiter l'historique ancien du dossier SPAM.
    """
    seen    = set()
    results = []

    # INBOX — 10 derniers
    try:
        resp_inbox = _gmail_execute_with_retry(
            service.users().messages().list(
                userId='me',
                maxResults=max_inbox,
                labelIds=['INBOX'],
            )
        )
        inbox_messages = resp_inbox.get('messages', [])
        for m in inbox_messages:
            mid = m['id']
            if mid not in seen:
                seen.add(mid)
                results.append((mid, 'INBOX'))
        print(f"  [INBOX] {len(inbox_messages)} email(s) trouvé(s)")
    except Exception as e:
        print(f"  [INBOX] Erreur fetch : {e}")

    # SPAM — uniquement nouveaux/non lus
    try:
        resp_spam = _gmail_execute_with_retry(
            service.users().messages().list(
                userId='me',
                maxResults=max_spam,
                labelIds=['SPAM'],
                q='is:unread',
            )
        )
        spam_messages = resp_spam.get('messages', [])
        for m in spam_messages:
            mid = m['id']
            if mid not in seen:
                seen.add(mid)
                results.append((mid, 'SPAM'))

        if spam_messages:
            print(f"  [SPAM] {len(spam_messages)} nouveau(x) spam(s) non lu(s)")
        else:
            print("  [SPAM] Aucun nouveau spam non lu")
    except Exception as e:
        print(f"  [SPAM] Erreur fetch : {e}")
    
    return results


async def main_gmail():
    print("\n" + "#" * 55)
    print("  THREATINTEL — Détection Automatisée Multi-Agents")
    print("  v4.3 — Inbox 10 + Gmail retry network-safe")
    print("#" * 55)

    user    = input("\nSession utilisateur (ex: amira) : ").strip().lower()
    service = get_gmail_service(user)

    print(f"\nFetch emails (INBOX + SPAM)...")
    messages = fetch_messages(service, max_inbox=10, max_spam=5)

    if not messages:
        print("Aucun email trouvé.")
        return

    print(f"\n{len(messages)} email(s) à analyser.\n")

    cache = get_cache()
    if cache.available:
        stats = cache.stats()
        print(f"[CACHE] {stats.get('total_keys', 0)} entrées en cache")
        print(f"[CACHE] Hits: {stats.get('hits', 0)} | Misses: {stats.get('misses', 0)}\n")

    for msg_id, folder in messages:
        context = build_email_context(msg_id, service, source_folder=folder)
        if not context:
            print(f"  [SKIP] Message ignoré (erreur lecture Gmail): {msg_id}")
            continue
        result  = await orchestrate(context, reports_dir="reports")
        print(f"  Rapport JSON : {result.get('report_path', 'N/A')}")
        print(f"  Rapport DOCX : {result.get('report_docx_path', 'N/A')}")

    if cache.available:
        stats = cache.stats()
        print(f"\n[CACHE] Session terminée")
        print(f"[CACHE] Hits: {stats.get('hits', 0)} | Misses: {stats.get('misses', 0)}")
        print(f"[CACHE] Clés stockées : {stats.get('keys', {})}")


if __name__ == "__main__":
    asyncio.run(main_gmail())