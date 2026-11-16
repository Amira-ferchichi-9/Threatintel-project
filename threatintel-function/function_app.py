import asyncio
import json
import logging
import os
import sys

import azure.functions as func
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

# Add the parent project directory (PFA_2) so we can import orchestrator.py
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

app = func.FunctionApp()
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def get_gmail_service_from_blob() -> object:
    """Load Gmail OAuth token from Azure Blob, refresh if needed, and return Gmail API service."""
    from azure.storage.blob import BlobServiceClient

    storage_connection = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "")
    if not storage_connection:
        raise ValueError("AZURE_STORAGE_CONNECTION_STRING is not set")

    container_name = "gmail-tokens"
    blob_name = "token_default.json"

    blob_service_client = BlobServiceClient.from_connection_string(storage_connection)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)

    token_json = blob_client.download_blob().readall().decode("utf-8")
    token_info = json.loads(token_json)
    creds = Credentials.from_authorized_user_info(token_info, SCOPES)

    if creds.expired:
        if not creds.refresh_token:
            raise ValueError("Gmail token is expired and has no refresh token")
        creds.refresh(Request())
        blob_client.upload_blob(creds.to_json(), overwrite=True)

    return build("gmail", "v1", credentials=creds)


def _run_orchestrate_sync(email_context: dict, orchestrate_fn) -> dict:
    """Sync-safe entrypoint when no event loop is available."""
    return asyncio.run(orchestrate_fn(email_context))


async def _run_orchestrate(email_context: dict, orchestrate_fn) -> dict:
    """
    Run orchestrate in both async and sync contexts.
    - If we're already in an event loop, await directly.
    - Otherwise, execute asyncio.run in a worker thread.
    """
    try:
        asyncio.get_running_loop()
        return await orchestrate_fn(email_context)
    except RuntimeError:
        return await asyncio.to_thread(_run_orchestrate_sync, email_context, orchestrate_fn)


@app.service_bus_queue_trigger(
    arg_name="azservicebus",
    queue_name="email-analysis-queue",
    connection="ServiceBusConnection",
)
async def EmailAnalyzer(azservicebus: func.ServiceBusMessage) -> None:
    raw_payload = ""
    try:
        from orchestrator import build_email_context, orchestrate

        raw_payload = azservicebus.get_body().decode("utf-8")
        logging.info("[RECEPTION] Message Service Bus recu: %s", raw_payload)

        payload = json.loads(raw_payload)
        message_id = payload.get("message_id")
        if not message_id:
            logging.error("[EXTRACTION] message_id manquant dans le payload JSON")
            return

        logging.info("[EXTRACTION] message_id extrait: %s", message_id)

        service = get_gmail_service_from_blob()

        email_context = build_email_context(message_id, service)
        if not email_context:
            logging.error("[EXTRACTION] email_context vide pour message_id=%s", message_id)
            return

        logging.info("[ANALYSE] Lancement orchestration multi-agents...")
        result = await _run_orchestrate(email_context, orchestrate)

        logging.info("[SAUVEGARDE] Analyse terminee et sauvegarde geree par orchestrator")

        verdict = (
            (result or {})
            .get("scoring", {})
            .get("verdict", "INCONNU")
        )
        logging.info("[ANALYSE] Verdict final: %s", verdict)

    except json.JSONDecodeError as exc:
        logging.error("Payload JSON invalide: %s | payload=%s", exc, raw_payload, exc_info=True)
    except Exception as exc:
        logging.error("Erreur non geree dans EmailAnalyzer: %s", exc, exc_info=True)
