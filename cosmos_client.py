# cosmos_client.py — Intégration Azure Cosmos DB
# Stocke chaque analyse email + permet recherche par hash

import os
import uuid
import logging
from datetime import datetime, timezone
from azure.cosmos import CosmosClient, PartitionKey, exceptions

# ─── Initialisation ───────────────────────────────────────────
_client = None
_container = None

def get_container():
    global _client, _container
    if _container:
        return _container

    endpoint = os.getenv("COSMOS_ENDPOINT")
    key      = os.getenv("COSMOS_KEY")
    db_name  = os.getenv("COSMOS_DATABASE", "pfa_email_threats")
    cont_name = os.getenv("COSMOS_CONTAINER", "analyses")

    if not endpoint or not key:
        raise ValueError("COSMOS_ENDPOINT et COSMOS_KEY manquants dans .env")

    try:
        _client = CosmosClient(endpoint, credential=key)
    except Exception as e:
        logging.warning("CosmosClient init failed: %s", e)
        return None

    try:
        # Crée la base si elle n'existe pas
        db = _client.create_database_if_not_exists(id=db_name)

        # Crée le conteneur si il n'existe pas (partition par email_hash)
        _container = db.create_container_if_not_exists(
            id=cont_name,
            partition_key=PartitionKey(path="/email_hash"),
        )
        return _container
    except Exception as e:
        logging.warning("Cosmos DB unavailable (db/container): %s", e)
        return None


# ─── Vérifier si un email a déjà été analysé ──────────────────
def get_analysis_by_hash(email_hash: str) -> dict | None:
    """
    Retourne l'analyse existante si l'email a déjà été vu,
    sinon retourne None.
    """
    container = get_container()
    if not container:
        return None

    try:
        query = f"SELECT * FROM c WHERE c.email_hash = '{email_hash}'"
        items = list(container.query_items(query=query, enable_cross_partition_query=True))
        return items[0] if items else None
    except exceptions.CosmosHttpResponseError:
        return None


# ─── Sauvegarder une nouvelle analyse ─────────────────────────
def save_analysis(email_context: dict, result: dict) -> str:
    """
    Sauvegarde le résultat complet d'une analyse dans Cosmos DB.
    Retourne l'ID du document créé.
    """
    container = get_container()

    doc_id = str(uuid.uuid4())

    if not container:
        logging.warning("Cosmos unavailable — skipping save for analysis %s", doc_id)
        return doc_id

    document = {
        "id": doc_id,
        "email_hash": email_context.get("email_hash", ""),
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # Métadonnées email
        "subject":       email_context.get("subject", ""),
        "sender":        email_context.get("sender", ""),
        "source_folder": email_context.get("source_folder", "INBOX"),
        "has_attachment": email_context.get("has_attachment", False),

        # Scores des agents
        "scores": {
            "auth":    result.get("auth_score", 0),
            "url":     result.get("url_score", 0),
            "nlp_bec": result.get("nlp_score", 0),
            "sandbox": result.get("sandbox_score", 0),
            "final":   result.get("final_score", 0),
        },

        # Verdict
        "verdict":        result.get("verdict", "INCONNU"),
        "verdict_label":  result.get("verdict_label", ""),

        # Détails agents
        "agent_details": result.get("agent_details", {}),

        # Rapport HTML
        "report_path": result.get("report_path", ""),
    }

    container.create_item(body=document)
    return doc_id


# ─── Récupérer les dernières analyses ─────────────────────────
def get_recent_analyses(limit: int = 50) -> list:
    """Retourne les N dernières analyses triées par date."""
    container = get_container()
    if not container:
        return []
    query = f"""
        SELECT c.id, c.timestamp, c.subject, c.sender,
               c.verdict, c.scores.final, c.email_hash
        FROM c
        ORDER BY c.timestamp DESC
        OFFSET 0 LIMIT {limit}
    """
    try:
        return list(container.query_items(query=query, enable_cross_partition_query=True))
    except Exception:
        return []


# ─── Stats globales ───────────────────────────────────────────
def get_stats() -> dict:
    """Retourne des statistiques globales sur toutes les analyses."""
    container = get_container()
    if not container:
        return {"total": 0, "sain": 0, "suspect": 0, "danger": 0, "avg_score": 0}
    try:
        all_items = list(container.query_items(
            query="SELECT c.verdict, c.scores.final FROM c",
            enable_cross_partition_query=True
        ))
        total = len(all_items)
        if total == 0:
            return {"total": 0, "sain": 0, "suspect": 0, "danger": 0, "avg_score": 0}

        verdicts = [i.get("verdict", "") for i in all_items]
        scores   = [i.get("final", 0) for i in all_items]

        return {
            "total":     total,
            "sain":      verdicts.count("SAIN"),
            "suspect":   verdicts.count("SUSPECT"),
            "danger":    verdicts.count("DANGER"),
            "avg_score": round(sum(scores) / total, 2)
        }
    except Exception:
        return {"total": 0, "sain": 0, "suspect": 0, "danger": 0, "avg_score": 0}
