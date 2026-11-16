# cache.py — ThreatIntel Redis Cache v1.0
"""
Cache Redis centralisé pour ThreatIntel.
4 namespaces : email / url / nlp / auth

Usage:
    from cache import get_cache
    cache = get_cache()

    # Email (message_id → résultat complet)
    cache.get_email("msg_id_123")
    cache.set_email("msg_id_123", result_dict)

    # URL (url → score + detail)
    cache.get_url("https://paypal-verify.top")
    cache.set_url("https://paypal-verify.top", 90, "CRITICAL: Imitation PayPal")

    # NLP (body text → score + verdict)
    cache.get_nlp("body text here...")
    cache.set_nlp("body text here...", score, verdict)

    # AUTH (sender_domain → score + detail)
    cache.get_auth("gmail.com")
    cache.set_auth("gmail.com", score, detail)
"""

import json
import hashlib
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)

# ── TTL par namespace ──────────────────────────────────────
TTL_EMAIL = 86400       # 24h  — résultat complet email
TTL_URL   = 3600        # 1h   — score URL (phishing évolue vite)
TTL_NLP   = 21600       # 6h   — analyse NLP
TTL_AUTH  = 43200       # 12h  — réputation domaine expéditeur

# ── Préfixes des clés Redis ────────────────────────────────
PREFIX_EMAIL = "threatintel:email:"
PREFIX_URL   = "threatintel:url:"
PREFIX_NLP   = "threatintel:nlp:"
PREFIX_AUTH  = "threatintel:auth:"


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


class ThreatIntelCache:
    """
    Wrapper Redis pour ThreatIntel.
    Si Redis est indisponible, fonctionne en mode dégradé (no-op).
    """

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        self._client = None
        self._available = False
        self._connect(host, port, db)

    def _connect(self, host: str, port: int, db: int):
        try:
            import redis
            client = redis.Redis(
                host=host, port=port, db=db,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
            client.ping()
            self._client = client
            self._available = True
            logger.info(f"[CACHE] Redis connecte sur {host}:{port}")
            print(f"[CACHE] Redis OK — {host}:{port}")
        except Exception as e:
            self._available = False
            logger.warning(f"[CACHE] Redis indisponible : {e}")
            print(f"[CACHE] Redis indisponible — mode sans cache ({e})")

    @property
    def available(self) -> bool:
        return self._available

    # ── Helpers internes ──────────────────────────────────

    def _get(self, key: str) -> Optional[dict]:
        if not self._available:
            return None
        try:
            raw = self._client.get(key)
            if raw:
                return json.loads(raw)
        except Exception as e:
            logger.debug(f"[CACHE] GET error {key}: {e}")
        return None

    def _set(self, key: str, value: dict, ttl: int):
        if not self._available:
            return
        try:
            self._client.setex(key, ttl, json.dumps(value, ensure_ascii=False))
        except Exception as e:
            logger.debug(f"[CACHE] SET error {key}: {e}")

    def _delete(self, key: str):
        if not self._available:
            return
        try:
            self._client.delete(key)
        except Exception as e:
            logger.debug(f"[CACHE] DEL error {key}: {e}")

    # ── Namespace EMAIL ────────────────────────────────────

    def get_email(self, message_id: str) -> Optional[dict]:
        """Retourne le résultat complet d'analyse si déjà traité."""
        key = PREFIX_EMAIL + message_id
        result = self._get(key)
        if result:
            logger.info(f"[CACHE HIT] email {message_id[:20]}...")
        return result

    def set_email(self, message_id: str, result: dict):
        """Stocke le résultat complet d'analyse d'un email."""
        key = PREFIX_EMAIL + message_id
        # On ne stocke que les champs essentiels (pas les pièces jointes binaires)
        payload = {
            "message_id":    message_id,
            "subject":       result.get("email", {}).get("subject", ""),
            "sender":        result.get("email", {}).get("sender", ""),
            "source_folder": result.get("email", {}).get("source_folder", "INBOX"),
            "scoring":       result.get("scoring", {}),
            "agents": {
                "auth":    {k: v for k, v in result.get("agents", {}).get("auth", {}).items()
                            if k not in ("raw",)},
                "url":     result.get("agents", {}).get("url", {}),
                "nlp":     result.get("agents", {}).get("nlp", {}),
                "sandbox": {k: v for k, v in result.get("agents", {}).get("sandbox", {}).items()
                            if k != "data"},
            },
            "cached_at": int(time.time()),
        }
        self._set(key, payload, TTL_EMAIL)
        logger.info(f"[CACHE SET] email {message_id[:20]}...")

    def invalidate_email(self, message_id: str):
        """Force la ré-analyse d'un email (ex: après update du modèle)."""
        self._delete(PREFIX_EMAIL + message_id)

    # ── Namespace URL ──────────────────────────────────────

    def get_url(self, url: str) -> Optional[dict]:
        """Retourne {score, detail} si l'URL a déjà été analysée."""
        key = PREFIX_URL + _md5(url)
        return self._get(key)

    def set_url(self, url: str, score: int, detail: str):
        """Stocke le score d'une URL."""
        key = PREFIX_URL + _md5(url)
        self._set(key, {"score": score, "detail": detail, "url": url[:200]}, TTL_URL)

    # ── Namespace NLP ──────────────────────────────────────

    def get_nlp(self, body_text: str) -> Optional[dict]:
        """Retourne {score_nlp, verdict} si ce corps de mail a déjà été analysé."""
        # Hash sur les 2000 premiers caractères (le début porte le signal phishing)
        key = PREFIX_NLP + _md5(body_text[:2000])
        return self._get(key)

    def set_nlp(self, body_text: str, score: int, verdict: str, detail: str = ""):
        """Stocke le résultat NLP d'un corps de mail."""
        key = PREFIX_NLP + _md5(body_text[:2000])
        self._set(key, {
            "score_nlp": score,
            "verdict":   verdict,
            "detail":    detail,
        }, TTL_NLP)

    # ── Namespace AUTH ─────────────────────────────────────

    def get_auth(self, sender_domain: str) -> Optional[dict]:
        """Retourne {score_auth, detail} si ce domaine expéditeur a déjà été analysé."""
        key = PREFIX_AUTH + sender_domain.lower()
        return self._get(key)

    def set_auth(self, sender_domain: str, score: int, detail: str,
                 verdict: str = "", needs_nlp_review: bool = False,
                 confidence_ceiling: int = 100):
        """Stocke la réputation d'un domaine expéditeur."""
        key = PREFIX_AUTH + sender_domain.lower()
        self._set(key, {
            "score_auth":         score,
            "detail":             detail,
            "verdict":            verdict,
            "needs_nlp_review":   needs_nlp_review,
            "confidence_ceiling": confidence_ceiling,
        }, TTL_AUTH)

    # ── Stats ──────────────────────────────────────────────

    def stats(self) -> dict:
        """Retourne les stats du cache Redis."""
        if not self._available:
            return {"available": False}
        try:
            info = self._client.info("stats")
            keys_by_ns = {}
            for prefix, name in [
                (PREFIX_EMAIL, "email"),
                (PREFIX_URL,   "url"),
                (PREFIX_NLP,   "nlp"),
                (PREFIX_AUTH,  "auth"),
            ]:
                keys_by_ns[name] = len(self._client.keys(f"{prefix}*"))
            return {
                "available":    True,
                "hits":         info.get("keyspace_hits",   0),
                "misses":       info.get("keyspace_misses", 0),
                "keys":         keys_by_ns,
                "total_keys":   sum(keys_by_ns.values()),
            }
        except Exception as e:
            return {"available": True, "error": str(e)}


# ── Singleton ──────────────────────────────────────────────
_cache_instance: Optional[ThreatIntelCache] = None


def get_cache(host: str = "localhost", port: int = 6379) -> ThreatIntelCache:
    """Retourne l'instance singleton du cache."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = ThreatIntelCache(host=host, port=port)
    return _cache_instance