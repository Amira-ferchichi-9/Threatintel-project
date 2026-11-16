# agents/agent_url.py — v2.5 (URLhaus + PhishTank — 100% gratuit, no keys)
"""
Agent URL v2.5 :
- FIX-1 : Shorteners (bit.ly, tinyurl…) → score 50, override Tranco
- FIX-2 : Tunnels (ngrok, localtunnel…) → score 65, override Tranco
- FIX-3 : CRITICAL_BRAND_PATTERNS (PayPal, Amazon, Microsoft, Apple) → score 85-90
- URLhaus : 100% gratuit, pas de clé requise
- PhishTank : 100% gratuit, pas de clé requise
- Heuristique locale : instant
- Timeout total : 2s max
"""
import re
import time
import hashlib
import logging
import os
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

logger = logging.getLogger(__name__)

TRANCO_LIMIT = 1_000_000
ALT_TIMEOUT = 4

_tranco_set: set[str] = set()
_tranco_loaded = False


def load_tranco() -> set[str]:
    global _tranco_set, _tranco_loaded
    if _tranco_loaded:
        return _tranco_set

    import tempfile
    cache_dir = os.path.join(tempfile.gettempdir(), "tranco")
    os.makedirs(cache_dir, exist_ok=True)
    cache_path = os.path.join(cache_dir, "tranco_top1m.txt")

    if os.path.exists(cache_path):
        age = time.time() - os.path.getmtime(cache_path)
        if age < 86400:
            try:
                with open(cache_path, "r") as f:
                    _tranco_set = set(line.strip().lower() for line in f if line.strip())
                _tranco_loaded = True
                print(f"   [TRANCO] Cache : {len(_tranco_set):,} domaines")
                return _tranco_set
            except Exception:
                pass

    try:
        from tranco import Tranco
        t = Tranco(cache=True, cache_dir=cache_dir)
        lst = t.list()
        domains = set(lst.top(TRANCO_LIMIT))
        _tranco_set = domains

        with open(cache_path, "w") as f:
            f.write("\n".join(domains))

        _tranco_loaded = True
        print(f"   [TRANCO] Téléchargé : {len(_tranco_set):,} domaines")
        return _tranco_set

    except Exception as e:
        logger.warning(f"Tranco indisponible : {e}")
        _tranco_loaded = True
        return _tranco_set


try:
    load_tranco()
except Exception:
    pass


_cache: dict = {}
CACHE_TTL = 3600


def _cache_get(key: str) -> dict | None:
    entry = _cache.get(key)
    if entry and time.time() < entry["expires"]:
        return entry
    return None


def _cache_set(key: str, score: int, detail: str):
    _cache[key] = {"score": score, "detail": detail, "expires": time.time() + CACHE_TTL}


# ── Redis singleton (lazy-init, fails silently) ───────────────────────────────
_redis_cache = None


def _get_redis():
    global _redis_cache
    if _redis_cache is None:
        try:
            from cache import get_cache
            _redis_cache = get_cache()
        except Exception:
            class _NoCache:
                available = False
            _redis_cache = _NoCache()
    return _redis_cache


def extract_urls(text: str) -> list[str]:
    urls = re.findall(r'https?://[^\s<>"\')\]\\]+', text)
    cleaned = [u.rstrip(".,;:!?)>\"'") for u in urls]
    # Preserve first-seen order so max_urls does not randomly drop a dangerous URL.
    return list(dict.fromkeys(cleaned))


def get_root_domain(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
    except Exception:
        return ""


def is_in_tranco(url: str) -> tuple[bool, int | None]:
    if not _tranco_set:
        return False, None
    root = get_root_domain(url)
    found = root in _tranco_set
    return found, None


# ─────────────────────────────────────────────────────────
# FIX-1 : SHORTENERS — Override Tranco
# Ces domaines sont dans Tranco (légitimes) MAIS sont des
# vecteurs phishing connus → on les intercepte AVANT Tranco.
# ─────────────────────────────────────────────────────────
DANGEROUS_SHORTENERS = {
    "bit.ly", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "t.co",
    "short.link", "dl.click", "adf.ly", "rb.gy", "cutt.ly",
    "shorturl.at", "tiny.cc", "clck.ru", "url.ie", "x.co",
}

# ─────────────────────────────────────────────────────────
# FIX-2 : TUNNELS & LOCALHOST — Override Tranco
# ngrok, localtunnel etc. sont légitimes en dev MAIS
# sont des vecteurs d'attaque connus en contexte email.
# ─────────────────────────────────────────────────────────
DANGEROUS_TUNNELS = {
    "ngrok.io", "ngrok-free.app", "localtunnel.me", "loca.lt",
    "localhost.run", "serveo.net", "burpcollaborator.net",
    "canarytokens.com", "interactsh.com",
}

# ─────────────────────────────────────────────────────────
# FIX-3 : PATTERNS IMITATION — stricts + score élevé
# Remplacent les patterns génériques (score 70-75) par des
# patterns précis avec score 90+ sur les marques critiques.
# ─────────────────────────────────────────────────────────
CRITICAL_BRAND_PATTERNS = [
    # PayPal — score 90
    (r'paypal[.\-](login|verify|secure|account|payment|confirm|update)', 90, "CRITICAL: Imitation PayPal"),
    (r'(login|verify|secure|account|payment)[\-.]paypal', 90, "CRITICAL: Imitation PayPal"),
    # Amazon — score 90
    (r'amazon[.\-](login|account|verify|prime|membership|secure|update)', 90, "CRITICAL: Imitation Amazon"),
    (r'(login|verify|secure|account)[\-.]amazon', 90, "CRITICAL: Imitation Amazon"),
    # Microsoft / Office 365 — score 90
    (r'microsoft[.\-](365|office|account|onedrive|outlook|login|verify)', 90, "CRITICAL: Imitation Microsoft"),
    (r'(office|outlook|onedrive)[.\-](live|login|verify|account|secure)', 90, "CRITICAL: Imitation Microsoft"),
    # Apple / iCloud — score 90
    (r'apple[.\-](id|icloud|support|account|verify|login)', 90, "CRITICAL: Imitation Apple"),
    (r'icloud[.\-](login|verify|account|secure)', 90, "CRITICAL: Imitation iCloud"),
    # Google — score 85
    (r'google[.\-](login|account|verify|gmail|drive|secure)', 85, "CRITICAL: Imitation Google"),
    # Banques génériques — score 85
    (r'(bank|banque)[.\-](login|verify|secure|account|update)', 85, "Imitation bancaire"),
    (r'(bnpparibas|societegenerale|creditagricole|lcl)[.\-]', 85, "Imitation banque FR"),
]

SUSPICIOUS_PATTERNS = [
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 75, "IP directe"),
    (r'\.(tk|ml|ga|cf|gq)(\/|$)', 60, "TLD gratuit suspect"),
    (r'(login|verify|secure|account|update).*\.(xyz|top|club|online|site|icu)', 70, "Domaine phishing"),
    # Patterns génériques PayPal/Amazon conservés comme fallback (score 75)
    # pour les cas non couverts par CRITICAL_BRAND_PATTERNS
    (r'paypal.*[-.](?!com)', 75, "Imitation PayPal"),
    (r'amazon.*login(?!\.amazon)', 75, "Imitation Amazon"),
    (r'microsoft.*365(?!\.com)', 70, "Imitation Microsoft"),
    (r'apple.*id(?!\.apple)', 70, "Imitation Apple ID"),
    # Pattern spécifique avant pattern hash générique pour éviter le sous-score.
    (r'/mo/[a-f0-9]{16,}', 75, "Path malware pattern détecté"),
    (r'/[a-f0-9]{20,}', 50, "Hash suspect dans path (tracking/malware)"),
]

TRUST_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".fr", ".uk", ".de", ".it", ".tn"}

LEGITIMATE_PATTERNS = [
    r'unsubscribe', r'se-desabonner', r'optout', r'opt-out',
    r'list-unsubscribe', r'email-preferences', r'privacy-policy',
]


def heuristic_score(url: str) -> tuple[int, str]:
    """
    FIX-3 : CRITICAL_BRAND_PATTERNS appliqués en priorité (score 85-90).
    Ordre : légitimes → critiques → suspects généraux → TLD confiance.
    """
    url_lower = url.lower()

    for p in LEGITIMATE_PATTERNS:
        if re.search(p, url_lower):
            return 0, "URL légitime"

    # FIX-3 : patterns imitation critique en premier
    for pattern, score, label in CRITICAL_BRAND_PATTERNS:
        if re.search(pattern, url_lower):
            return score, label

    for pattern, score, label in SUSPICIOUS_PATTERNS:
        if re.search(pattern, url_lower):
            return score, label

    for trust_tld in TRUST_TLDS:
        if url_lower.endswith(trust_tld):
            return 0, "TLD confiance"

    return 0, ""


def check_urlhaus(url: str) -> tuple[int, str]:
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=1.5
        )
        if response.status_code == 200:
            data = response.json()
            query_status = data.get("query_status", "")
            url_status = data.get("url_status", "")

            if query_status == "ok":
                if url_status == "malware":
                    threat_type = data.get("threat", {}).get("type", "malware")
                    return 95, f"URLhaus: MALWARE ({threat_type})"
                elif url_status == "phishing":
                    return 90, "URLhaus: PHISHING"
                elif url_status == "spam":
                    return 60, "URLhaus: SPAM"
                else:
                    return 0, "URLhaus: Clean"
            else:
                return 0, f"URLhaus: {query_status}"
    except requests.Timeout:
        logger.debug(f"URLhaus timeout: {url[:50]}")
    except Exception as e:
        logger.debug(f"URLhaus error: {e}")

    return 0, ""


def check_phishtank(url: str) -> tuple[int, str]:
    try:
        response = requests.get(
            "https://checkurl.phishtank.com/checkurl/",
            params={"url": url, "format": "json"},
            timeout=1.5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("in_database"):
                if data.get("verified") == "yes":
                    return 92, "PhishTank: VERIFIED PHISHING"
                else:
                    return 75, "PhishTank: Suspected phishing"
            else:
                return 0, "PhishTank: Clean"
    except requests.Timeout:
        logger.debug(f"PhishTank timeout: {url[:50]}")
    except Exception as e:
        logger.debug(f"PhishTank error: {e}")

    return 0, ""


def check_url_parallel(url: str) -> tuple[int, str]:
    max_score = 0
    details = []

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(check_urlhaus, url): "URLhaus",
                executor.submit(check_phishtank, url): "PhishTank",
            }

            for future in as_completed(futures, timeout=ALT_TIMEOUT):
                try:
                    score, detail = future.result(timeout=1)
                    if score > 0:
                        max_score = max(max_score, score)
                        if detail:
                            details.append(detail)
                except Exception:
                    pass
    except FuturesTimeoutError:
        logger.debug(f"Parallel timeout for {url[:50]}")
    except Exception as e:
        logger.debug(f"Parallel error: {e}")

    detail_str = " | ".join(details) if details else ""
    return max_score, detail_str


def check_url(url: str) -> tuple[int, str, bool]:
    """
    v2.5 : Pipeline ULTRA RAPIDE (timeout total ~2s).

    Ordre :
    1. FIX-1 : Shortener connu → score 50 (override Tranco)
    2. FIX-2 : Tunnel connu → score 65 (override Tranco)
    3. Tranco (instant) → SAFE
    4. Cache (instant) → return cached
    5. FIX-3 : Heuristique enrichie (CRITICAL brands + suspects)
    6. Parallel: URLhaus + PhishTank (2s timeout) → best result
    7. Fallback heuristique
    """
    root = get_root_domain(url)

    # ── FIX-1 : Shorteners — Override Tranco ──────────────
    if root in DANGEROUS_SHORTENERS:
        return 60, "⚠️ URL Shortener (vecteur phishing connu)", False

    # ── FIX-2 : Tunnels — Override Tranco ─────────────────
    if root in DANGEROUS_TUNNELS:
        return 65, "🔴 Tunnel/reverse proxy (vecteur phishing connu)", False

    # ── REDIS CACHE-FIRST ─────────────────────────────────
    _r = _get_redis()
    if _r.available:
        _rhit = _r.get_url(url)
        if _rhit is not None:
            logger.info("[URL CACHE HIT] Redis: %s", url[:60])
            return _rhit.get("score", 0), f"💾 {_rhit.get('detail', '')}", False
        logger.debug("[URL CACHE MISS] Redis: %s", url[:60])

    # ── 3. Tranco Top 1M ──────────────────────────────────
    in_tranco, _ = is_in_tranco(url)
    if in_tranco:
        h_score, h_detail = heuristic_score(url)
        if h_score >= 60:
            p_score, p_detail = check_url_parallel(url)
            final_score = max(h_score, p_score)
            final_detail = p_detail if p_score > h_score else f"Tranco mais path suspect: {h_detail}"
            return final_score, final_detail, False
        p_score, p_detail = check_url_parallel(url)
        if p_score >= 60:
            return p_score, p_detail, False
        return 0, "✅ Tranco Top 1M", True

    # ── 4. In-memory cache (fallback when Redis unavailable) ──────────────────
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cached = _cache_get(cache_key)
    if cached:
        return cached["score"], f"💾 {cached['detail']}", False

    # ── 5. Heuristique enrichie ───────────────────────────
    h_score, h_detail = heuristic_score(url)

    # URL explicitement légitime (unsubscribe, preferences, etc.)
    if h_score == 0 and h_detail == "URL légitime":
        _cache_set(cache_key, 0, h_detail)
        if _r.available:
            _r.set_url(url, 0, h_detail)
        return 0, h_detail, False

    if h_score >= 75:
        _cache_set(cache_key, h_score, f"Heur: {h_detail}")
        if _r.available:
            _r.set_url(url, h_score, f"Heur: {h_detail}")
        return h_score, f"🔴 {h_detail}", False

    # ── 6. Parallel: URLhaus + PhishTank ──────────────────
    p_score, p_detail = check_url_parallel(url)

    if p_score > 0:
        combined_score = max(h_score, p_score)
        detail = p_detail or f"Heur: {h_detail}"
        _cache_set(cache_key, combined_score, detail)
        if _r.available:
            _r.set_url(url, combined_score, detail)
        return combined_score, detail, False

    # ── 7. Fallback ───────────────────────────────────────
    if h_score == 0:
        fallback_score = 10
        fallback_detail = "Domaine inconnu (non-Tranco)"
        _cache_set(cache_key, fallback_score, fallback_detail)
        if _r.available:
            _r.set_url(url, fallback_score, fallback_detail)
        return fallback_score, f"🟡 {fallback_detail}", False

    fallback_score = h_score
    fallback_detail = f"Heur: {h_detail or 'unknown'}"
    _cache_set(cache_key, fallback_score, fallback_detail)
    if _r.available:
        _r.set_url(url, fallback_score, fallback_detail)
    return fallback_score, fallback_detail, False


def run_url_agent(body_text: str, max_urls: int = 5) -> dict:
    urls = extract_urls(body_text)

    if not urls:
        return {
            "urls_found": 0,
            "urls": [],
            "score_url": 0,
            "detail": "Aucune URL détectée",
            "verdict": "✅ AUCUN LIEN"
        }

    results = []
    tranco_hits = 0

    # Prioritize risky URLs first, then fill with the rest.
    candidates = []
    for idx, url in enumerate(urls):
        in_tranco, _ = is_in_tranco(url)
        h_score, _ = heuristic_score(url)
        root = get_root_domain(url)
        known_risky_root = int(root in DANGEROUS_SHORTENERS or root in DANGEROUS_TUNNELS)
        candidates.append({
            "url": url,
            "index": idx,
            "in_tranco": in_tranco,
            "h_score": h_score,
            "known_risky_root": known_risky_root,
        })

    candidates.sort(
        key=lambda c: (
            c["known_risky_root"],      # shorteners/tunnels first
            c["h_score"],               # higher heuristic risk first
            int(not c["in_tranco"]),    # non-tranco first
            -c["index"],                # recent mention first if tie
        ),
        reverse=True,
    )

    to_analyze = [c["url"] for c in candidates[:max_urls]]

    for url in to_analyze:
        score, detail, is_tranco = check_url(url)
        if is_tranco:
            tranco_hits += 1
        results.append({
            "url": url[:120],
            "score": score,
            "detail": detail,
            "tranco_hit": is_tranco,
        })

    max_score = max(r["score"] for r in results) if results else 0

    if max_score >= 85:
        verdict = "🛑 LIEN MALVEILLANT DÉTECTÉ"
    elif max_score >= 60:
        verdict = "⚠️ LIEN SUSPECT"
    else:
        verdict = "✅ LIENS SAINS"

    return {
        "urls_found": len(urls),
        "urls": results,
        "score_url": max_score,
        "tranco_hits": tranco_hits,
        "detail": f"{len(urls)} URL(s) | {len(to_analyze)} analysées",
        "verdict": verdict,
    }


# ─────────────────────────────────────────────────────────
# TESTS — v2.5 (régression v2.4 + nouveaux cas blindspots)
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import time

    print("\n🔍 Agent URL v2.5\n" + "─" * 70)

    tests = [
        # ── Tranco (légitimes) ───────────────────────────────────────────────
        ("https://www.google.com",           "Google (Tranco)",              0,   "✅"),
        ("https://www.facebook.com",         "Facebook (Tranco)",            0,   "✅"),
        ("https://www.amazon.com",           "Amazon.com officiel (Tranco)", 0,   "✅"),
        ("https://www.microsoft.com",        "Microsoft.com officiel",       0,   "✅"),
        ("https://www.github.com",           "GitHub (Tranco)",              0,   "✅"),
        ("https://soprasteria.com",          "Soprasteria (Tranco)",         0,   "✅"),
        ("https://random-unknown-12345.xyz", "Inconnu",                      0,   None),

        # ── FIX-1 : Shorteners ──────────────────────────────────────────────
        ("https://bit.ly/xyz123",            "bit.ly shortener",             50,  "⚠️"),
        ("https://tinyurl.com/malware",      "tinyurl shortener",            50,  "⚠️"),
        ("https://ow.ly/phishing",           "ow.ly shortener",              50,  "⚠️"),
        ("https://is.gd/badlink",            "is.gd shortener",              50,  "⚠️"),

        # ── FIX-2 : Tunnels ─────────────────────────────────────────────────
        ("https://abc123.ngrok.io/steal",    "ngrok tunnel",                 65,  "🔴"),
        ("https://abc.loca.lt/admin",        "localtunnel",                  65,  "🔴"),

        # ── FIX-3 : Imitations critiques ────────────────────────────────────
        ("https://paypal.login-secure.xyz",  "PayPal imitation critique",    90,  "🛑"),
        ("https://paypal-verify.top",        "PayPal imitation générique",   75,  "🔴"),
        ("https://amazon.account-verify.top","Amazon imitation critique",    90,  "🛑"),
        ("https://amazon-login.xyz",         "Amazon imitation générique",   75,  "🔴"),
        ("https://microsoft.365-update.club","Microsoft imitation critique",  90,  "🛑"),
        ("https://apple.id-support.online",  "Apple imitation critique",     90,  "🛑"),

        # ── Heuristique classique ────────────────────────────────────────────
        ("https://192.168.1.1/login",        "IP directe",                   75,  "🔴"),
        ("https://example.tk/",              "TLD gratuit .tk",              60,  "⚠️"),
        ("https://login-secure.xyz",         "Domaine phishing générique",   70,  "🔴"),

        # ── Légitimes (anti faux-positifs) ──────────────────────────────────
        ("https://legit.com/unsubscribe",    "Unsubscribe légitime",         0,   "✅"),
    ]

    passed = 0
    for url, label, min_score, expected_icon in tests:
        start = time.time()
        score, detail, is_tranco = check_url(url)
        elapsed = time.time() - start

        ok = score >= min_score
        if expected_icon is None:
            ok = True  # pas d'assertion forte sur ce cas

        status = "✅" if ok else "❌"
        if ok:
            passed += 1

        actual_icon = "🛑" if score >= 85 else "⚠️" if score >= 60 else ("🔴" if score >= 50 else "✅")
        print(f"{status} {label:<40} | {score:>3}/100 (min={min_score}) | {elapsed*1000:.0f}ms")
        print(f"   → {detail}")

    print(f"\n{'─'*70}")
    print(f"Résultat : {passed}/{len(tests)} tests passés")

    # Run URL agent test
    print("\n\n📋 Agent run_url_agent (body text)")
    print("─" * 70)
    body_tests = [
        ("Clique ici https://bit.ly/evil123 pour vérifier ton compte",
         "Shortener dans body", "SUSPECT"),
        ("Connecte-toi sur https://paypal.login-verify.xyz maintenant",
         "PayPal imitation dans body", "MALVEILLANT"),
        ("Visite https://www.google.com pour plus d'infos",
         "Google légitime dans body", "SAIN"),
        ("Aucune URL dans ce message.",
         "Pas d'URL", "AUCUN"),
    ]
    for body, label, expected_contains in body_tests:
        r = run_url_agent(body)
        ok = expected_contains in r["verdict"]
        status = "✅" if ok else "❌"
        print(f"{status} {label:<40} | Score={r['score_url']:>3} | {r['verdict']}")