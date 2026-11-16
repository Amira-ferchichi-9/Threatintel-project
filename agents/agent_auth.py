# agents/agent_auth.py — v3.5
# Fixes vs v3.4:
#   FIX-11 : Architecture — Reconnaissance de la limite structurelle du compromised relay.
#
#   Constat : B-REL-001 (Finance Director) et A-B-001 (vrai CEO) ont un profil
#   de headers IDENTIQUE quand le relay est propre. Aucune règle header-only ne peut
#   les distinguer sans créer un FP symétrique.
#
#   Solution : introduire deux nouveaux signaux de sortie dans run_auth_agent :
#     - `needs_nlp_review` (bool) : True si HVT détecté sans signal infra suspect.
#       Signal explicite pour l'Agent NLP/BEC en aval qui analysera le contenu.
#     - `confidence_ceiling` (int) : plafond de confiance réel (0-100).
#       HVT sans infra → ceiling=75 (même si score=100 brut).
#       Permet au pipeline de savoir que la confiance n'est pas absolue.
#     - `verdict` enrichi : "✅ IDENTITÉ VÉRIFIÉE — ⚠️ REVUE BEC RECOMMANDÉE"
#       quand HVT présent sans infra signal (au lieu du ✅ pur trompeur).
#
#   Ce design respecte le principe de séparation des responsabilités :
#     Agent Auth  → analyse des headers (SPF/DKIM/DMARC + anomalies structurelles)
#     Agent NLP   → analyse du contenu (urgence, demande de virement, contexte BEC)
#   Les deux ensembles donnent un verdict final robuste sans FP sur les relays propres.
#
# Conservés vs v3.4:
#   FIX-7  : titres arabes RTL
#   FIX-8  : scan partie locale email (no display name)
#   FIX-9  : TLD suspects + tokens ingénierie sociale
#   FIX-10 : word-boundary pour titres courts + HVT conditionnel (infra signal requis)
import re
import unicodedata
import logging

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# CONSTANTES
# ─────────────────────────────────────────────────────────
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "icloud.com", "protonmail.com",
    "yopmail.com", "guerrillamail.com", "tempmail.com",
}

EXECUTIVE_TITLES = {
    # Anglais
    "cfo", "ceo", "cto", "coo", "ciso", "vp",
    "vice president", "chief financial", "chief executive",
    "chief operating", "chief information", "chief security",
    "director", "president", "finance director",
    "head of finance", "head of accounting", "managing director",
    # Français
    "dg", "directeur general", "directeur generale",
    "pdg", "president directeur", "directeur financier",
    "directeur general adjoint", "dga",
    "responsable financier", "chef comptable",
    "directeur des operations", "directeur technique",
}

# FIX-7 : titres exécutifs arabes (translittération + arabe natif)
EXECUTIVE_TITLES_AR = {
    # Natif arabe
    "المدير المالي",       # Directeur Financier
    "المدير العام",        # Directeur Général
    "الرئيس التنفيذي",    # PDG / CEO
    "المدير التنفيذي",    # Directeur Exécutif
    "مدير المالية",        # Directeur Finance
    "رئيس مجلس الإدارة",  # Président du CA
    "نائب الرئيس",         # VP
    "المدير التقني",       # CTO
    "المدير المالي الرئيسي", # CFO
    # Translittération latine courante
    "mudir mali", "mudir aam", "ra2is tanfizi",
    "mudeer", "ra2ees",
}

# FIX-8 : mots-clés exec dans la partie locale de l'email
EXECUTIVE_LOCAL_KEYWORDS = {
    "ceo", "cfo", "cto", "coo", "ciso",
    "director", "chief", "president", "finance",
    "vp", "managing", "executive",
    "directeur", "financier", "pdg",
}

# FIX-12 : version stricte pour HVT corporate (evite les FP sur "finance team")
HVT_LOCAL_KEYWORDS_STRICT = {
    "ceo", "cfo", "cto", "coo", "ciso",
    "chief", "president", "executive",
    "directeur", "pdg", "dg", "dga",
}

# FIX-12 : roles sensibles typiques des relays compromis (non-exec)
COMPROMISED_RELAY_ROLE_KEYWORDS = {
    "ops", "operations", "operation", "admin",
}

# FIX-12 : titres privilegies a haut risque en cas de compte compromis
COMPROMISED_RELAY_PRIVILEGED_TITLES = {
    "ceo", "cfo", "chief financial", "finance director",
    "president", "pdg", "directeur financier", "directeur general",
}

# FIX-9 : TLD suspects associés à des campagnes de phishing
SUSPICIOUS_TLDS = {
    ".click", ".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".ga",
    ".pw", ".icu", ".cyou", ".work", ".rest", ".zip", ".mov",
    ".loan", ".win", ".download", ".stream", ".racing",
}

# FIX-9 : sous-domaines/tokens d'ingénierie sociale classiques
SOCIAL_ENGINEERING_TOKENS = {
    "secure", "security", "login", "signin", "account", "accounts",
    "update", "verify", "verification", "alert", "support",
    "helpdesk", "service", "services", "webmail", "portal",
    "mail", "safe", "protect", "confirm", "validation",
    "banking", "payment", "invoice",
}

# FIX-5 : mots-clés suspects dans la partie locale du Reply-To (même domaine)
SUSPICIOUS_REPLY_LOCAL_KEYWORDS = {
    "payment", "pay", "update", "secure", "verify", "alert",
    "invoice", "billing", "transfer", "wire", "urgent",
    "confirm", "validate", "account", "reset", "support-",
    "fraud", "admin-", "noreply-",
}

BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "linkedin.com", "twitter.com",
    "orange.com", "orange.tn", "ooredoo.tn", "tunisietelecom.tn",
    "banque-zitouna.tn", "attijari.tn", "biat.com.tn",
    "enit.utm.tn", "utm.tn", "rnu.tn",
}

HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g',
    'ո': 'n', 'υ': 'u', 'ν': 'v', 'ω': 'w',
}

# FIX-10 : titres courts qui nécessitent un word-boundary (évite "director" → "cto" substring FP)
SHORT_EXEC_TITLES = {"ceo", "cfo", "cto", "coo", "ciso", "vp", "dg", "dga", "pdg"}


# ─────────────────────────────────────────────────────────
# HELPERS NORMALISATION
# ─────────────────────────────────────────────────────────
def _normalize_display(text: str) -> str:
    """
    FIX-1/7 : normalise un display name pour la détection de titres.
    - NFD → supprime les diacritiques (accents)
    - Remplace les chiffres qui imitent des lettres
    - Supprime ponctuation non-alphanumérique
    - Lowercase
    """
    nfd = unicodedata.normalize("NFD", text)
    without_accents = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    lowered = without_accents.lower()
    leet_map = {"1": "i", "0": "o", "3": "e", "4": "a", "5": "s", "@": "a"}
    normalized = "".join(leet_map.get(c, c) for c in lowered)
    normalized = re.sub(r"[^a-z0-9 ]", "", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _title_matches(title: str, normalized_text: str) -> bool:
    """
    FIX-10 : pour les titres courts (ceo, cto…), exige un word-boundary.
    Pour les titres longs, un simple 'in' suffit.
    Évite le FP : "director" → contient "cto" comme substring.
    """
    if title in SHORT_EXEC_TITLES:
        return bool(re.search(r'\b' + re.escape(title) + r'\b', normalized_text))
    return title in normalized_text


def _decode_punycode_domain(domain: str) -> str:
    """FIX-3 : décode un domaine punycode (xn--...) vers Unicode."""
    parts = domain.split(".")
    decoded_parts = []
    for part in parts:
        if part.startswith("xn--"):
            try:
                decoded_parts.append(part.encode("ascii").decode("idna"))
            except (UnicodeError, UnicodeDecodeError):
                decoded_parts.append(part)
        else:
            decoded_parts.append(part)
    return ".".join(decoded_parts)


def _extract_domain_tokens(domain: str) -> list:
    """FIX-4 : extrait tous les tokens significatifs d'un domaine composé."""
    without_tld = re.sub(r"\.[a-z]{2,6}$", "", domain)
    tokens = re.split(r"[-.]", without_tld)
    tokens = [t for t in tokens if len(t) >= 3]
    tokens.append(without_tld)
    return tokens


def _get_tld(domain: str) -> str:
    """Extrait le TLD d'un domaine (avec le point). Ex: 'acme.click' → '.click'"""
    m = re.search(r'(\.[a-z]{2,}(?:\.[a-z]{2,})?)$', domain)
    return m.group(1) if m else ""


# ─────────────────────────────────────────────────────────
# TIER 1 — PARSING HEADERS
# ─────────────────────────────────────────────────────────
def parse_authentication_results(auth_results: str) -> dict:
    if not auth_results:
        return {
            "spf": None, "dkim": None, "dmarc": None,
            "spf_domain": "", "dkim_domain": "", "dmarc_policy": "",
            "dmarc_bestguesspass": False,
        }

    result = {
        "spf": None, "dkim": None, "dmarc": None,
        "spf_domain": "", "dkim_domain": "", "dmarc_policy": "",
        "dmarc_bestguesspass": False,
    }

    spf_match = re.search(
        r'spf=(pass|fail|softfail|neutral|none|permerror|temperror)',
        auth_results, re.I)
    if spf_match:
        result["spf"] = spf_match.group(1).lower()

    spf_domain = re.search(r'smtp\.mailfrom=([^\s;]+)', auth_results, re.I)
    if spf_domain:
        mailfrom_val = spf_domain.group(1).lower()
        # smtp.mailfrom can be a full address (user@domain.com) — extract only the domain
        result["spf_domain"] = mailfrom_val.split('@')[-1] if '@' in mailfrom_val else mailfrom_val

    dkim_match = re.search(
        r'dkim=(pass|fail|none|neutral|permerror|temperror)',
        auth_results, re.I)
    if dkim_match:
        result["dkim"] = dkim_match.group(1).lower()

    dkim_domain = re.search(r'header\.i=@([^\s;]+)', auth_results, re.I)
    if dkim_domain:
        result["dkim_domain"] = dkim_domain.group(1).lower()

    # FIX-6 : bestguesspass détecté explicitement AVANT le match normal
    if re.search(r'dmarc=bestguesspass', auth_results, re.I):
        result["dmarc_bestguesspass"] = True
    else:
        dmarc_match = re.search(r'dmarc=(pass|fail|none)', auth_results, re.I)
        if dmarc_match:
            result["dmarc"] = dmarc_match.group(1).lower()

    dmarc_policy = re.search(r'\(p=(\w+)', auth_results, re.I)
    if dmarc_policy:
        result["dmarc_policy"] = dmarc_policy.group(1).lower()

    return result


def parse_from_header(from_header: str) -> dict:
    """FIX-2 : gère le format inhabituel "Name email@domain.com" sans chevrons."""
    from_header = from_header.strip()

    display_match = re.match(r'^"?([^"<]+)"?\s*<', from_header)
    display_name = display_match.group(1).strip() if display_match else ""

    email_match = re.search(r'<([^>]+)>', from_header)
    if email_match:
        email = email_match.group(1).lower()
    else:
        email_bare = re.search(r'[\w.+-]+@[\w.\-]+', from_header)
        if email_bare:
            email = email_bare.group(0).lower()
            if not display_name:
                display_name = from_header[:from_header.lower().index(email)].strip()
        else:
            email = from_header.lower()

    domain_match = re.search(r'@([\w.\-]+)', email)
    domain = domain_match.group(1).lower() if domain_match else ""

    return {"display_name": display_name, "email": email, "domain": domain}


def parse_return_path(return_path: str) -> str:
    if not return_path:
        return ""
    match = re.search(r'@([\w.\-]+)', return_path)
    return match.group(1).lower() if match else ""


def parse_reply_to(reply_to: str) -> str:
    if not reply_to:
        return ""
    match = re.search(r'[\w.+-]+@[\w.\-]+', reply_to)
    return match.group(0).lower() if match else ""


# ─────────────────────────────────────────────────────────
# TIER 2 — DÉTECTION D'ANOMALIES
# ─────────────────────────────────────────────────────────
def check_executive_title_spoofing(display_name: str, domain: str) -> tuple:
    """
    FIX-1/7/10 : normalisation Unicode + leet + ponctuation + word-boundary pour titres courts.
    Couvre maintenant : arabe via EXECUTIVE_TITLES_AR (FIX-7).
    """
    if not display_name or not domain:
        return False, ""

    is_free = domain in FREE_EMAIL_DOMAINS
    if not is_free:
        return False, ""

    # Check arabe (FIX-7) — comparaison directe sur display_name brut
    for title_ar in EXECUTIVE_TITLES_AR:
        if title_ar in display_name:
            return True, f"Titre exécutif arabe '{title_ar}' via domaine gratuit ({domain})"

    # Check latin normalisé (FIX-1 + FIX-10)
    normalized = _normalize_display(display_name)
    for title in EXECUTIVE_TITLES:
        if _title_matches(title, normalized):
            return True, (
                f"Titre exécutif '{title}' via domaine gratuit ({domain}) "
                f"[display: '{display_name}']"
            )

    return False, ""


def check_executive_title_local(from_email: str, domain: str) -> tuple:
    """
    FIX-8 : scanne la PARTIE LOCALE de l'email pour détecter les patterns exec
    quand il n'y a pas de display name.
    Ex: ceo.request@gmail.com, chief.financial.office@gmail.com → détecté.
    Seulement déclenché si domaine gratuit (sinon trop de FP sur emails légitimes).
    """
    if not from_email or not domain:
        return False, ""

    if domain not in FREE_EMAIL_DOMAINS:
        return False, ""

    local_part = from_email.split("@")[0].lower() if "@" in from_email else ""
    if not local_part:
        return False, ""

    # Sépare sur . et - pour tokeniser
    tokens = re.split(r'[.\-_]', local_part)
    for token in tokens:
        if token in EXECUTIVE_LOCAL_KEYWORDS:
            return True, (
                f"Partie locale exec '{token}' dans '{from_email}' "
                f"via domaine gratuit ({domain})"
            )

    # Check aussi la chaîne complète (ex: "chieffinancial")
    for kw in EXECUTIVE_LOCAL_KEYWORDS:
        if len(kw) >= 4 and kw in local_part:
            return True, (
                f"Mot-clé exec '{kw}' dans partie locale '{local_part}' "
                f"via domaine gratuit ({domain})"
            )

    return False, ""


def check_exotic_tld(from_domain: str) -> tuple:
    """
    FIX-9 : détecte les TLD suspects + combinaisons sous-domaine d'ingénierie sociale.
    Deux signaux indépendants :
    - Signal A : TLD dans SUSPICIOUS_TLDS
    - Signal B : token d'ingénierie sociale dans les labels du domaine
    Les deux ensemble → score maximal de suspicion.
    """
    if not from_domain:
        return False, ""

    tld = _get_tld(from_domain)
    has_suspicious_tld = tld in SUSPICIOUS_TLDS

    # Extrait tous les labels (sous-domaines + SLD, sans TLD)
    without_tld = re.sub(r'\.[a-z]{2,}(?:\.[a-z]{2,})?$', '', from_domain)
    labels = re.split(r'[-.]', without_tld)
    labels = [l.lower() for l in labels if len(l) >= 3]

    social_tokens_found = [l for l in labels if l in SOCIAL_ENGINEERING_TOKENS]

    if has_suspicious_tld and social_tokens_found:
        return True, (
            f"TLD suspect '{tld}' + token ingénierie sociale "
            f"{social_tokens_found} dans '{from_domain}'"
        )
    if has_suspicious_tld:
        return True, f"TLD suspect '{tld}' dans '{from_domain}'"
    if len(social_tokens_found) >= 2:
        # Deux tokens SE sans TLD suspect → suspicion modérée
        return True, (
            f"Tokens d'ingénierie sociale multiples {social_tokens_found} "
            f"dans '{from_domain}'"
        )

    return False, ""


def check_high_value_target(
    display_name: str,
    from_email: str,
    from_domain: str,
    exec_spoofing: bool,
    exec_local: bool,
) -> tuple:
    """
    FIX-10 : flag HVT pour compromised relay.
    Détecte : display name exec + domaine corporate (non-gratuit) + auth parfaite.
    Signal : on ne bloque pas (FP sur vrais directeurs légitimes), mais on
    retourne un flag + une pénalité forte (-50) appliquée au score pour
    abaisser le verdict sous le seuil "IDENTITÉ PARTIELLE" (55).

    La logique : un relay compromis aura SPF+DKIM+DMARC=pass → score brut ~100.
    Avec -50, score final ≤ 55 → "⚠️ IDENTITÉ PARTIELLE" au lieu de "✅ VÉRIFIÉE".

    NB : on exclut les domaines gratuits (déjà couverts par exec_spoofing).
    """
    if from_domain in FREE_EMAIL_DOMAINS:
        return False, ""

    # Signal exec dans display name (via normalisation latine ou arabe)
    has_exec_display = False
    if display_name:
        normalized = _normalize_display(display_name)
        for title in EXECUTIVE_TITLES:
            if _title_matches(title, normalized):
                has_exec_display = True
                break
        if not has_exec_display:
            for title_ar in EXECUTIVE_TITLES_AR:
                if title_ar in display_name:
                    has_exec_display = True
                    break

    # Signal exec dans partie locale (ex: cto@acme-corp.com)
    # FIX-12 : jeu strict (sans "finance"/"director" seuls) pour limiter les FP.
    has_exec_local = False
    if from_email and not has_exec_display:
        local_part = from_email.split("@")[0].lower() if "@" in from_email else ""
        tokens = re.split(r'[.\-_]', local_part)
        for token in tokens:
            if token in HVT_LOCAL_KEYWORDS_STRICT:
                has_exec_local = True
                break

    if has_exec_display or has_exec_local:
        signal = "display" if has_exec_display else "local-part"
        return True, (
            f"High-Value Target : signal exec ({signal}) sur domaine corporate "
            f"'{from_domain}' — possible compromised relay"
        )

    return False, ""


def check_compromised_relay_suspected(
    display_name: str,
    from_email: str,
    from_domain: str,
    parsed_auth: dict,
    anomalies: dict,
) -> tuple:
    """
    FIX-12 : couvre le blindspot relay compromis avec auth propre.

    Regles :
    - SPF=pass, DKIM=pass, DMARC=pass
    - Pas d'anomalie infra (alignement ok, pas de mismatch)
    - Puis detection d'un profil sensible :
      A) titre privilegie (finance director, cfo, pdg...) ; ou
      B) role operationnel sensible (ops/admin) avec DMARC=quarantine.
    """
    if not from_domain or from_domain in FREE_EMAIL_DOMAINS:
        return False, ""

    spf = parsed_auth.get("spf")
    dkim = parsed_auth.get("dkim")
    dmarc = parsed_auth.get("dmarc")
    dmarc_policy = (parsed_auth.get("dmarc_policy") or "").lower()

    if not (spf == "pass" and dkim == "pass" and dmarc == "pass"):
        return False, ""

    has_infra_signal = (
        parsed_auth.get("dmarc_bestguesspass", False)
        or anomalies.get("return_path_mismatch", False)
        or anomalies.get("reply_to_mismatch", False)
        or anomalies.get("reply_to_suspicious", False)
        or not anomalies.get("dkim_aligned", True)
        or not anomalies.get("spf_aligned", True)
    )
    if has_infra_signal:
        return False, ""

    normalized_display = _normalize_display(display_name or "")
    local_part = from_email.split("@")[0].lower() if "@" in from_email else ""
    local_tokens = re.split(r'[.\-_]', local_part)

    for title in COMPROMISED_RELAY_PRIVILEGED_TITLES:
        if _title_matches(title, normalized_display):
            return True, (
                f"Compromised relay suspect : profil privilegie '{title}' "
                f"sur domaine corporate '{from_domain}' avec auth propre"
            )

    if dmarc_policy == "quarantine":
        for token in local_tokens:
            if token in COMPROMISED_RELAY_ROLE_KEYWORDS:
                return True, (
                    f"Compromised relay suspect : role '{token}' sur "
                    f"domaine corporate '{from_domain}' (DMARC quarantine)"
                )
        for token in COMPROMISED_RELAY_ROLE_KEYWORDS:
            if _title_matches(token, normalized_display):
                return True, (
                    f"Compromised relay suspect : display role '{token}' sur "
                    f"domaine corporate '{from_domain}' (DMARC quarantine)"
                )

    return False, ""


def check_reply_to_mismatch(from_email: str, reply_to_email: str) -> tuple:
    if not reply_to_email or not from_email:
        return False, ""
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    reply_domain = reply_to_email.split("@")[-1] if "@" in reply_to_email else ""
    if from_domain and reply_domain and from_domain != reply_domain:
        # Allow subdomain relationships (e.g. reply.github.com vs github.com)
        if from_domain.endswith("." + reply_domain) or reply_domain.endswith("." + from_domain):
            return False, ""
        return True, f"Reply-To ({reply_to_email}) ≠ From ({from_email})"
    return False, ""


def check_reply_to_suspicious(from_email: str, reply_to_email: str) -> tuple:
    """FIX-5 : détecte un Reply-To suspect dans le MÊME domaine."""
    if not reply_to_email or not from_email:
        return False, ""
    from_domain = from_email.split("@")[-1] if "@" in from_email else ""
    reply_domain = reply_to_email.split("@")[-1] if "@" in reply_to_email else ""

    if from_domain != reply_domain:
        return False, ""

    reply_local = reply_to_email.split("@")[0].lower() if "@" in reply_to_email else ""
    from_local  = from_email.split("@")[0].lower() if "@" in from_email else ""

    if reply_local == from_local:
        return False, ""

    for kw in SUSPICIOUS_REPLY_LOCAL_KEYWORDS:
        if kw in reply_local:
            return True, (
                f"Reply-To suspect même domaine : '{reply_to_email}' "
                f"(mot-clé '{kw}' détecté)"
            )
    return False, ""


# Ajoute cette constante en haut avec les autres (après FREE_EMAIL_DOMAINS)
ESP_BOUNCE_PATTERNS = [
    "bounce.", "em.", "send.", "mail.", "sg.", "msprvs",
    "brevosend", "mailchimp", "mcsv.net",  # Mailchimp bounce domain
    "sendgrid", "sendgrid.net",
    "amazonses", "amazonses.com",
    "sparkpost", "mandrill", "klaviyo", "brevo", "mailjet",
    "constantcontact", "campaign-archive", "chime-notifications",
    "reply.", "newsletter.",
]

def check_return_path_mismatch(from_domain: str, return_path_domain: str) -> tuple:
    if not return_path_domain or not from_domain:
        return False, ""
    if from_domain == return_path_domain:
        return False, ""
    # NEW : ignorer les domaines ESP connus (bounce routing légitimes)
    rp_lower = return_path_domain.lower()
    for esp in ESP_BOUNCE_PATTERNS:
        if esp in rp_lower:
            return False, ""
    return True, f"Return-Path ({return_path_domain}) ≠ From ({from_domain})"


def check_homograph_attack(domain: str) -> tuple:
    """FIX-3 : décode le punycode AVANT de chercher les caractères homographes."""
    if not domain:
        return False, ""

    decoded = _decode_punycode_domain(domain)
    if decoded != domain:
        for char in decoded:
            if char in HOMOGRAPH_MAP:
                return True, f"Punycode homographe détecté : '{domain}' → '{decoded}'"
        return True, f"Domaine IDN/punycode suspect : '{domain}' → '{decoded}'"

    for char in domain:
        if char in HOMOGRAPH_MAP:
            return True, f"Caractère homographe : '{char}' dans {domain}"

    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        return True, f"Domaine non-ASCII suspect : {domain}"

    return False, ""


def check_cousin_domain(from_domain: str) -> tuple:
    """FIX-4 : extrait TOUS les tokens du domaine composé et les compare aux brand domains."""
    if not from_domain:
        return False, ""

    def levenshtein(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein(s2, s1)
        if not s2:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 != c2)))
            prev = curr
        return prev[-1]

    tokens = _extract_domain_tokens(from_domain)

    for token in tokens:
        for brand in BRAND_DOMAINS:
            brand_root = brand.split(".")[0]
            if token == brand_root:
                continue
            dist = levenshtein(token, brand_root)
            if 0 < dist <= 2 and len(token) >= 5 and len(brand_root) >= 5:
                return True, (
                    f"Cousin domain : token '{token}' dans '{from_domain}' "
                    f"≈ '{brand}' (distance={dist})"
                )
    return False, ""


def check_dkim_alignment(from_domain: str, dkim_domain: str) -> tuple:
    if not dkim_domain or not from_domain:
        return True, ""
    if from_domain == dkim_domain:
        return True, ""
    if from_domain.endswith("." + dkim_domain) or dkim_domain.endswith("." + from_domain):
        return True, ""
    return False, f"DKIM domain ({dkim_domain}) ≠ From domain ({from_domain})"


def check_spf_alignment(from_domain: str, spf_domain: str) -> tuple:
    if not spf_domain or not from_domain:
        return True, ""
    if from_domain == spf_domain:
        return True, ""
    if from_domain.endswith("." + spf_domain) or spf_domain.endswith("." + from_domain):
        return True, ""
    return False, f"SPF domain ({spf_domain}) ≠ From domain ({from_domain})"


# ─────────────────────────────────────────────────────────
# TIER 3 — SCORING + HARD RULES
# ─────────────────────────────────────────────────────────
def compute_auth_score(
    parsed_auth: dict,
    anomalies: dict,
    from_domain: str
) -> tuple:

    # ── HARD RULES — verdict immédiat (confidence_ceiling=100, needs_nlp_review=False) ──
    if anomalies.get("homograph"):
        return 0, "❌ HOMOGRAPH ATTACK DÉTECTÉ", [anomalies["homograph_msg"]], 100, False

    if anomalies.get("exec_spoofing"):
        return 5, "❌ USURPATION EXÉCUTIVE (BEC)", [anomalies["exec_spoofing_msg"]], 100, False

    if anomalies.get("exec_local"):
        return 8, "❌ USURPATION EXÉCUTIVE LOCALE (BEC)", [anomalies["exec_local_msg"]], 100, False

    if anomalies.get("cousin_domain"):
        return 10, "❌ COUSIN DOMAIN DÉTECTÉ", [anomalies["cousin_domain_msg"]], 100, False

    if anomalies.get("exotic_tld"):
        return 15, "❌ TLD/DOMAINE SUSPECT (PHISHING)", [anomalies["exotic_tld_msg"]], 100, False

    if anomalies.get("reply_to_mismatch"):
        return 25, "❌ REPLY-TO PIÉGÉ", [anomalies["reply_to_msg"]], 100, False

    if anomalies.get("reply_to_suspicious"):
        return 45, "🔶 REPLY-TO SUSPECT (même domaine)", [anomalies["reply_to_suspicious_msg"]], 100, False

    # ── SCORING SPF/DKIM/DMARC ─────────────────────────────
    score = 0
    flags = []

    spf           = parsed_auth.get("spf")
    dkim          = parsed_auth.get("dkim")
    dmarc         = parsed_auth.get("dmarc")
    dmarc_policy  = parsed_auth.get("dmarc_policy", "")
    bestguesspass = parsed_auth.get("dmarc_bestguesspass", False)

    if spf == "pass":
        score += 30
        flags.append("SPF ✅")
    elif spf in ("softfail", "neutral"):
        score += 10
        flags.append(f"SPF ⚠️ ({spf})")
    elif spf in ("fail", "permerror"):
        score -= 20
        flags.append(f"SPF ❌ ({spf})")
    else:
        flags.append("SPF absent")

    if dkim == "pass":
        score += 35
        flags.append("DKIM ✅")
        if not anomalies.get("dkim_aligned", True):
            score -= 35
            flags.append(f"⚠️ {anomalies.get('dkim_align_msg', '')}")
    elif dkim in ("fail", "permerror"):
        score -= 15
        flags.append(f"DKIM ❌ ({dkim})")
    else:
        flags.append("DKIM absent")

    if dmarc == "pass":
        if dmarc_policy == "reject":
            score += 35
            flags.append("DMARC ✅ (reject)")
        elif dmarc_policy == "quarantine":
            score += 25
            flags.append("DMARC ✅ (quarantine)")
        else:
            score += 15
            flags.append(f"DMARC ✅ (p={dmarc_policy or 'none'})")
    elif dmarc == "fail":
        score -= 20
        flags.append("DMARC ❌")
    elif bestguesspass:
        score -= 15
        flags.append("DMARC ⚠️ (bestguesspass — non fiable)")
    else:
        flags.append("DMARC absent")

    # ── PÉNALITÉS ANOMALIES ────────────────────────────────
    if anomalies.get("return_path_mismatch"):
        score -= 40
        flags.append(f"⚠️ {anomalies['return_path_msg']}")

    if not anomalies.get("spf_aligned", True):
        score -= 30
        flags.append(f"⚠️ {anomalies.get('spf_align_msg', '')}")

    if from_domain in FREE_EMAIL_DOMAINS:
        score -= 10
        flags.append(f"Domaine gratuit ({from_domain})")

    # FIX-10b/11 : pénalité HVT conditionnelle + confidence_ceiling.
    #
    # Signaux infra suspects :
    #   - bestguesspass (DMARC non fiable)
    #   - return_path_mismatch (bounce ≠ From)
    #   - dkim_aligned=False (DKIM domain ≠ From domain)
    #   - spf_aligned=False  (SPF domain ≠ From domain)
    #
    # HVT + infra signal  → pénalité -50 (relay compromis probable)
    # HVT sans infra      → score intact MAIS ceiling=75 + verdict enrichi
    #                        + needs_nlp_review=True pour le pipeline en aval
    needs_nlp_review = False
    confidence_ceiling = 100

    if anomalies.get("high_value_target"):
        hvt_has_infra = (
            parsed_auth.get("dmarc_bestguesspass", False)
            or anomalies.get("return_path_mismatch", False)
            or not anomalies.get("dkim_aligned", True)
            or not anomalies.get("spf_aligned", True)
        )
        if hvt_has_infra:
            score -= 50
            flags.append(f"🎯 {anomalies['hvt_msg']}")
        else:
            # Auth parfaitement propre : impossible de distinguer un vrai dirigeant
            # d'un relay compromis sans signal infra. On délègue à l'Agent NLP/BEC.
            confidence_ceiling = 75
            needs_nlp_review = True
            flags.append(f"ℹ️ HVT — revue BEC requise : {anomalies['hvt_msg']}")

    # FIX-12 : signature relay compromis avec auth propre.
    if anomalies.get("compromised_relay_suspected"):
        score = min(score, 50)
        confidence_ceiling = min(confidence_ceiling, 60)
        needs_nlp_review = True
        flags.append(f"🚨 {anomalies['compromised_relay_msg']}")

    score = max(0, min(100, score))

    # ── VERDICT ────────────────────────────────────────────
    if score >= 80:
        if needs_nlp_review:
            verdict = "✅ IDENTITÉ VÉRIFIÉE — ⚠️ REVUE BEC RECOMMANDÉE"
        else:
            verdict = "✅ IDENTITÉ VÉRIFIÉE"
    elif score >= 55:
        verdict = "⚠️ IDENTITÉ PARTIELLE"
    elif score >= 30:
        verdict = "🔶 IDENTITÉ FAIBLE"
    else:
        verdict = "❌ IDENTITÉ NON VÉRIFIÉE"

    return score, verdict, flags, confidence_ceiling, needs_nlp_review

def pred_label(result: dict) -> int:
    # Bloqué par score
    if int(result.get("score_auth", 0)) < 55:
        return 1
    # Signalé pour revue NLP — compté comme détection partielle
    if result.get("needs_nlp_review", False):
        return 1
    return 0

# ─────────────────────────────────────────────────────────
# AGENT PRINCIPAL — v3.5
# ─────────────────────────────────────────────────────────
def run_auth_agent(
    sender: str,
    subject: str = "",
    to_header: str = "",
    cc_header: str = "",
    reply_to: str = "",
    return_path: str = "",
    authentication_results: str = "",
    arc_authentication_results: str = "",
) -> dict:

    # Tier 1 — Parsing
    from_parsed        = parse_from_header(sender)
    display_name       = from_parsed["display_name"]
    from_email         = from_parsed["email"]
    from_domain        = from_parsed["domain"]

    auth_source        = authentication_results or arc_authentication_results
    parsed_auth        = parse_authentication_results(auth_source)
    return_path_domain = parse_return_path(return_path)
    reply_to_email     = parse_reply_to(reply_to)

    # Tier 2 — Anomalies
    exec_spoofed, exec_msg          = check_executive_title_spoofing(display_name, from_domain)
    exec_local, exec_local_msg      = check_executive_title_local(from_email, from_domain)
    exotic_tld, exotic_tld_msg      = check_exotic_tld(from_domain)
    reply_mismatch, reply_msg       = check_reply_to_mismatch(from_email, reply_to_email)
    reply_suspicious, reply_sus_msg = check_reply_to_suspicious(from_email, reply_to_email)
    rpath_mismatch, rpath_msg       = check_return_path_mismatch(from_domain, return_path_domain)
    homograph, homo_msg             = check_homograph_attack(from_domain)
    cousin, cousin_msg              = check_cousin_domain(from_domain)
    dkim_aligned, dkim_al_msg       = check_dkim_alignment(from_domain, parsed_auth.get("dkim_domain", ""))
    spf_aligned, spf_al_msg         = check_spf_alignment(from_domain, parsed_auth.get("spf_domain", ""))

    # FIX-10 : HVT check — après tous les autres pour avoir exec_spoofed/exec_local
    hvt, hvt_msg = check_high_value_target(
        display_name, from_email, from_domain,
        exec_spoofed, exec_local
    )

    compromised_relay, compromised_relay_msg = check_compromised_relay_suspected(
        display_name=display_name,
        from_email=from_email,
        from_domain=from_domain,
        parsed_auth=parsed_auth,
        anomalies={
            "reply_to_mismatch": reply_mismatch,
            "reply_to_suspicious": reply_suspicious,
            "return_path_mismatch": rpath_mismatch,
            "dkim_aligned": dkim_aligned,
            "spf_aligned": spf_aligned,
        },
    )

    anomalies = {
        "exec_spoofing":           exec_spoofed,
        "exec_spoofing_msg":       exec_msg,
        "exec_local":              exec_local,
        "exec_local_msg":          exec_local_msg,
        "exotic_tld":              exotic_tld,
        "exotic_tld_msg":          exotic_tld_msg,
        "reply_to_mismatch":       reply_mismatch,
        "reply_to_msg":            reply_msg,
        "reply_to_suspicious":     reply_suspicious,
        "reply_to_suspicious_msg": reply_sus_msg,
        "return_path_mismatch":    rpath_mismatch,
        "return_path_msg":         rpath_msg,
        "homograph":               homograph,
        "homograph_msg":           homo_msg,
        "cousin_domain":           cousin,
        "cousin_domain_msg":       cousin_msg,
        "dkim_aligned":            dkim_aligned,
        "dkim_align_msg":          dkim_al_msg,
        "spf_aligned":             spf_aligned,
        "spf_align_msg":           spf_al_msg,
        "high_value_target":       hvt,
        "hvt_msg":                 hvt_msg,
        "compromised_relay_suspected": compromised_relay,
        "compromised_relay_msg":      compromised_relay_msg,
    }

    # Tier 3 — Scoring
    score, verdict, flags, confidence_ceiling, needs_nlp_review = compute_auth_score(
        parsed_auth, anomalies, from_domain
    )

    return {
        "domain":                 from_domain,
        "display_name":           display_name,
        "from_email":             from_email,
        "spf":                    parsed_auth.get("spf"),
        "dkim":                   parsed_auth.get("dkim"),
        "dmarc":                  parsed_auth.get("dmarc"),
        "dmarc_policy":           parsed_auth.get("dmarc_policy"),
        "dmarc_bestguesspass":    parsed_auth.get("dmarc_bestguesspass"),
        "exec_spoofing":          exec_spoofed,
        "exec_local":             exec_local,
        "exotic_tld":             exotic_tld,
        "reply_to_mismatch":      reply_mismatch,
        "reply_to_suspicious":    reply_suspicious,
        "return_path_mismatch":   rpath_mismatch,
        "homograph":              homograph,
        "cousin_domain":          cousin,
        "high_value_target":      hvt,
        "compromised_relay_suspected": compromised_relay,
        "score_auth":             score,
        "confidence_ceiling":     confidence_ceiling,  # FIX-11 : plafond réel de confiance
        "needs_nlp_review":       needs_nlp_review,    # FIX-11 : signal pour Agent NLP/BEC
        "verdict":                verdict,
        "detail":                 " | ".join(flags),
        "institutional_bonus":    0,
    }