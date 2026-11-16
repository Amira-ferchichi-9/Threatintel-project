# agents/agent_nlp_bec.py — v3.6
#
# Changelog v3.5 → v3.6
# ─────────────────────────────────────────────────────────────────────────────
# NEW-1 : Détection domaine expéditeur suspect (TLD + patterns)
#         goacadco.info, domaines exotiques → floor SUSPECT minimum
# NEW-2 : Mail forwardé depuis domaine suspect → floor 65
# NEW-3 : Extraction domaine forwardé depuis corps du mail
#         Analyse le "De : x@domain" dans le corps pour détecter l'origine réelle

import re
import logging
from transformers import pipeline as hf_pipeline
from transformers import logging as transformers_logging
from rapidfuzz import fuzz
import os

transformers_logging.set_verbosity_error()
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# CHARGEMENT MODÈLES
# ─────────────────────────────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
LOCAL_DISTILBERT = os.path.join(PROJECT_ROOT, "distilbert-threatintel")
HF_DISTILBERT    = "Amira789/distilbert-phishing-pfa2"

SAFE_LABEL_HINTS      = {"SAFE", "LEGITIMATE", "HAM", "BENIGN", "NORMAL"}
MALICIOUS_LABEL_HINTS = {"PHISHING", "SPAM", "MALICIOUS", "FRAUD", "SCAM"}

STRICT_EXACT_PATTERNS = {
    "ceo request", "cfo request", "president request",
    "complete before end of business", "before end of day", "before close of business",
    "updated banking details", "update your payment", "reply only to me",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr",
    "outlook.com", "live.com", "icloud.com", "protonmail.com",
    "gmx.com", "gmx.fr", "laposte.net", "orange.fr", "sfr.fr",
}

# NEW-1 : Domaines suspects
SUSPICIOUS_TLDS = {
    '.info', '.xyz', '.top', '.click', '.tk', '.ml', '.ga',
    '.cf', '.gq', '.work', '.loan', '.online', '.site',
    '.website', '.space', '.buzz', '.club', '.win', '.bid',
}
SUSPICIOUS_DOMAIN_PATTERNS = [
    r'\d{4,}',
    r'[a-z]{18,}',
    r'(academy|speech|medical|doctor|japan|asia|global|world|united|secure|verify|account|login|update)\.',
]

print("[🤖 NLP] Chargement RoBERTa (spam)...")
roberta_classifier = hf_pipeline(
    "text-classification",
    model="mshenoda/roberta-spam",
    truncation=True,
    max_length=512,
)

print("[🤖 NLP] Chargement DistilBERT (phishing)...")


def _distilbert_device() -> int:
    use_cuda = os.getenv("NLP_USE_CUDA", "0").strip() == "1"
    if not use_cuda:
        return -1
    try:
        return 0 if __import__('torch').cuda.is_available() else -1
    except Exception:
        return -1


if os.path.isdir(LOCAL_DISTILBERT):
    print(f"[🤖 NLP] DistilBERT chargé depuis dossier LOCAL : {LOCAL_DISTILBERT}")
    distilbert_classifier = hf_pipeline(
        "text-classification",
        model=LOCAL_DISTILBERT,
        device=_distilbert_device(),
        truncation=True,
        max_length=512,
    )
else:
    print(f"[🤖 NLP] DistilBERT chargé depuis HuggingFace Hub : {HF_DISTILBERT}")
    distilbert_classifier = hf_pipeline(
        "text-classification",
        model=HF_DISTILBERT,
        truncation=True,
        max_length=512,
    )


# ─────────────────────────────────────────────────────────
# CHUNKING ANTI-ÉVASION
# ─────────────────────────────────────────────────────────
def _score_with_chunking(
    classifier,
    text: str,
    chunk_chars: int = 400,
    overlap: int = 50,
) -> tuple:
    text = text.strip()
    if not text:
        return "LABEL_0", 0.5

    if len(text) <= chunk_chars:
        pred = classifier(text)[0]
        return pred['label'], float(pred['score'])

    chunks = []
    start = 0
    while start < len(text):
        end = min(start + chunk_chars, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start += chunk_chars - overlap

    results = [classifier(c)[0] for c in chunks]
    worst = max(results, key=lambda r: float(r['score']))
    return worst['label'], float(worst['score'])


# ─────────────────────────────────────────────────────────
# PROBE label mapping
# ─────────────────────────────────────────────────────────
_distilbert_phishing_label = None


def _distilbert_semantic_risk(raw_label: str, score: float):
    upper = raw_label.upper()
    if any(h in upper for h in SAFE_LABEL_HINTS):
        return int(100 - score)
    if any(h in upper for h in MALICIOUS_LABEL_HINTS):
        return int(score)
    return None


def _probe_distilbert_labels():
    global _distilbert_phishing_label
    if _distilbert_phishing_label is not None:
        return _distilbert_phishing_label

    probe_malicious = (
        "Verify your account now. Enter your password immediately. "
        "Your account will be suspended."
    )
    probe_benign = (
        "Thank you for your application. We have received your request "
        "and will review your profile shortly."
    )

    try:
        pred_m = distilbert_classifier(probe_malicious, truncation=True, max_length=512)[0]
        pred_b = distilbert_classifier(probe_benign,    truncation=True, max_length=512)[0]

        label_m = pred_m["label"].upper()
        score_m = float(pred_m["score"])
        label_b = pred_b["label"].upper()
        score_b = float(pred_b["score"])

        if label_m != label_b and score_m >= 0.55 and score_b >= 0.55:
            _distilbert_phishing_label = label_m
            print(f"[🤖 NLP] DistilBERT mapping calibré : phishing='{label_m}' benign='{label_b}'")
        else:
            # NEW : mapping ambigu → on force LABEL_1 = phishing
            _distilbert_phishing_label = "LABEL_1"
            print(f"[🤖 NLP] DistilBERT mapping ambigu → forcé LABEL_1=phishing")
            print(f"  probe_malicious: label={label_m} score={score_m:.2f}")
            print(f"  probe_benign:    label={label_b} score={score_b:.2f}")

        return _distilbert_phishing_label   # ← ICI, indenté dans le try

    except Exception as e:
        logger.warning(f"Probe DistilBERT échoué : {e}")
        return None


try:
    _probe_distilbert_labels()
except Exception:
    pass


# ─────────────────────────────────────────────────────────
# BEC PATTERNS
# ─────────────────────────────────────────────────────────
BEC_IMPERSONATION_PATTERNS = [
    "directeur général", "directrice générale", "pdg", "président directeur",
    "ceo request", "cfo request", "president request",
    "de la part du directeur", "de la part du pdg", "de la part du dg",
    "message du directeur", "message du pdg",
    "le directeur vous demande", "le pdg vous demande",
    "i am the ceo", "i am the cfo", "i am the president",
    "je suis le directeur", "je suis le pdg", "je suis le dg",
    "my assistant will", "ma secrétaire va", "my pa will contact",
    "keep my name out", "ne mentionnez pas mon nom",
    "acting on my behalf", "agissez en mon nom",
    "do not copy anyone", "ne mettez personne en copie",
    "reply only to me", "répondez uniquement à moi",
    "former surgeon", "former scientist", "medical doctor",
    "international academic", "academic exchange", "fostering collaboration",
    "longstanding commitment", "humanitarian medical",
    "i have had the privilege", "nearly 70 countries",
    "transcends borders", "mutual understanding",
    "keen to explore opportunities", "meaningful collaboration",
    "trust-based", "long-term friendship",
    "wishing you safety", "wishing you and your family",
    "recent developments in the middle east",
    "significant challenges and uncertainty",
    "expert in international",
]

BEC_PATTERNS_HIGH = [
    "wire transfer", "bank transfer", "wire the funds", "transfer the funds",
    "routing number", "routing:", "account number", "bank account details",
    "process this payment", "process an urgent", "urgent payment",
    "transfer of funds", "fund transfer", "international transfer",
    "new vendor account", "new supplier account", "new bank account",
    "updated banking details", "payment details have changed",
    "do not discuss with anyone", "do not discuss this with",
    "keep this confidential", "keep this between us",
    "complete before end of business", "before end of day", "before close of business",
    "i need you to process", "i need this done today", "process urgently",
    "my personal request", "this is time-sensitive",
    "enter your password", "update your payment",
    "billing information required", "verify your identity now",
    "your account has been compromised", "confirm your account",
    "click to verify", "verify account now",
    "send me the gift cards", "gift card", "buy gift cards",
    "iTunes", "google play cards", "amazon gift",
    "virement urgent", "virement immédiat", "transfert immédiat",
    "ne parlez à personne", "gardez le secret",
    "instruction confidentielle", "CEO request",
    "votre mot de passe a expiré", "remittance advice"
    "international collaboration", "academic exchange",
    "explore opportunities", "keen to collaborate",
    "medical background", "academic network",
    "foster cooperation", "scientific goals",
    "building bridges", "transcend borders",
    "former surgeon", "former scientist",
]

BEC_PATTERNS_LOW = [
    "act now", "limited time offer", "winner", "congratulations",
    "click here to confirm", "urgent action required",
    "your account will be suspended", "invoice attached",
    "dear customer", "dear user","wishing you safety", "hope this finds you",
    "recent developments", "significant challenges",
    "heartfelt concern", "best wishes for your safety",
    "living and working in", "nearly 70 countries", "longstanding commitment", "humanitarian medical",
]


# ─────────────────────────────────────────────────────────
# NEW-3 : Extraction domaine depuis mail forwardé
# ─────────────────────────────────────────────────────────
def extract_forwarded_sender_domain(body_text: str) -> str:
    # Format 1 : De : email@domain
    # Format 2 : De : Nom <email@domain>
    pattern = r'(?:De|From)\s*:\s*.*?@([\w.\-]+)'
    matches = re.findall(pattern, body_text, re.IGNORECASE)
    if matches:
        # Prendre le PREMIER domaine trouvé (l'expéditeur original)
        for domain in matches:
            domain = domain.lower().strip()
            # Ignorer les domaines ENIT/étudiants (ce sont des forwarders)
            if 'etudiant-enit' not in domain and 'enit.utm' not in domain:
                return domain
    return ""


def is_domain_suspicious(domain: str) -> tuple:
    """
    Retourne (is_suspicious, reason).
    NEW-1 : vérifie TLD et patterns suspects.
    """
    if not domain:
        return False, ""

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True, f"TLD suspect : {tld}"

    for pat in SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pat, domain):
            return True, f"Domaine suspect : {domain}"

    return False, ""


# ─────────────────────────────────────────────────────────
# EXTRACTION MAIL FORWARDÉ
# ─────────────────────────────────────────────────────────
def extract_forwarded_body(text: str, _depth: int = 0) -> tuple:
    if _depth > 5:
        return text, True

    fwd_markers = [
        r'-{3,}\s*(Message transféré|Forwarded message|Original Message|Begin forwarded)',
        r'={3,}\s*(Message transféré|Forwarded)',
    ]
    for marker in fwd_markers:
        match = re.search(marker, text, re.IGNORECASE)
        if match:
            inner = text[match.end():]
            inner = re.sub(
                r'^(De|From|Date|Envoyé|Sent|Objet|Subject|À|To|Cc)\s*:.*$',
                '', inner, flags=re.MULTILINE | re.IGNORECASE
            )
            inner = inner.strip()
            deeper, _ = extract_forwarded_body(inner, _depth + 1)
            return deeper, True
    return text, False


# ─────────────────────────────────────────────────────────
# DÉTECTION CONTEXTE LÉGITIME
# ─────────────────────────────────────────────────────────
LEGIT_SIGNALS_STRONG = [
    (r'nous\s+(avons\s+bien\s+re[çc]u|accusons\s+(bonne\s+)?r[ée]ception)',                  "accusé réception"),
    (r'(merci\s+pour\s+votre|nous\s+vous\s+remercions)',                                       "remerciement"),
    (r'(candidature|application)\s+(re[çc]ue|bien\s+re[çc]ue)',                               "confirmation candidature"),
    (r'(votre\s+candidature\s+sera|nous\s+allons\s+examiner)',                                 "traitement candidature"),
    (r'(protection\s+des\s+donn[ée]es|rgpd|gdpr)',                                            "RGPD"),
    (r'(donn[ée]es\s+personnelles.{0,50}?trait[ée]es|politique\s+de\s+confidentialit[ée])', "politique confidentialité"),
    (r'(cordialement\s+invit[ée]s|journée|invitation\s+[àa])',                                "invitation institutionnelle"),
    (r'(vous\s+êtes\s+(abonn|inscrit)|unsubscribe|se\s+d[ée]sabonner)',                       "désabonnement"),
    (r'(free\s+shipping|livraison\s+gratuite|shop\s+now)',                                     "marketing e-commerce"),
    (r'(lancement|launch|announce)',                                                            "announcement"),
    (r'(procédure|procedure|process|étapes)',                                                  "procedural email"),
    (r'(équipe\s+(rh|recrutement|stages)|direction|system)',                                  "institutional unit"),
]

LEGIT_SIGNALS_WEAK = [
    (r'(poste\s+de|ingénieur|stagiaire|développeur)',             "offre emploi"),
    (r'(cordialement|bien\s+à\s+vous|meilleures\s+salutations)',  "formule de politesse"),
    (r'(equipe\s+(rh|recrutement)|hiring\s+team)',                "équipe RH"),
    (r'(programme|amphi|table\s+ronde|conférence)',               "événement"),
    (r'(conformément\s+[àa]|en\s+vertu\s+de)',                    "mention légale"),
    (r'(ce\s+(mail|message)\s+(a\s+été\s+)?envoyé\s+automatiquement|automated\s+email)', "automated but legit"),
    (r'(do\s+not\s+reply|ne\s+pas\s+répondre|noreply)',          "no-reply marker"),
]

SUSPICIOUS_INTENT_PATTERNS = [
    r'wire\s+transfer',
    r'bank\s+transfer',
    r'gift\s+card',
    r'enter\s+your\s+password',
    r'verify\s+your\s+account',
    r'click\s+to\s+verify',
    r'urgent\s+payment',
    r'account\s+has\s+been\s+compromised',
    r'fund\s+transfer',
    r'virement\s+urgent',
    r'virement\s+imm[ée]diat',
    r'transfert\s+imm[ée]diat',
    r'routing\s*(number|:)',
    r'account\s+number',
    r'new\s+(vendor|supplier|bank)\s+account',
    r'payment\s+details\s+have\s+changed',
    r'do\s+not\s+discuss\s+(with|this)',
    r'keep\s+this\s+(confidential|between\s+us)',
    r'ne\s+parlez\s+[àa]\s+personne',
    r'gardez\s+le\s+secret',
    r'instruction\s+confidentielle',
    r'buy\s+gift\s+cards?',
    r'remittance\s+advice',
]


def detect_legitimate_context(text: str) -> tuple:
    text_lower  = text.lower()
    score       = 0
    matched     = []
    strong_hits = 0

    for pattern, label in LEGIT_SIGNALS_STRONG:
        if re.search(pattern, text_lower):
            score       += 2
            strong_hits += 1
            matched.append(label)

    for pattern, label in LEGIT_SIGNALS_WEAK:
        if re.search(pattern, text_lower) and label not in matched:
            score += 1
            matched.append(label)

    is_legit = strong_hits >= 1 or score >= 3

    suspicious_hits = sum(
        bool(re.search(p, text_lower)) for p in SUSPICIOUS_INTENT_PATTERNS
    )
    if suspicious_hits >= 1 and strong_hits == 0:
        is_legit = False

    confidence = min(1.0, score / 6.0)
    if suspicious_hits >= 1 and strong_hits == 0:
        confidence = min(confidence, 0.35)

    return is_legit, confidence, matched


# ─────────────────────────────────────────────────────────
# ANALYSE ROBERTA
# ─────────────────────────────────────────────────────────
def analyze_roberta(text: str, is_legit: bool = False) -> tuple:
    if not text or len(text.strip()) < 10:
        return 0, "Texte trop court"

    word_count = len(text.split())
    if word_count < 20:
        return 10, f"RoBERTa neutralisé (texte court : {word_count} mots)"

    try:
        label, score_raw = _score_with_chunking(roberta_classifier, text)
        score = score_raw * 100
        risk  = score if label == "LABEL_1" else (100 - score)

        if is_legit:
            reduction = int(0.25 * risk)
            risk = max(0, risk - reduction)
            return int(risk), f"RoBERTa : {label} ({score:.1f}%) [RÉDUIT 25%] [chunked]"

        return int(risk), f"RoBERTa : {label} ({score:.1f}%) [chunked]"
    except Exception as e:
        return 0, f"RoBERTa erreur : {e}"


# ─────────────────────────────────────────────────────────
# ANALYSE DISTILBERT
# ─────────────────────────────────────────────────────────
def analyze_distilbert(text: str) -> tuple:
    if not text or len(text.strip()) < 10:
        return 0, "Texte trop court"
    try:
        raw_label, score_raw = _score_with_chunking(distilbert_classifier, text)
        raw_label      = raw_label.upper()
        score          = score_raw * 100
        phishing_label = _distilbert_phishing_label

        if phishing_label is not None:
            risk = int(score) if raw_label == phishing_label else int(100 - score)
            if len(text.split()) < 20:
                risk = min(risk, 30)
                return risk, f"DistilBERT : {raw_label} ({score:.1f}%) [cal, cap-court, chunked]"
            return risk, f"DistilBERT : {raw_label} ({score:.1f}%) [cal, chunked]"

        semantic_risk = _distilbert_semantic_risk(raw_label, score)
        if semantic_risk is not None:
            return semantic_risk, f"DistilBERT : {raw_label} ({score:.1f}%) [sem, chunked]"

        if raw_label in ("LABEL_1", "PHISHING", "MALICIOUS"):
            risk = int(score)
        elif raw_label in ("LABEL_0", "SAFE", "SAIN", "LEGITIMATE"):
            risk = int(100 - score)
        else:
            risk = int(50 - abs(score - 50))

        if len(text.split()) < 20:
            risk = min(risk, 30)
            return risk, f"DistilBERT : {raw_label} ({score:.1f}%) [fallback, cap-court, chunked]"
        return risk, f"DistilBERT : {raw_label} ({score:.1f}%) [fallback, chunked]"
    except Exception as e:
        return 0, f"DistilBERT erreur : {e}"


# ─────────────────────────────────────────────────────────
# ANALYSE BEC FUZZY — v3.6
# ─────────────────────────────────────────────────────────
def analyze_bec(
    text: str,
    is_legit: bool,
    sender_domain: str = "",
    word_cap: int = 2000,
) -> tuple:
    if not text:
        return 0, "Texte vide", 0, 0

    text_lower = text.lower()
    words = text_lower.split()
    if len(words) > word_cap:
        words = words[:word_cap]
        text_lower = " ".join(words)

    def find_matches(patterns: list) -> list:
        matched = []
        for pattern in patterns:
            if pattern in STRICT_EXACT_PATTERNS and pattern not in text_lower:
                continue
            window_size = len(pattern.split()) + 2
            threshold = 85 if len(pattern.split()) <= 2 else 82
            for i in range(len(words)):
                window = " ".join(words[i:i + window_size])
                if fuzz.partial_ratio(pattern, window) >= threshold:
                    matched.append(pattern)
                    break
        return matched

    high        = find_matches(BEC_PATTERNS_HIGH)
    low         = find_matches(BEC_PATTERNS_LOW)
    impersonate = find_matches(BEC_IMPERSONATION_PATTERNS)

    score = min(100, len(high) * 50 + len(impersonate) * 30 + len(low) * 8)

    if is_legit and not high and not impersonate and score < 25:
        score = min(15, score)

    impersonation_bonus = 0
    impersonation_flag  = False
    if impersonate and sender_domain in FREE_EMAIL_DOMAINS:
        impersonation_bonus = 20
        impersonation_flag  = True
        score = min(100, score + impersonation_bonus)

    if not high and not low and not impersonate:
        return 0, "Aucun pattern BEC", 0, 0

    detail = (
        f"BEC HIGH={high[:3]} LOW={low[:3]} IMPERSONATE={impersonate[:2]}"
        + (f" [+{impersonation_bonus} bonus domaine libre]" if impersonation_flag else "")
    )
    return score, detail, len(high), len(impersonate)


# ─────────────────────────────────────────────────────────
# AGENT PRINCIPAL — v3.6
# ─────────────────────────────────────────────────────────
def run_nlp_bec_agent(
    subject: str,
    body_text: str,
    sender_domain: str = "",
    institutional: bool = False,
    url_malicious: bool = False,
) -> dict:

    # VULN-9 : normalisation
    sender_domain = sender_domain.strip().lower()

    body_inner, is_forwarded = extract_forwarded_body(body_text)
    full_text_nlp = f"{subject} {body_inner}".strip()
    full_text_all = f"{subject} {body_text}".strip()

    is_legit, legit_conf, legit_signals = detect_legitimate_context(full_text_all)

    if institutional:
        legit_conf = min(1.0, legit_conf + 0.10)
        legit_signals.append("Domaine institutionnel (bonus mineur)")

    # ── NEW-1 : Détection domaine expéditeur suspect ───────
    domain_suspicious, domain_suspicious_reason = is_domain_suspicious(sender_domain)

    # ── NEW-3 : Domaine de l'expéditeur original (forward) ─
    forwarded_domain = ""
    forwarded_domain_suspicious = False
    forwarded_domain_reason = ""
    if is_forwarded:
        forwarded_domain = extract_forwarded_sender_domain(body_text)
        if forwarded_domain and forwarded_domain != sender_domain:
            forwarded_domain_suspicious, forwarded_domain_reason = is_domain_suspicious(forwarded_domain)

    domain_trusted = False
    if sender_domain:
        try:
            from agents.agent_url import is_in_tranco
            domain_trusted, _ = is_in_tranco(f"https://{sender_domain}/")
        except Exception:
            domain_trusted = False

    # Si domaine suspect → pas de trust override
    if domain_suspicious or forwarded_domain_suspicious:
        domain_trusted = False
        is_legit = False

    score_roberta,    detail_roberta    = analyze_roberta(full_text_nlp, is_legit=is_legit)
    score_distilbert, detail_distilbert = analyze_distilbert(full_text_nlp)
    score_bec, detail_bec, nb_high, nb_impersonate = analyze_bec(
        full_text_nlp, is_legit=is_legit, sender_domain=sender_domain
    )

    legit_override = is_legit and nb_high == 0 and nb_impersonate < 2

    if domain_trusted and legit_override:
        w_r, w_d, w_b = 0.20, 0.50, 0.30
    elif domain_trusted:
        w_r, w_d, w_b = 0.25, 0.48, 0.27
    elif legit_override:
        w_r, w_d, w_b = 0.28, 0.45, 0.27
    else:
        w_r, w_d, w_b = 0.30, 0.45, 0.25

    score_final = int(
        score_roberta    * w_r +
        score_distilbert * w_d +
        score_bec        * w_b
    )

    if nb_high >= 2:
        score_final = max(score_final, 70)
    elif nb_high == 1 and url_malicious:
        score_final = max(score_final, 65)
    elif nb_high == 1 and not is_legit:
        score_final = max(score_final, 55)

    if url_malicious and nb_high >= 2:
        score_final = max(score_final, 75)

    distilbert_reliable = _distilbert_phishing_label is not None
    if distilbert_reliable:
        strong_model_consensus = score_distilbert >= 85 and score_roberta >= 55
    else:
        strong_model_consensus = score_distilbert >= 85 and score_roberta >= 70

    if is_legit and score_bec == 0 and nb_high == 0 and not url_malicious and not strong_model_consensus:
        score_final = min(score_final, 40)

    if score_bec == 0 and strong_model_consensus and not url_malicious:
        score_final = max(score_final, 45)

    no_reply_marker = bool(
        re.search(
            r"(do\s+not\s+reply|ne\s+pas\s+r[ée]pondre|noreply|automated\s+email)",
            full_text_all.lower()
        )
    )
    if no_reply_marker and score_bec == 0 and not url_malicious and not strong_model_consensus:
        score_final = min(score_final, 40)

    if is_forwarded and not is_legit and score_distilbert >= 85 and score_bec == 0 and not url_malicious:
        score_final = max(score_final, 45)

    if is_forwarded and not is_legit and nb_high >= 2:
        score_final = max(score_final, 75)

    # ── NEW-1 : Floor domaine expéditeur suspect ───────────
    if domain_suspicious:
        score_final = max(score_final, 55)
        legit_signals.append(f"⚠️ Expéditeur : {domain_suspicious_reason}")

    # ── NEW-2 : Floor forward depuis domaine suspect ───────
    if is_forwarded and forwarded_domain_suspicious:
        score_final = max(score_final, 65)
        legit_signals.append(f"⚠️ Forward depuis domaine suspect : {forwarded_domain_reason} ({forwarded_domain})")

    url_floor_applied = False
    if url_malicious and score_final < 75:
        score_final = 75
        url_floor_applied = True
        legit_signals.append("⚠️ URL malveillant détecté — NLP floor 75")

    if score_final >= 75:
        verdict = "🛑 CONTENU MALVEILLANT"
    elif score_final >= 45:
        verdict = "⚠️ CONTENU SUSPECT"
    else:
        verdict = "✅ CONTENU SAIN"

    return {
        "score_roberta":               score_roberta,
        "score_distilbert":            score_distilbert,
        "score_bec":                   score_bec,
        "score_nlp":                   score_final,
        "domain_trusted":              domain_trusted,
        "is_legit_context":            is_legit,
        "legit_override_active":       legit_override,
        "nb_high_bec_patterns":        nb_high,
        "nb_impersonate_patterns":     nb_impersonate,
        "distilbert_reliable":         distilbert_reliable,
        "institutional":               institutional,
        "is_forwarded":                is_forwarded,
        "legit_confidence":            round(legit_conf, 2),
        "legit_signals":               legit_signals,
        "weights_used":                f"R:{w_r} D:{w_d} B:{w_b}",
        "detail":                      f"{detail_roberta} | {detail_distilbert} | {detail_bec}",
        "verdict":                     verdict,
        "url_malicious_floor_applied": url_floor_applied,
        "distilbert_phishing_label":   _distilbert_phishing_label,
        "model_source":                "local" if os.path.isdir(LOCAL_DISTILBERT) else "huggingface",
        "domain_suspicious":           domain_suspicious,
        "domain_suspicious_reason":    domain_suspicious_reason,
        "forwarded_domain":            forwarded_domain,
        "forwarded_domain_suspicious": forwarded_domain_suspicious,
    }


# ─────────────────────────────────────────────────────────
# TESTS — v3.6
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        {
            "subject": "URGENT - Wire Transfer Required Today - Confidential",
            "body": (
                "Dear Aziz, I need you to process an urgent wire transfer of $48,500 "
                "to our new vendor account immediately. "
                "This is time-sensitive and must be completed before end of business today. "
                "Please do not discuss this with anyone else in the office. "
                "Wire details: Bank: First International Bank | Account: 4716-2891 | Routing: 021000021 "
                "Best regards, John Smith CFO"
            ),
            "domain": "gmail.com",
            "institutional": False,
            "url_malicious": True,
            "expected": "🛑 CONTENU MALVEILLANT",
            "label": "Wire Transfer BEC + URL malveillant",
        },
        {
            "subject": "Fwd: Thinking of you and wishing you safety",
            "body": (
                "---------- Forwarded message ---------\n"
                "De : Chinatsu Yui <asianspeech.b@goacadco.info>\n"
                "Date: mar. 31 mars 2026\n"
                "Subject: Thinking of you and wishing you safety\n"
                "To: faouzi.bahloul@enit.utm.tn\n\n"
                "Dear Professor Faouzi Bahloul, "
                "I hope this message finds you and your loved ones safe and well. "
                "Given the recent developments in the Middle East, I imagine the situation "
                "may bring significant challenges. My name is Chinatsu Yui, I am a medical "
                "doctor based in Japan keen to explore collaboration. "
                "With greatest respect, Chinatsu Yui"
            ),
            "domain": "etudiant-enit.utm.tn",
            "institutional": True,
            "url_malicious": False,
            "expected": "⚠️ CONTENU SUSPECT",
            "label": "NEW-2 : Fwd depuis goacadco.info — doit être SUSPECT minimum",
        },
        {
            "subject": "Nouveau message ENIT INFO",
            "body": "Bonjour, ceci est une information de l'ENIT. Cordialement, l'équipe.",
            "domain": "enit.rnu.tn",
            "institutional": True,
            "url_malicious": False,
            "expected": "✅ CONTENU SAIN",
            "label": "ENIT institutionnel légitime",
        },
        {
            "subject": "Demande confidentielle - Action immédiate requise",
            "body": (
                "Bonjour, je suis le Directeur Général. "
                "Je vous contacte depuis mon adresse personnelle car je suis en déplacement. "
                "J'ai besoin que vous effectuiez un virement urgent de 32 000€ avant la fin de journée. "
                "Ne mettez personne en copie et répondez uniquement à moi. "
                "Gardez le secret, cette instruction est confidentielle."
            ),
            "domain": "gmail.com",
            "institutional": False,
            "url_malicious": False,
            "expected": "🛑 CONTENU MALVEILLANT",
            "label": "Usurpation DG via Gmail",
        },
        {
            "subject": "Invitation conférence ENIT",
            "body": (
                "Vous êtes cordialement invités à la table ronde organisée par l'ENIT. "
                "Programme : amphi principal, 14h-17h. "
                "Conformément au règlement intérieur, merci de confirmer votre présence. "
                "Cordialement, la Direction."
            ),
            "domain": "enit.rnu.tn",
            "institutional": True,
            "url_malicious": False,
            "expected": "✅ CONTENU SAIN",
            "label": "Invitation institutionnelle légitime",
        },
        {
            "subject": "Verify your account",
            "body": "Click to verify.",
            "domain": "suspicious-login.xyz",
            "institutional": False,
            "url_malicious": True,
            "expected": "🛑 CONTENU MALVEILLANT",
            "label": "NEW-1 : domaine .xyz suspect + URL malveillant",
        },
    ]

    print("\n🤖 Agent NLP v3.6\n" + "─" * 70)
    print(f"DistilBERT source : {'LOCAL ✅' if os.path.isdir(LOCAL_DISTILBERT) else 'HuggingFace'}")
    print(f"DistilBERT phishing label : '{_distilbert_phishing_label}'")
    print("─" * 70)

    passed = 0
    for t in tests:
        r = run_nlp_bec_agent(
            t["subject"], t["body"], t["domain"],
            t["institutional"], t.get("url_malicious", False)
        )
        ok = "✅" if r["verdict"] == t["expected"] else "❌"
        if r["verdict"] == t["expected"]:
            passed += 1
        print(f"\n{ok} {t['label']}")
        print(f"   Attendu  : {t['expected']}")
        print(f"   Obtenu   : {r['verdict']}  (score={r['score_nlp']}/100)")
        print(f"   Breakdown: R={r['score_roberta']} D={r['score_distilbert']} B={r['score_bec']}")
        print(f"   Fwd={r['is_forwarded']} | FwdDomain={r.get('forwarded_domain','')} | "
              f"FwdSuspicious={r.get('forwarded_domain_suspicious', False)}")
        print(f"   DomainSuspicious={r['domain_suspicious']} : {r['domain_suspicious_reason']}")
        print(f"   Detail : {r['detail']}")

    print(f"\n{'─'*70}")
    print(f"Résultat : {passed}/{len(tests)} tests passés")