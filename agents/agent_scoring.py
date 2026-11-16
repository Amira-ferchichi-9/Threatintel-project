# agents/agent_scoring.py — v3.1
# Fix v3.1 : subject + sender passés aux hard rules pour détecter BEC critique
import os
import re
import numpy as np
np.random.seed(42)
import pandas as pd
import logging
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from xgboost import XGBClassifier


logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────
# CHARGEMENT DATASET RÉEL
# ─────────────────────────────────────────────────────────
_dataset_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '../datasets/threatintel_training_dataset_v6.csv'
)

print("[🌲 SCORING] Chargement dataset réel...")
_df = pd.read_csv(_dataset_path)
_df = _df[['auth_score','url_score','nlp_score','sandbox_score','label']].dropna()

print(f"[🌲 SCORING] {len(_df)} exemples chargés")
print(f"[🌲 SCORING] Sain={(_df.label==0).sum()} | Suspect={(_df.label==1).sum()} | Danger={(_df.label==2).sum()}")

X_raw = _df[['auth_score','url_score','nlp_score','sandbox_score']].values.astype(float)
y_raw = _df['label'].values.astype(int)

# ─────────────────────────────────────────────────────────
# SMOTE — Équilibrage classe Suspect
# ─────────────────────────────────────────────────────────
print("[🌲 SCORING] Application SMOTE pour équilibrage...")

n_sain   = int((_df.label==0).sum())
n_danger = int((_df.label==2).sum())
n_target = max(2000, int((_df.label==1).sum() * 5))
n_target = min(n_target, min(n_sain, n_danger))

smote = SMOTE(
    sampling_strategy={1: n_target},
    random_state=42,
    k_neighbors=min(5, int((_df.label==1).sum()) - 1)
)
X_resampled, y_resampled = smote.fit_resample(X_raw, y_raw)

unique, counts = np.unique(y_resampled, return_counts=True)
for cls, cnt in zip(unique, counts):
    name = ['Sain','Suspect','Danger'][cls]
    print(f"[🌲 SCORING]   {name}: {cnt}")

# ─────────────────────────────────────────────────────────
# SPLIT TRAIN / TEST
# ─────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled,
    test_size=0.2,
    random_state=42,
    stratify=y_resampled
)

scaler    = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s  = scaler.transform(X_test)

# ─────────────────────────────────────────────────────────
# MODÈLES — Random Forest + XGBoost Ensemble
# ─────────────────────────────────────────────────────────
print("[🌲 SCORING] Entraînement Random Forest...")
rf_model = RandomForestClassifier(
    n_estimators=300,
    max_depth=10,
    random_state=42,
    class_weight='balanced',
    min_samples_leaf=2,
    n_jobs=-1,
)

print("[🌲 SCORING] Entraînement XGBoost...")
xgb_model = XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    eval_metric='mlogloss',
    verbosity=0,
    use_label_encoder=False,
)

print("[🌲 SCORING] Entraînement Ensemble (RF + XGBoost)...")
ensemble = VotingClassifier(
    estimators=[('rf', rf_model), ('xgb', xgb_model)],
    voting='soft',
    weights=[2, 3],
)
ensemble.fit(X_train_s, y_train)

# ─────────────────────────────────────────────────────────
# ÉVALUATION
# ─────────────────────────────────────────────────────────
y_pred = ensemble.predict(X_test_s)
print("\n[🌲 SCORING] ═══ RÉSULTATS ═══")
print(classification_report(
    y_test, y_pred,
    target_names=['Sain','Suspect','Danger']
))

rf_fitted   = ensemble.named_estimators_['rf']
importances = rf_fitted.feature_importances_
feature_names = ['Auth','URL','NLP','Sandbox']
print("[🌲 SCORING] Feature importances (RF) :")
for name, imp in zip(feature_names, importances):
    bar = '█' * int(imp * 40)
    print(f"  {name:8s} : {imp*100:5.1f}%  {bar}")

print("[🌲 SCORING] Modèle prêt ✅\n")

# ─────────────────────────────────────────────────────────
# HARD RULES — v3.1 (avec subject + sender)
# ─────────────────────────────────────────────────────────
BEC_KEYWORDS = [
    'wire transfer', 'urgent', 'payment required', 'transfer required',
    'required today', 'wire', 'virement', 'urgent payment', 'confidential',
    'immediate', 'today only', 'act now', 'verify your account',
    'suspended', 'confirm your', 'update your'
]

ESP_DOMAINS = {
    'msprvs1', 'bounce', 'em.', 'send.', 'mail.', 'sg.',
    'brevosend', 'mailchimp', 'sendgrid', 'amazonses',
    'sparkpost', 'mandrill', 'klaviyo', 'brevo', 'mailjet',
    'constantcontact', 'campaign-archive'
}

LEGIT_SENDERS = {
    'coursera.org', 'learn.coursera.org', 'classroom.google.com',
    'pinterest.com', 'ideas.pinterest.com', 'lenovo.com',
    'ecomm.lenovo.com', 'pixlr.com', 'newsletter.pixlr.com',
    'linkedin.com', 'github.com', 'google.com', 'microsoft.com',
    'apple.com', 'amazon.com', 'paypal.com', 'youtube.com',
    'netflix.com', 'spotify.com', 'notion.so', 'slack.com',
}

SUSPICIOUS_SENDER_TLDS = {
    '.info', '.xyz', '.top', '.click', '.gq', '.tk', '.ml', '.cf', '.ga',
}


def _is_legit_newsletter(sender: str) -> bool:
    """Détecte les newsletters légitimes via domaine expéditeur connu."""
    sender_l = sender.lower()
    for domain in LEGIT_SENDERS:
        if domain in sender_l:
            return True
    return False


def _extract_sender_domain(sender: str) -> str:
    """Extrait le domaine de l'adresse email expéditeur."""
    match = re.search(r'@([\w.\-]+)', sender.lower())
    return match.group(1) if match else ""


def apply_hard_rules(auth, url, nlp, sandbox, subject="", sender="") -> tuple:
    subject_l = (subject or "").lower()
    sender_l = (sender or "").lower()
    sender_domain = _extract_sender_domain(sender_l)


    # ── SIGNAL UNIQUE CRITIQUE — un seul agent suffit ────
    # URL seule très malveillante
    if url >= 80:
        return 2, "URL critique — vecteur unique détecté"

    # NLP seul très malveillant
    if nlp >= 85:
        # Ne pas bloquer si expéditeur légitime connu + auth correcte
        if _is_legit_newsletter(sender_l) and auth >= 50:
            return 1, "NLP élevé mais expéditeur légitime authentifié (quarantaine)"
        return 2, "NLP critique — contenu malveillant confirmé"

    # Sandbox seul critique
    if sandbox >= 75:
        return 2, "Sandbox critique — menace dans PJ"

    # Auth nulle seule = suspect minimum (jamais sain)
    if auth <= 5 and url == 0 and nlp == 0 and sandbox == 0:
        return 1, "Auth totalement absente — expéditeur non vérifiable"

    # ── SIGNAUX COMBINÉS MODÉRÉS ──────────────────────────
    # URL modérée + auth faible
    if url >= 50 and auth <= 30:
        return 2, "URL suspecte + auth faible"

    # NLP élevé + auth piégée (Reply-To mismatch, partial auth) → BEC probable
    if nlp >= 65 and auth <= 25 and not _is_legit_newsletter(sender_l):
        return 2, "NLP suspect + auth piégée (BEC probable)"

    # Pièce jointe suspecte + expéditeur faiblement authentifié
    if sandbox >= 40 and auth <= 35:
        return 2, "Pièce jointe suspecte + expéditeur faiblement authentifié"

    # Domaine explicitement suspect (cousin domain, TLD exotique) + URL présente
    if auth <= 15 and url >= 8 and not _is_legit_newsletter(sender_l):
        return 2, "Domaine suspect confirmé + URL dans message"

    # Reply-To piégé + contenu financier modéré → quarantaine préventive (BEC)
    if auth <= 25 and nlp >= 20 and url == 0 and sandbox == 0 and not _is_legit_newsletter(sender_l):
        return 1, "Reply-To suspect + contenu financier (BEC probable — quarantaine)"

    # NLP modéré + auth nulle
    # Réduit les faux positifs : sans URL/PJ malveillante, ce cas reste SUSPECT.
    if nlp >= 60 and auth <= 10:
        if nlp >= 75 or url >= 25 or sandbox >= 40:
            return 2, "Contenu suspect + expéditeur non authentifié"
        return 1, "Auth absente + contenu suspect (quarantaine)"

    # Filet de sécurité : auth nulle + NLP suspect = au moins quarantaine
    if auth <= 10 and nlp >= 45:
        return 1, "Auth absente + contenu suspect"

    # Forward social engineering : auth nulle + signal forward + expéditeur exotique
    if auth <= 10 and nlp >= 35 and ("fwd:" in subject_l or "forwarded" in subject_l):
        if sender_domain.endswith(tuple(SUSPICIOUS_SENDER_TLDS)) and not _is_legit_newsletter(sender_l):
            return 1, "Forward douteux + auth absente"

    # NLP modéré + URL modérée
    if nlp >= 55 and url >= 40:
        return 2, "Double signal NLP+URL"

    # Sandbox modéré
    if sandbox >= 40:
        return 1, "Sandbox : comportement suspect"
    is_fwd = "fwd:" in subject_l or "forwarded" in subject_l
    
    if is_fwd and nlp >= 40 and auth <= 10:
        return 2, "Forward BEC détecté — expéditeur non authentifié"
    
    return None, None


# ─────────────────────────────────────────────────────────
# AGENT PRINCIPAL
# ─────────────────────────────────────────────────────────
def run_scoring_agent(
    score_auth: int,
    score_url: int,
    score_nlp: int,
    score_sandbox: int = 0,
    subject: str = "",
    sender: str = ""
) -> dict:
    """
    Scoring final — Ensemble RF+XGBoost + Hard Rules.
    Retourne un dict complet avec verdict, score, probabilités.
    """
    # Hard rules d'abord
    hard_pred, hard_reason = apply_hard_rules(
        score_auth, score_url, score_nlp, score_sandbox, subject, sender
    )

    # Prédiction ensemble ML
    features        = np.array([[score_auth, score_url, score_nlp, score_sandbox]], dtype=float)
    features_scaled = scaler.transform(features)

    rf_pred    = rf_fitted.predict(features_scaled)[0]
    rf_probas  = rf_fitted.predict_proba(features_scaled)[0]
    ens_pred   = ensemble.predict(features_scaled)[0]
    ens_probas = ensemble.predict_proba(features_scaled)[0]

    score_final = int(ens_probas[2] * 100 + ens_probas[1] * 50)
    score_final = min(100, score_final)

    final_pred = hard_pred if hard_pred is not None else int(ens_pred)

    # Override anti-faux-positifs : expéditeur légitime + auth correcte + aucun signal URL/PJ.
    sender_l = (sender or "").lower()
    trusted_sender = _is_legit_newsletter(sender_l)
    low_tech_signal = score_url <= 20 and score_sandbox <= 20
    if trusted_sender and score_auth >= 50 and low_tech_signal:
        if score_nlp >= 85:
            # NLP très haut sur expéditeur fiable : garder prudence mais éviter blocage direct.
            final_pred = min(final_pred, 1)
            if not hard_reason:
                hard_reason = "Override: expéditeur légitime authentifié (quarantaine préventive)"
        else:
            final_pred = 0
            if not hard_reason:
                hard_reason = "Override: expéditeur légitime authentifié"

    # Cohérence score / prédiction
    if final_pred == 2 and score_final < 70:
        score_final = max(score_final, 75)
    elif final_pred == 1:
        # Un verdict SUSPECT doit rester dans une plage suspecte (pas "danger-like").
        score_final = max(score_final, 45)
        score_final = min(score_final, 69)

        # Cas fréquent: auth absente + contenu suspect (quarantaine préventive).
        # Calibrage plus lisible autour de 45-65 selon le niveau NLP.
        if hard_reason and "Auth absente + contenu suspect" in hard_reason:
            nlp_based_cap = 45 + max(0, min(20, (score_nlp - 40) // 2))
            score_final = min(score_final, nlp_based_cap)
    elif final_pred == 0 and score_final > 40:
        score_final = min(score_final, 35)

    dominant = feature_names[int(np.argmax(importances))]

    if final_pred == 2:
        verdict, action = "🛑 DANGER — BLOQUÉ",       "BLOCK"
    elif final_pred == 1:
        verdict, action = "⚠️ SUSPECT — QUARANTAINE", "QUARANTINE"
    else:
        verdict, action = "✅ SAIN — DÉLIVRÉ",         "DELIVER"

    return {
        "score_auth":    score_auth,
        "score_url":     score_url,
        "score_nlp":     score_nlp,
        "score_sandbox": score_sandbox,
        "score_final":   score_final,
        "prediction":    final_pred,
        "rf_prediction": int(rf_pred),
        "ens_prediction":int(ens_pred),
        "hard_rule":     hard_reason,
        "probabilites": {
            "sain":    round(float(ens_probas[0]) * 100, 1),
            "suspect": round(float(ens_probas[1]) * 100, 1),
            "danger":  round(float(ens_probas[2]) * 100, 1),
        },
        "feature_importances": {
            n: round(float(i) * 100, 1)
            for n, i in zip(feature_names, importances)
        },
        "facteur_dominant": dominant,
        "verdict":  verdict,
        "action":   action,
    }


# ─────────────────────────────────────────────────────────
# TESTS
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    tests = [
        # Cas réels boîte mail
        {"label": "Fwd: Thinking of you (BEC)",         "auth": 0,   "url": 0,  "nlp": 45, "sandbox": 0,
         "subject": "Fwd: Thinking of you and wishing you safety", "sender": "amira.ferchichi@etudiant-enit.utm.tn"},
        {"label": "URGENT Wire Transfer (BEC)",          "auth": 0,   "url": 0,  "nlp": 55, "sandbox": 0,
         "subject": "URGENT - Wire Transfer Required Today", "sender": "amira.ferchichi@etudiant-enit.utm.tn"},
        {"label": "Coursera promo (légitime)",           "auth": 66,  "url": 10, "nlp": 60, "sandbox": 0,
         "subject": "Ends tomorrow: Lock in 40% off Coursera Plus", "sender": "Coursera <Coursera@m.learn.coursera.org>"},
        {"label": "Tarek Kouki ENIT (légitime)",         "auth": 60,  "url": 0,  "nlp": 65, "sandbox": 0,
         "subject": "Nouveau support de cours", "sender": "Tarek Kouki <no-reply@classroom.google.com>"},
        {"label": "Lenovo sale (légitime)",              "auth": 55,  "url": 10, "nlp": 50, "sandbox": 0,
         "subject": "Ends Today. No Extensions.", "sender": "Lenovo <lenovo@ecomm.lenovo.com>"},
        # Cas de test originaux
        {"label": "Sopra RH accusé réception",           "auth": 66,  "url": 0,  "nlp": 45, "sandbox": 0,
         "subject": "Accusé réception candidature", "sender": "rh@soprasteria.com"},
        {"label": "Valeo Workday candidature",           "auth": 100, "url": 10, "nlp": 30, "sandbox": 0,
         "subject": "Votre candidature Valeo", "sender": "workday@valeo.com"},
        {"label": "Phishing complet",                    "auth": 0,   "url": 72, "nlp": 85, "sandbox": 80,
         "subject": "Verify your account now", "sender": "support@paypa1.tk"},
        {"label": "BEC pur",                             "auth": 0,   "url": 0,  "nlp": 99, "sandbox": 0,
         "subject": "Urgent wire transfer needed", "sender": "ceo@company-fake.com"},
        {"label": "Phishing URL IP",                     "auth": 0,   "url": 95, "nlp": 70, "sandbox": 0,
         "subject": "Click here urgently", "sender": "alert@192.168.1.1"},
        {"label": "Newsletter légitime",                 "auth": 66,  "url": 10, "nlp": 20, "sandbox": 0,
         "subject": "Weekly digest", "sender": "newsletter@github.com"},
    ]

    print("\n🌲 Agent Scoring v3.1 — Tests\n" + "═" * 60)
    for t in tests:
        r = run_scoring_agent(
            t["auth"], t["url"], t["nlp"], t["sandbox"],
            subject=t.get("subject", ""),
            sender=t.get("sender", "")
        )
        icon = "✅" if r["prediction"] == 0 else ("⚠️" if r["prediction"] == 1 else "🛑")
        print(f"\n{icon} {t['label']}")
        print(f"   Score : {r['score_final']}/100 | {r['verdict']}")
        print(f"   Probas: Sain={r['probabilites']['sain']}% | Suspect={r['probabilites']['suspect']}% | Danger={r['probabilites']['danger']}%")
        if r.get('hard_rule'):
            print(f"   Règle : {r['hard_rule']}")