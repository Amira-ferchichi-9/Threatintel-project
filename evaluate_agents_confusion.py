from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from agents.agent_auth import run_auth_agent
from agents.agent_nlp_bec import run_nlp_bec_agent


@dataclass
class BinaryMetrics:
    tp: int
    tn: int
    fp: int
    fn: int
    accuracy: float
    precision: float
    recall: float
    f1: float


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def compute_binary_metrics(y_true: list[int], y_pred: list[int]) -> BinaryMetrics:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    accuracy = safe_div(tp + tn, len(y_true))
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    return BinaryMetrics(tp, tn, fp, fn, accuracy, precision, recall, f1)


def auth_prediction_to_label(result: dict[str, Any]) -> int:
    # Positive class = malicious/suspicious identity.
    return 1 if int(result.get("score_auth", 0)) < 55 else 0


def nlp_prediction_to_label(result: dict[str, Any]) -> int:
    # Positive class = malicious/suspicious content.
    return 1 if int(result.get("score_nlp", 0)) >= 45 else 0


def evaluate_auth_agent() -> dict[str, Any]:
    cases = [
        {
            "id": "AUTH-001",
            "label": 0,
            "name": "Le9gitime entreprise, authentification aligne9e",
            "input": {
                "sender": '"Finance Team" <finance@acme-corp.com>',
                "reply_to": "",
                "return_path": "<bounce@acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=reject)",
            },
        },
        {
            "id": "AUTH-002",
            "label": 0,
            "name": "Sous-domaine aligne9 le9gitime",
            "input": {
                "sender": '"IT Security" <alerts@mail.acme-corp.com>',
                "reply_to": "",
                "return_path": "<mail@mail.acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=mail.acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "AUTH-003",
            "label": 1,
            "name": "Usurpation DG via Gmail",
            "input": {
                "sender": '"Directeur Ge9ne9ral" <ceo.request@gmail.com>',
                "reply_to": "",
                "return_path": "<ceo.request@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-004",
            "label": 1,
            "name": "Homograph domain",
            "input": {
                "sender": '"Support" <help@microsоft.com>',
                "reply_to": "",
                "return_path": "<help@microsоft.com>",
                "authentication_results": "spf=pass smtp.mailfrom=microsоft.com; dkim=pass header.i=@microsоft.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-005",
            "label": 1,
            "name": "Cousin domain (paypa1)",
            "input": {
                "sender": '"PayPal Billing" <alerts@paypa1.com>',
                "reply_to": "",
                "return_path": "<alerts@paypa1.com>",
                "authentication_results": "spf=pass smtp.mailfrom=paypa1.com; dkim=pass header.i=@paypa1.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-006",
            "label": 1,
            "name": "Reply-To mismatch",
            "input": {
                "sender": '"Vendor" <vendor@trusted-supplier.com>',
                "reply_to": "frauddesk@pay-out-now.net",
                "return_path": "<vendor@trusted-supplier.com>",
                "authentication_results": "spf=pass smtp.mailfrom=trusted-supplier.com; dkim=pass header.i=@trusted-supplier.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "AUTH-007",
            "label": 1,
            "name": "Return-Path mismatch",
            "input": {
                "sender": '"Accounts" <accounts@acme-corp.com>',
                "reply_to": "",
                "return_path": "<billing@payment-update.net>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "AUTH-008",
            "label": 1,
            "name": "SPF/DKIM/DMARC fail",
            "input": {
                "sender": '"Security" <security@bank-secure-alert.com>',
                "reply_to": "",
                "return_path": "<mailer@bank-secure-alert.com>",
                "authentication_results": "spf=fail smtp.mailfrom=bank-secure-alert.com; dkim=fail header.i=@bank-secure-alert.com; dmarc=fail (p=reject)",
            },
        },
        {
            "id": "AUTH-009",
            "label": 1,
            "name": "DKIM alignment casse9",
            "input": {
                "sender": '"Office365 Alert" <noreply@contoso.com>',
                "reply_to": "",
                "return_path": "<noreply@contoso.com>",
                "authentication_results": "spf=pass smtp.mailfrom=contoso.com; dkim=pass header.i=@mailer-thirdparty.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-010",
            "label": 1,
            "name": "SPF alignment casse9",
            "input": {
                "sender": '"Invoice" <invoice@acme-corp.com>',
                "reply_to": "",
                "return_path": "<invoice@acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=mail-relay-untrusted.net; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-011",
            "label": 0,
            "name": "Newsletter le9gitime avec DMARC none",
            "input": {
                "sender": '"News Team" <news@legit-media.com>',
                "reply_to": "",
                "return_path": "<bounce@legit-media.com>",
                "authentication_results": "spf=pass smtp.mailfrom=legit-media.com; dkim=pass header.i=@legit-media.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-012",
            "label": 0,
            "name": "Mail interne sans Reply-To/Return-Path anormal",
            "input": {
                "sender": '"RH" <recrutement@enit.utm.tn>',
                "reply_to": "",
                "return_path": "<recrutement@enit.utm.tn>",
                "authentication_results": "spf=pass smtp.mailfrom=enit.utm.tn; dkim=pass header.i=@utm.tn; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "AUTH-013",
            "label": 1,
            "name": "Domaine gratuit + exe9cutif anglais",
            "input": {
                "sender": '"Chief Financial Officer" <cfo.board@outlook.com>',
                "reply_to": "",
                "return_path": "<cfo.board@outlook.com>",
                "authentication_results": "spf=pass smtp.mailfrom=outlook.com; dkim=pass header.i=@outlook.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "AUTH-014",
            "label": 0,
            "name": "SPF softfail mais contexte le9gitime",
            "input": {
                "sender": '"Vendor Portal" <no-reply@trusted-portal.com>',
                "reply_to": "",
                "return_path": "<mailer@trusted-portal.com>",
                "authentication_results": "spf=softfail smtp.mailfrom=trusted-portal.com; dkim=pass header.i=@trusted-portal.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "AUTH-015",
            "label": 1,
            "name": "Aucun signal auth + mismatch",
            "input": {
                "sender": '"Finance" <finance@unknown-payments.net>',
                "reply_to": "secureteam@external-verify.org",
                "return_path": "<bounce@mailer-temp.xyz>",
                "authentication_results": "",
            },
        },
        {
            "id": "AUTH-016",
            "label": 0,
            "name": "DMARC reject enterprise propre",
            "input": {
                "sender": '"Microsoft Alerts" <alerts@microsoft.com>',
                "reply_to": "",
                "return_path": "<alerts@microsoft.com>",
                "authentication_results": "spf=pass smtp.mailfrom=microsoft.com; dkim=pass header.i=@microsoft.com; dmarc=pass (p=reject)",
            },
        },
    ]

    y_true: list[int] = []
    y_pred: list[int] = []
    details: list[dict[str, Any]] = []

    for case in cases:
        result = run_auth_agent(**case["input"])
        pred = auth_prediction_to_label(result)
        y_true.append(case["label"])
        y_pred.append(pred)
        details.append(
            {
                "id": case["id"],
                "name": case["name"],
                "true_label": case["label"],
                "pred_label": pred,
                "score_auth": result.get("score_auth"),
                "verdict": result.get("verdict"),
                "detail": result.get("detail"),
            }
        )

    metrics = compute_binary_metrics(y_true, y_pred)
    misclassified = [d for d in details if d["true_label"] != d["pred_label"]]

    return {
        "agent": "agent_auth",
        "positive_class": "malicious_or_suspicious_identity",
        "threshold_rule": "pred=1 if score_auth < 55 else 0",
        "num_cases": len(cases),
        "metrics": asdict(metrics),
        "confusion_matrix": {
            "labels": ["benign(0)", "malicious(1)"],
            "matrix": [[metrics.tn, metrics.fp], [metrics.fn, metrics.tp]],
        },
        "misclassified": misclassified,
        "all_results": details,
    }


def evaluate_nlp_agent() -> dict[str, Any]:
    cases = [
        {
            "id": "NLP-001",
            "label": 1,
            "name": "Wire transfer urgent confidentiel",
            "input": {
                "subject": "URGENT - process wire transfer now",
                "body_text": "I need you to process an urgent wire transfer today. Do not discuss this with anyone and send confirmation.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-002",
            "label": 1,
            "name": "Gift cards scam",
            "input": {
                "subject": "Quick request",
                "body_text": "Please buy Amazon gift cards and send me the codes immediately. Keep this between us.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-003",
            "label": 1,
            "name": "Reset password phishing",
            "input": {
                "subject": "Your account will be suspended",
                "body_text": "Verify your identity now. Enter your password immediately to avoid account suspension.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": True,
            },
        },
        {
            "id": "NLP-004",
            "label": 1,
            "name": "French virement urgent",
            "input": {
                "subject": "Virement immédiat",
                "body_text": "Merci de faire un virement urgent aujourd'hui. Ne parlez à personne de cette instruction confidentielle.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-005",
            "label": 1,
            "name": "Invoice spoof + urgency",
            "input": {
                "subject": "Invoice attached - urgent action required",
                "body_text": "Process this payment before end of day. Updated banking details are attached.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-006",
            "label": 1,
            "name": "Forwarded suspicious collaboration",
            "input": {
                "subject": "Fwd: private proposal",
                "body_text": "---------- Forwarded message ---------\nFrom: unknown person <x@temp-mail.xyz>\nSubject: private proposal\nI need this done today and keep this confidential.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-007",
            "label": 1,
            "name": "Do not discuss + bank details",
            "input": {
                "subject": "Confidential instruction",
                "body_text": "This is a personal request. Transfer the funds to this new bank account and do not discuss with anyone.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-008",
            "label": 1,
            "name": "Compromised account lure",
            "input": {
                "subject": "Security notice",
                "body_text": "Your account has been compromised. Click to verify and confirm your account now.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": True,
            },
        },
        {
            "id": "NLP-009",
            "label": 1,
            "name": "Routing number request",
            "input": {
                "subject": "Bank transfer setup",
                "body_text": "Share routing number and account number urgently so we can complete transfer of funds.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-010",
            "label": 1,
            "name": "CEO request",
            "input": {
                "subject": "CEO request",
                "body_text": "This is time-sensitive. I need you to process urgently and keep this between us.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-011",
            "label": 0,
            "name": "Accuse9 de re9ception candidature",
            "input": {
                "subject": "Candidature bien ree7ue",
                "body_text": "Nous avons bien ree7u votre candidature. Nous allons examiner votre dossier conforme9ment au RGPD.",
                "sender_domain": "",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-012",
            "label": 0,
            "name": "Invitation e9ve9nement acade9mique",
            "input": {
                "subject": "Invitation e0 la confe9rence IA",
                "body_text": "Vous eates invite9s e0 la confe9rence annuelle. Cordialement, e9quipe organisation.",
                "sender_domain": "",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-013",
            "label": 0,
            "name": "Newsletter marketing standard",
            "input": {
                "subject": "Spring launch and free shipping",
                "body_text": "We announce our new product launch. Shop now and enjoy free shipping this week.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-014",
            "label": 0,
            "name": "Re9union interne",
            "input": {
                "subject": "Re9union cellule qualite9",
                "body_text": "Bonjour, re9union demain e0 10h. Merci pour votre pre9sence.",
                "sender_domain": "",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-015",
            "label": 0,
            "name": "Confirmation livraison e-commerce",
            "input": {
                "subject": "Your order has shipped",
                "body_text": "Thank you for your purchase. Your package will be delivered on Monday.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-016",
            "label": 0,
            "name": "Message procedural",
            "input": {
                "subject": "Proce9dure d'onboarding",
                "body_text": "Voici les e9tapes de la proce9dure d'inte9gration. Merci de suivre les instructions RH.",
                "sender_domain": "",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-017",
            "label": 0,
            "name": "Automated no-reply le9gitime",
            "input": {
                "subject": "Automated email notice",
                "body_text": "This email was sent automatically. Please do not reply. Your profile update is complete.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-018",
            "label": 0,
            "name": "Merci pour votre candidature",
            "input": {
                "subject": "Merci pour votre candidature",
                "body_text": "Nous vous remercions pour votre intérêt. Votre candidature sera étudiée prochainement.",
                "sender_domain": "",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-019",
            "label": 0,
            "name": "Communication universitaire",
            "input": {
                "subject": "Nouveau programme amphi",
                "body_text": "Programme de la semaine disponible. Bien à vous, direction des études.",
                "sender_domain": "",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NLP-020",
            "label": 0,
            "name": "Support client neutre",
            "input": {
                "subject": "Ticket updated",
                "body_text": "Dear customer, your support request has been updated by our team.",
                "sender_domain": "",
                "institutional": False,
                "url_malicious": False,
            },
        },
    ]

    y_true: list[int] = []
    y_pred: list[int] = []
    details: list[dict[str, Any]] = []

    for case in cases:
        result = run_nlp_bec_agent(**case["input"])
        pred = nlp_prediction_to_label(result)
        y_true.append(case["label"])
        y_pred.append(pred)
        details.append(
            {
                "id": case["id"],
                "name": case["name"],
                "true_label": case["label"],
                "pred_label": pred,
                "score_nlp": result.get("score_nlp"),
                "score_roberta": result.get("score_roberta"),
                "score_distilbert": result.get("score_distilbert"),
                "score_bec": result.get("score_bec"),
                "verdict": result.get("verdict"),
                "detail": result.get("detail"),
            }
        )

    metrics = compute_binary_metrics(y_true, y_pred)
    misclassified = [d for d in details if d["true_label"] != d["pred_label"]]

    return {
        "agent": "agent_nlp_bec",
        "positive_class": "malicious_or_suspicious_content",
        "threshold_rule": "pred=1 if score_nlp >= 45 else 0",
        "num_cases": len(cases),
        "metrics": asdict(metrics),
        "confusion_matrix": {
            "labels": ["benign(0)", "malicious(1)"],
            "matrix": [[metrics.tn, metrics.fp], [metrics.fn, metrics.tp]],
        },
        "misclassified": misclassified,
        "all_results": details,
    }


def write_reports(results: dict[str, Any]) -> tuple[Path, Path]:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"agent_eval_{ts}.json"
    md_path = reports_dir / f"agent_eval_{ts}.md"

    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    auth = results["auth"]
    nlp = results["nlp"]

    def line_metrics(m: dict[str, Any]) -> str:
        return (
            f"accuracy={m['accuracy']:.3f}, precision={m['precision']:.3f}, "
            f"recall={m['recall']:.3f}, f1={m['f1']:.3f}, "
            f"tp={m['tp']}, tn={m['tn']}, fp={m['fp']}, fn={m['fn']}"
        )

    md = [
        "# Rapport d'évaluation agents (tests robustes)",
        "",
        f"Date: {datetime.now().isoformat(timespec='seconds')}",
        "",
        "## Agent Auth",
        f"- Cas testés: {auth['num_cases']}",
        f"- Règle de décision: {auth['threshold_rule']}",
        f"- Métriques: {line_metrics(auth['metrics'])}",
        f"- Matrice de confusion [ [TN, FP], [FN, TP] ]: {auth['confusion_matrix']['matrix']}",
        f"- Erreurs de classification: {len(auth['misclassified'])}",
        "",
        "## Agent NLP_BEC",
        f"- Cas testés: {nlp['num_cases']}",
        f"- Règle de décision: {nlp['threshold_rule']}",
        f"- Métriques: {line_metrics(nlp['metrics'])}",
        f"- Matrice de confusion [ [TN, FP], [FN, TP] ]: {nlp['confusion_matrix']['matrix']}",
        f"- Erreurs de classification: {len(nlp['misclassified'])}",
        "",
        "## Détails erreurs",
        "",
        "### Auth",
    ]

    if auth["misclassified"]:
        for e in auth["misclassified"]:
            md.append(
                f"- {e['id']} | true={e['true_label']} pred={e['pred_label']} | score={e['score_auth']} | {e['name']}"
            )
    else:
        md.append("- Aucune erreur")

    md += ["", "### NLP_BEC"]
    if nlp["misclassified"]:
        for e in nlp["misclassified"]:
            md.append(
                f"- {e['id']} | true={e['true_label']} pred={e['pred_label']} | score={e['score_nlp']} | {e['name']}"
            )
    else:
        md.append("- Aucune erreur")

    md_path.write_text("\n".join(md), encoding="utf-8")
    return json_path, md_path


def main() -> None:
    auth_result = evaluate_auth_agent()
    nlp_result = evaluate_nlp_agent()

    final = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "auth": auth_result,
        "nlp": nlp_result,
    }

    json_path, md_path = write_reports(final)

    print("=== EVALUATION COMPLETE ===")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")

    print("\n[AUTH] confusion matrix:", auth_result["confusion_matrix"]["matrix"])
    print("[AUTH] metrics:", auth_result["metrics"])

    print("\n[NLP] confusion matrix:", nlp_result["confusion_matrix"]["matrix"])
    print("[NLP] metrics:", nlp_result["metrics"])


if __name__ == "__main__":
    main()

