from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

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
    acc = safe_div(tp + tn, len(y_true))
    prec = safe_div(tp, tp + fp)
    rec = safe_div(tp, tp + fn)
    f1 = safe_div(2 * prec * rec, prec + rec)
    return BinaryMetrics(tp, tn, fp, fn, acc, prec, rec, f1)


def pred_label(result: dict[str, Any]) -> int:
    return 1 if int(result.get("score_nlp", 0)) >= 45 else 0


def build_cases() -> list[dict[str, Any]]:
    return [
        # Malicious
        {
            "id": "NB-M-001",
            "angle": "wire_transfer_short",
            "label": 1,
            "name": "Short FR wire transfer",
            "input": {
                "subject": "Virement urgent",
                "body_text": "Virement urgent aujourd'hui. Ne parlez à personne.",
                "sender_domain": "gmail.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-M-002",
            "angle": "gift_card",
            "label": 1,
            "name": "Gift card scam short",
            "input": {
                "subject": "Quick favor",
                "body_text": "Buy gift cards now and send me codes. Keep this between us.",
                "sender_domain": "outlook.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-M-003",
            "angle": "credential_phishing",
            "label": 1,
            "name": "Password verify",
            "input": {
                "subject": "Account suspended",
                "body_text": "Enter your password now to verify account and avoid suspension.",
                "sender_domain": "unknown-alert.net",
                "institutional": False,
                "url_malicious": True,
            },
        },
        {
            "id": "NB-M-004",
            "angle": "ceo_impersonation",
            "label": 1,
            "name": "CEO request from free mail",
            "input": {
                "subject": "CEO request",
                "body_text": "This is confidential. I need this done today. Do not copy anyone.",
                "sender_domain": "gmail.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-M-005",
            "angle": "forwarded_bec",
            "label": 1,
            "name": "Forwarded private transfer instruction",
            "input": {
                "subject": "Fwd: transfer instruction",
                "body_text": "---------- Forwarded message ---------\nFrom: x <x@temp-mail.xyz>\nSubject: transfer\nProcess this payment before end of day and keep this confidential.",
                "sender_domain": "enit.utm.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-M-006",
            "angle": "banking_details",
            "label": 1,
            "name": "Updated banking details",
            "input": {
                "subject": "Supplier update",
                "body_text": "Payment details have changed. Use new bank account details immediately.",
                "sender_domain": "trusted-supplier.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-M-007",
            "angle": "french_confidential",
            "label": 1,
            "name": "Instruction confidentielle FR",
            "input": {
                "subject": "Action immédiate",
                "body_text": "Instruction confidentielle. Effectuez le transfert immédiat avant la fin de journée.",
                "sender_domain": "yahoo.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-M-008",
            "angle": "url_malicious_floor",
            "label": 1,
            "name": "Weak text but malicious URL",
            "input": {
                "subject": "Notice",
                "body_text": "Please check attached notice.",
                "sender_domain": "example.com",
                "institutional": False,
                "url_malicious": True,
            },
        },

        # Benign
        {
            "id": "NB-B-001",
            "angle": "legit_hr",
            "label": 0,
            "name": "HR acknowledgment",
            "input": {
                "subject": "Candidature bien reçue",
                "body_text": "Nous avons bien reçu votre candidature. Merci pour votre intérêt.",
                "sender_domain": "enit.utm.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-002",
            "angle": "legit_meeting",
            "label": 0,
            "name": "Internal meeting short",
            "input": {
                "subject": "Réunion interne",
                "body_text": "Réunion demain à 10h. Merci pour votre présence.",
                "sender_domain": "enit.utm.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-003",
            "angle": "legit_support",
            "label": 0,
            "name": "Customer support neutral",
            "input": {
                "subject": "Ticket updated",
                "body_text": "Dear customer, your support ticket has been updated.",
                "sender_domain": "service.example.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-004",
            "angle": "legit_marketing",
            "label": 0,
            "name": "Marketing announcement",
            "input": {
                "subject": "Spring launch",
                "body_text": "We announce our spring launch and free shipping this week.",
                "sender_domain": "shop.example.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-005",
            "angle": "legit_automated",
            "label": 0,
            "name": "Automated no-reply",
            "input": {
                "subject": "Automated notice",
                "body_text": "This email was sent automatically. Please do not reply.",
                "sender_domain": "noreply.example.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-006",
            "angle": "legit_event",
            "label": 0,
            "name": "Academic invitation",
            "input": {
                "subject": "Invitation conférence",
                "body_text": "Vous êtes invités à la conférence annuelle. Cordialement.",
                "sender_domain": "enit.rnu.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-007",
            "angle": "legit_delivery",
            "label": 0,
            "name": "Order delivery confirmation",
            "input": {
                "subject": "Your order has shipped",
                "body_text": "Thank you for your purchase. Your package arrives Monday.",
                "sender_domain": "shop.example.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "NB-B-008",
            "angle": "legit_procedure",
            "label": 0,
            "name": "Procedure onboarding",
            "input": {
                "subject": "Procédure d'intégration",
                "body_text": "Voici les étapes de la procédure d'intégration RH.",
                "sender_domain": "enit.utm.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
    ]


def evaluate() -> dict[str, Any]:
    cases = build_cases()
    y_true: list[int] = []
    y_pred: list[int] = []
    results: list[dict[str, Any]] = []

    for case in cases:
        out = run_nlp_bec_agent(**case["input"])
        pred = pred_label(out)
        y_true.append(case["label"])
        y_pred.append(pred)
        results.append(
            {
                "id": case["id"],
                "angle": case["angle"],
                "name": case["name"],
                "true_label": case["label"],
                "pred_label": pred,
                "score_nlp": out.get("score_nlp"),
                "score_roberta": out.get("score_roberta"),
                "score_distilbert": out.get("score_distilbert"),
                "score_bec": out.get("score_bec"),
                "verdict": out.get("verdict"),
                "detail": out.get("detail"),
            }
        )

    m = compute_binary_metrics(y_true, y_pred)
    false_negatives = [r for r in results if r["true_label"] == 1 and r["pred_label"] == 0]
    false_positives = [r for r in results if r["true_label"] == 0 and r["pred_label"] == 1]

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "agent": "agent_nlp_bec",
        "decision_rule": "pred=1 if score_nlp >= 45 else 0",
        "num_cases": len(cases),
        "metrics": asdict(m),
        "confusion_matrix": [[m.tn, m.fp], [m.fn, m.tp]],
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "all_results": results,
    }


def save_report(data: dict[str, Any]) -> tuple[Path, Path]:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"nlp_blindspots_report_{ts}.json"
    md_path = reports_dir / f"nlp_blindspots_report_{ts}.md"

    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    m = data["metrics"]
    lines = [
        "# Rapport blindspots NLP/BEC",
        "",
        f"Date: {data['generated_at']}",
        f"Matrice [[TN, FP], [FN, TP]]: {data['confusion_matrix']}",
        (
            "Metrics: "
            f"accuracy={m['accuracy']:.3f}, precision={m['precision']:.3f}, "
            f"recall={m['recall']:.3f}, f1={m['f1']:.3f}, "
            f"tp={m['tp']}, tn={m['tn']}, fp={m['fp']}, fn={m['fn']}"
        ),
        "",
        "## False negatives",
    ]

    if data["false_negatives"]:
        for fn in data["false_negatives"]:
            lines.append(
                f"- {fn['id']} | score={fn['score_nlp']} | {fn['name']} | {fn['detail']}"
            )
    else:
        lines.append("- Aucun")

    lines += ["", "## False positives"]
    if data["false_positives"]:
        for fp in data["false_positives"]:
            lines.append(
                f"- {fp['id']} | score={fp['score_nlp']} | {fp['name']} | {fp['detail']}"
            )
    else:
        lines.append("- Aucun")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main() -> None:
    data = evaluate()
    json_path, md_path = save_report(data)
    print("=== NLP BLINDSPOTS TEST COMPLETE ===")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print("Confusion matrix:", data["confusion_matrix"])
    print("Metrics:", data["metrics"])
    print("False negatives:", len(data["false_negatives"]))
    print("False positives:", len(data["false_positives"]))


if __name__ == "__main__":
    main()
