from __future__ import annotations

import csv
import json
import random
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from agents.agent_nlp_bec import run_nlp_bec_agent

csv.field_size_limit(sys.maxsize)


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


def pred_label(result: dict[str, Any]) -> int:
    return 1 if int(result.get("score_nlp", 0)) >= 45 else 0


def text_to_subject_body(text: str) -> tuple[str, str]:
    words = text.split()
    if not words:
        return "", ""
    subject = " ".join(words[:10])
    body = " ".join(words[10:])
    if not body:
        body = subject
    return subject[:180], body[:3500]


def load_phishing_email_csv(path: Path, per_class: int = 120) -> list[dict[str, Any]]:
    rows_0: list[tuple[str, int]] = []
    rows_1: list[tuple[str, int]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            text = (row.get("text_combined") or "").strip()
            label_raw = (row.get("label") or "").strip()
            if not text or label_raw not in {"0", "1"}:
                continue
            label = int(label_raw)
            if label == 0:
                rows_0.append((text, label))
            else:
                rows_1.append((text, label))

    random.shuffle(rows_0)
    random.shuffle(rows_1)
    selected = rows_0[:per_class] + rows_1[:per_class]

    out: list[dict[str, Any]] = []
    for i, (text, label) in enumerate(selected, start=1):
        subject, body = text_to_subject_body(text)
        out.append(
            {
                "id": f"REAL-A-{i:04d}",
                "source": "phishing_email.csv",
                "name": "real_mail_a",
                "label": label,
                "input": {
                    "subject": subject,
                    "body_text": body,
                    "sender_domain": "",
                    "institutional": False,
                    "url_malicious": False,
                },
            }
        )
    return out


def load_phishing_email2_csv(path: Path, per_class: int = 120) -> list[dict[str, Any]]:
    rows_safe: list[tuple[str, int]] = []
    rows_phish: list[tuple[str, int]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            text = (row.get("Email Text") or "").strip()
            email_type = (row.get("Email Type") or "").strip().lower()
            if not text:
                continue
            if "safe" in email_type:
                rows_safe.append((text, 0))
            elif "phishing" in email_type:
                rows_phish.append((text, 1))

    random.shuffle(rows_safe)
    random.shuffle(rows_phish)
    selected = rows_safe[:per_class] + rows_phish[:per_class]

    out: list[dict[str, Any]] = []
    for i, (text, label) in enumerate(selected, start=1):
        subject, body = text_to_subject_body(text)
        out.append(
            {
                "id": f"REAL-B-{i:04d}",
                "source": "Phishing_Email.csv",
                "name": "real_mail_b",
                "label": label,
                "input": {
                    "subject": subject,
                    "body_text": body,
                    "sender_domain": "",
                    "institutional": False,
                    "url_malicious": False,
                },
            }
        )
    return out


def build_hard_synthetic_cases() -> list[dict[str, Any]]:
    return [
        {
            "id": "SYN-001",
            "source": "synthetic",
            "name": "url_and_bec_strong",
            "label": 1,
            "input": {
                "subject": "Urgent transfer",
                "body_text": "Process this wire transfer today, keep this confidential, do not discuss with anyone.",
                "sender_domain": "gmail.com",
                "institutional": False,
                "url_malicious": True,
            },
        },
        {
            "id": "SYN-002",
            "source": "synthetic",
            "name": "forwarded_suspicious",
            "label": 1,
            "input": {
                "subject": "Fwd private proposal",
                "body_text": "---------- Forwarded message ---------\nFrom: x <x@temp-mail.xyz>\nSubject: private\nKeep this confidential and process urgently.",
                "sender_domain": "enit.utm.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
        {
            "id": "SYN-003",
            "source": "synthetic",
            "name": "automated_noreply_legit",
            "label": 0,
            "input": {
                "subject": "Automated notice",
                "body_text": "This email was sent automatically. Please do not reply.",
                "sender_domain": "noreply.example.com",
                "institutional": False,
                "url_malicious": False,
            },
        },
        {
            "id": "SYN-004",
            "source": "synthetic",
            "name": "meeting_legit_short",
            "label": 0,
            "input": {
                "subject": "Réunion interne",
                "body_text": "Réunion demain à 10h. Merci pour votre présence.",
                "sender_domain": "enit.utm.tn",
                "institutional": True,
                "url_malicious": False,
            },
        },
    ]


def evaluate() -> dict[str, Any]:
    random.seed(42)
    root = Path(__file__).resolve().parent
    cases = []
    cases += load_phishing_email_csv(root / "phishing_email.csv", per_class=100)
    cases += load_phishing_email2_csv(root / "data" / "raw" / "phishing2" / "Phishing_Email.csv", per_class=100)
    cases += build_hard_synthetic_cases()

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
                "source": case["source"],
                "name": case["name"],
                "true_label": case["label"],
                "pred_label": pred,
                "score_nlp": out.get("score_nlp"),
                "verdict": out.get("verdict"),
                "detail": out.get("detail"),
            }
        )

    m = compute_binary_metrics(y_true, y_pred)
    fp = [r for r in results if r["true_label"] == 0 and r["pred_label"] == 1]
    fn = [r for r in results if r["true_label"] == 1 and r["pred_label"] == 0]

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "num_cases": len(cases),
        "metrics": asdict(m),
        "confusion_matrix": [[m.tn, m.fp], [m.fn, m.tp]],
        "false_positives": fp[:30],
        "false_negatives": fn[:30],
    }


def save_report(data: dict[str, Any]) -> tuple[Path, Path]:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"nlp_ultra_report_{ts}.json"
    md_path = reports_dir / f"nlp_ultra_report_{ts}.md"

    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    m = data["metrics"]
    lines = [
        "# Rapport Ultra NLP/BEC",
        f"Date: {data['generated_at']}",
        f"Cas: {data['num_cases']}",
        f"Matrice [[TN, FP], [FN, TP]]: {data['confusion_matrix']}",
        (
            "Metrics: "
            f"accuracy={m['accuracy']:.3f}, precision={m['precision']:.3f}, "
            f"recall={m['recall']:.3f}, f1={m['f1']:.3f}, "
            f"tp={m['tp']}, tn={m['tn']}, fp={m['fp']}, fn={m['fn']}"
        ),
        "",
        f"False positives (sample): {len(data['false_positives'])}",
        f"False negatives (sample): {len(data['false_negatives'])}",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main() -> None:
    data = evaluate()
    json_path, md_path = save_report(data)
    print("=== NLP ULTRA TEST COMPLETE ===")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print("Confusion matrix:", data["confusion_matrix"])
    print("Metrics:", data["metrics"])
    print("FP sample:", len(data["false_positives"]))
    print("FN sample:", len(data["false_negatives"]))


if __name__ == "__main__":
    main()
