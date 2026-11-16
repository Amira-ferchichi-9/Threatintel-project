from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from agents.agent_auth import run_auth_agent


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
    # Positive class = malicious/suspicious identity.
    return 1 if int(result.get("score_auth", 0)) < 55 else 0


def build_blindspot_cases() -> list[dict[str, Any]]:
    return [
        # 1) Exotic deceptive TLD / long deceptive hostnames
        {
            "id": "B-EXO-001",
            "angle": "exotic_tld_deceptive",
            "name": "Brand in long deceptive domain",
            "label": 1,
            "input": {
                "sender": '"Acme Billing" <notify@acme-corp.com.phish.xyz>',
                "return_path": "<bounce@mailer.phish.xyz>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com.phish.xyz; dkim=pass header.i=@acme-corp.com.phish.xyz; dmarc=pass (p=none)",
            },
        },
        {
            "id": "B-EXO-002",
            "angle": "exotic_tld_deceptive",
            "name": "Corporate lookalike on deceptive TLD",
            "label": 1,
            "input": {
                "sender": '"HR Team" <hr@acme-corp.secure-mail.click>',
                "return_path": "<hr@acme-corp.secure-mail.click>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.secure-mail.click; dkim=pass header.i=@acme-corp.secure-mail.click; dmarc=pass (p=none)",
            },
        },

        # 2) Arabic / mixed RTL display names (Tunisian context)
        {
            "id": "B-RTL-001",
            "angle": "arabic_rtl_display_name",
            "name": "Arabic executive title + free mail",
            "label": 1,
            "input": {
                "sender": '"المدير المالي" <ceo.request@gmail.com>',
                "return_path": "<ceo.request@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "B-RTL-002",
            "angle": "arabic_rtl_display_name",
            "name": "Mixed RTL/LTR executive spoof",
            "label": 1,
            "input": {
                "sender": '"مدير CEO" <alert@outlook.com>',
                "return_path": "<alert@outlook.com>",
                "authentication_results": "spf=pass smtp.mailfrom=outlook.com; dkim=pass header.i=@outlook.com; dmarc=pass (p=none)",
            },
        },

        # 3) Spoofing with no display name
        {
            "id": "B-NODISP-001",
            "angle": "no_display_name_spoof",
            "name": "No display name, free domain ceo alias",
            "label": 1,
            "input": {
                "sender": "<ceo.request@gmail.com>",
                "return_path": "<ceo.request@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "B-NODISP-002",
            "angle": "no_display_name_spoof",
            "name": "No display, executive keyword in local-part",
            "label": 1,
            "input": {
                "sender": "<chief.financial.office@gmail.com>",
                "return_path": "<chief.financial.office@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },

        # 4) SPF/DKIM pass via potentially compromised legitimate relay
        {
            "id": "B-REL-001",
            "angle": "compromised_legit_relay",
            "name": "Legit corporate domain with all pass (possible account takeover)",
            "label": 1,
            "input": {
                "sender": '"Finance Director" <finance.director@acme-corp.com>',
                "return_path": "<finance.director@acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=reject)",
            },
        },
        {
            "id": "B-REL-002",
            "angle": "compromised_legit_relay",
            "name": "Compromised shared provider scenario (all pass)",
            "label": 1,
            "input": {
                "sender": '"Operations" <ops@trusted-supplier.com>',
                "return_path": "<ops@trusted-supplier.com>",
                "authentication_results": "spf=pass smtp.mailfrom=mailer.trusted-supplier.com; dkim=pass header.i=@trusted-supplier.com; dmarc=pass (p=quarantine)",
            },
        },

        # 5) Subtle multi-signal combinations
        {
            "id": "B-MULTI-001",
            "angle": "subtle_multi_signal_combo",
            "name": "Cousin token + bestguesspass + return-path mismatch",
            "label": 1,
            "input": {
                "sender": '"PayPal Billing" <notice@secure-paypa1-login.com>',
                "return_path": "<bounce@alerts-gateway.net>",
                "authentication_results": "spf=pass smtp.mailfrom=secure-paypa1-login.com; dkim=pass header.i=@secure-paypa1-login.com; dmarc=bestguesspass (p=none)",
            },
        },
        {
            "id": "B-MULTI-002",
            "angle": "subtle_multi_signal_combo",
            "name": "No display + deceptive TLD + bestguesspass",
            "label": 1,
            "input": {
                "sender": "<alerts@acme-corp.com.audit.security.xyz>",
                "return_path": "<alerts@acme-corp.com.audit.security.xyz>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com.audit.security.xyz; dkim=pass header.i=@acme-corp.com.audit.security.xyz; dmarc=bestguesspass (p=none)",
            },
        },

        # Controls to ensure precision remains sane in this focused campaign
        {
            "id": "B-CTRL-001",
            "angle": "control_benign",
            "name": "Legit corporate strict auth",
            "label": 0,
            "input": {
                "sender": '"Internal IT" <it@acme-corp.com>',
                "return_path": "<it@acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=reject)",
            },
        },
        {
            "id": "B-CTRL-002",
            "angle": "control_benign",
            "name": "Legit free-mail personal sender",
            "label": 0,
            "input": {
                "sender": '"John Doe" <john.doe@gmail.com>',
                "return_path": "<john.doe@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
    ]


def evaluate_blindspots() -> dict[str, Any]:
    cases = build_blindspot_cases()
    y_true: list[int] = []
    y_pred: list[int] = []
    all_results: list[dict[str, Any]] = []

    for case in cases:
        out = run_auth_agent(**case["input"])
        pred = pred_label(out)
        y_true.append(case["label"])
        y_pred.append(pred)

        all_results.append(
            {
                "id": case["id"],
                "angle": case["angle"],
                "name": case["name"],
                "true_label": case["label"],
                "pred_label": pred,
                "score_auth": out.get("score_auth"),
                "verdict": out.get("verdict"),
                "detail": out.get("detail"),
                "signals": {
                    "exec_spoofing": out.get("exec_spoofing"),
                    "reply_to_mismatch": out.get("reply_to_mismatch"),
                    "return_path_mismatch": out.get("return_path_mismatch"),
                    "homograph": out.get("homograph"),
                    "cousin_domain": out.get("cousin_domain"),
                },
            }
        )

    metrics = compute_binary_metrics(y_true, y_pred)
    cm = [[metrics.tn, metrics.fp], [metrics.fn, metrics.tp]]

    false_negatives = [r for r in all_results if r["true_label"] == 1 and r["pred_label"] == 0]
    false_positives = [r for r in all_results if r["true_label"] == 0 and r["pred_label"] == 1]

    by_angle: dict[str, dict[str, Any]] = {}
    for r in all_results:
        angle = r["angle"]
        s = by_angle.setdefault(angle, {"total": 0, "fn": 0, "fp": 0, "malicious": 0, "benign": 0})
        s["total"] += 1
        if r["true_label"] == 1:
            s["malicious"] += 1
            if r["pred_label"] == 0:
                s["fn"] += 1
        else:
            s["benign"] += 1
            if r["pred_label"] == 1:
                s["fp"] += 1

    vulnerabilities = []
    for fn in false_negatives:
        vulnerabilities.append(
            {
                "id": fn["id"],
                "angle": fn["angle"],
                "risk": "high",
                "issue": "Blindspot bypass (malicious sample not blocked)",
                "evidence": {
                    "score_auth": fn["score_auth"],
                    "verdict": fn["verdict"],
                    "detail": fn["detail"],
                    "signals": fn["signals"],
                },
            }
        )

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "agent": "agent_auth",
        "campaign": "blindspots_targeted",
        "decision_rule": "pred=1 if score_auth < 55 else 0",
        "num_cases": len(cases),
        "num_malicious": sum(1 for c in cases if c["label"] == 1),
        "num_benign": sum(1 for c in cases if c["label"] == 0),
        "metrics": asdict(metrics),
        "confusion_matrix": {
            "labels": ["benign(0)", "malicious(1)"],
            "matrix": cm,
        },
        "by_angle": by_angle,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "vulnerabilities": vulnerabilities,
        "all_results": all_results,
    }


def save_report(data: dict[str, Any]) -> tuple[Path, Path]:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"auth_blindspots_report_{ts}.json"
    md_path = reports_dir / f"auth_blindspots_report_{ts}.md"

    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    m = data["metrics"]
    cm = data["confusion_matrix"]["matrix"]
    lines = [
        "# Rapport blindspots auth",
        "",
        f"Date: {data['generated_at']}",
        f"Cas: {data['num_cases']} (malicious={data['num_malicious']}, benign={data['num_benign']})",
        "",
        "## Performance",
        f"- Matrice [[TN, FP], [FN, TP]]: {cm}",
        (
            "- Metrics: "
            f"accuracy={m['accuracy']:.3f}, precision={m['precision']:.3f}, "
            f"recall={m['recall']:.3f}, f1={m['f1']:.3f}, "
            f"tp={m['tp']}, tn={m['tn']}, fp={m['fp']}, fn={m['fn']}"
        ),
        "",
        "## Resultats par angle mort",
    ]

    for angle, st in sorted(data["by_angle"].items()):
        lines.append(
            f"- {angle}: total={st['total']} malicious={st['malicious']} benign={st['benign']} fn={st['fn']} fp={st['fp']}"
        )

    lines += ["", "## Vulnerabilites detectees"]
    if data["vulnerabilities"]:
        for v in data["vulnerabilities"]:
            lines.append(
                f"- {v['id']} | angle={v['angle']} | risk={v['risk']} | {v['issue']}"
            )
    else:
        lines.append("- Aucune")

    lines += ["", "## False negatives"]
    if data["false_negatives"]:
        for fn in data["false_negatives"]:
            lines.append(
                f"- {fn['id']} | angle={fn['angle']} | score={fn['score_auth']} | {fn['name']} | {fn['detail']}"
            )
    else:
        lines.append("- Aucun")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main() -> None:
    data = evaluate_blindspots()
    json_path, md_path = save_report(data)

    print("=== AUTH BLINDSPOTS TEST COMPLETE ===")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print("Confusion matrix:", data["confusion_matrix"]["matrix"])
    print("Metrics:", data["metrics"])
    print("Vulnerabilities:", len(data["vulnerabilities"]))


if __name__ == "__main__":
    main()
