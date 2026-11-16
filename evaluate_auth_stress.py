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
    # Positive class = malicious/suspicious sender identity.
    return 1 if int(result.get("score_auth", 0)) < 55 else 0


def build_cases() -> list[dict[str, Any]]:
    return [
        {
            "id": "A-B-001",
            "name": "Enterprise strict auth",
            "category": "benign_baseline",
            "label": 0,
            "input": {
                "sender": '"Finance Team" <finance@acme-corp.com>',
                "return_path": "<bounce@acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=reject)",
            },
        },
        {
            "id": "A-B-002",
            "name": "Subdomain aligned",
            "category": "benign_baseline",
            "label": 0,
            "input": {
                "sender": '"IT Alert" <alerts@mail.acme-corp.com>',
                "return_path": "<mailer@mail.acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=mail.acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-B-003",
            "name": "Legit newsletter p=none",
            "category": "benign_baseline",
            "label": 0,
            "input": {
                "sender": '"News" <news@legit-media.com>',
                "return_path": "<news@legit-media.com>",
                "authentication_results": "spf=pass smtp.mailfrom=legit-media.com; dkim=pass header.i=@legit-media.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-B-004",
            "name": "Institutional domain",
            "category": "benign_baseline",
            "label": 0,
            "input": {
                "sender": '"RH" <recrutement@enit.utm.tn>',
                "return_path": "<recrutement@enit.utm.tn>",
                "authentication_results": "spf=pass smtp.mailfrom=enit.utm.tn; dkim=pass header.i=@utm.tn; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-B-005",
            "name": "Softfail but otherwise clean",
            "category": "benign_edge",
            "label": 0,
            "input": {
                "sender": '"Vendor Portal" <no-reply@trusted-portal.com>',
                "return_path": "<mailer@trusted-portal.com>",
                "authentication_results": "spf=softfail smtp.mailfrom=trusted-portal.com; dkim=pass header.i=@trusted-portal.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-B-006",
            "name": "No reply-to return-path but strict pass",
            "category": "benign_edge",
            "label": 0,
            "input": {
                "sender": '"Ops" <ops@microsoft.com>',
                "authentication_results": "spf=pass smtp.mailfrom=microsoft.com; dkim=pass header.i=@microsoft.com; dmarc=pass (p=reject)",
            },
        },
        {
            "id": "A-M-001",
            "name": "Homograph microsoft",
            "category": "homograph",
            "label": 1,
            "input": {
                "sender": '"Support" <help@microsоft.com>',
                "return_path": "<help@microsоft.com>",
                "authentication_results": "spf=pass smtp.mailfrom=microsоft.com; dkim=pass header.i=@microsоft.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-M-002",
            "name": "Cousin domain paypa1",
            "category": "cousin_domain",
            "label": 1,
            "input": {
                "sender": '"PayPal" <security@paypa1.com>',
                "return_path": "<security@paypa1.com>",
                "authentication_results": "spf=pass smtp.mailfrom=paypa1.com; dkim=pass header.i=@paypa1.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-M-003",
            "name": "Executive spoof EN free domain",
            "category": "executive_free_domain",
            "label": 1,
            "input": {
                "sender": '"Chief Financial Officer" <cfo.board@outlook.com>',
                "return_path": "<cfo.board@outlook.com>",
                "authentication_results": "spf=pass smtp.mailfrom=outlook.com; dkim=pass header.i=@outlook.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-M-004",
            "name": "Executive spoof FR accent",
            "category": "executive_free_domain",
            "label": 1,
            "input": {
                "sender": '"Directeur general" <ceo.request@gmail.com>',
                "return_path": "<ceo.request@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-M-005",
            "name": "Reply-to trap",
            "category": "reply_to_trap",
            "label": 1,
            "input": {
                "sender": '"Vendor" <vendor@trusted-supplier.com>',
                "reply_to": "frauddesk@pay-out-now.net",
                "return_path": "<vendor@trusted-supplier.com>",
                "authentication_results": "spf=pass smtp.mailfrom=trusted-supplier.com; dkim=pass header.i=@trusted-supplier.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-M-006",
            "name": "Return-path mismatch",
            "category": "return_path_mismatch",
            "label": 1,
            "input": {
                "sender": '"Accounts" <accounts@acme-corp.com>',
                "return_path": "<billing@payment-update.net>",
                "authentication_results": "spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-M-007",
            "name": "SPF DKIM DMARC fail",
            "category": "auth_fail_combo",
            "label": 1,
            "input": {
                "sender": '"Security" <security@bank-secure-alert.com>',
                "return_path": "<mailer@bank-secure-alert.com>",
                "authentication_results": "spf=fail smtp.mailfrom=bank-secure-alert.com; dkim=fail header.i=@bank-secure-alert.com; dmarc=fail (p=reject)",
            },
        },
        {
            "id": "A-M-008",
            "name": "DKIM misalignment",
            "category": "alignment_attack",
            "label": 1,
            "input": {
                "sender": '"Office365" <noreply@contoso.com>',
                "return_path": "<noreply@contoso.com>",
                "authentication_results": "spf=pass smtp.mailfrom=contoso.com; dkim=pass header.i=@mailer-thirdparty.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-M-009",
            "name": "SPF misalignment",
            "category": "alignment_attack",
            "label": 1,
            "input": {
                "sender": '"Invoice" <invoice@acme-corp.com>',
                "return_path": "<invoice@acme-corp.com>",
                "authentication_results": "spf=pass smtp.mailfrom=mail-relay-untrusted.net; dkim=pass header.i=@acme-corp.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-M-010",
            "name": "No auth + dual mismatch",
            "category": "auth_absent_combo",
            "label": 1,
            "input": {
                "sender": '"Finance" <finance@unknown-payments.net>',
                "reply_to": "secureteam@external-verify.org",
                "return_path": "<bounce@mailer-temp.xyz>",
                "authentication_results": "",
            },
        },
        {
            "id": "A-E-001",
            "name": "Exec obfuscated with digit",
            "category": "evasion_display_obfuscation",
            "label": 1,
            "input": {
                "sender": '"Chief F1nancial Officer" <ceo.request@gmail.com>',
                "return_path": "<ceo.request@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-E-002",
            "name": "Exec abbreviation punctuated",
            "category": "evasion_display_obfuscation",
            "label": 1,
            "input": {
                "sender": '"D.G." <ceo.request@gmail.com>',
                "return_path": "<ceo.request@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-E-003",
            "name": "Punycode brand spoof",
            "category": "evasion_punycode",
            "label": 1,
            "input": {
                "sender": '"Microsoft" <alerts@xn--micrsft-5za.com>',
                "return_path": "<alerts@xn--micrsft-5za.com>",
                "authentication_results": "spf=pass smtp.mailfrom=xn--micrsft-5za.com; dkim=pass header.i=@xn--micrsft-5za.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-E-004",
            "name": "Long cousin root evasion",
            "category": "evasion_cousin_root",
            "label": 1,
            "input": {
                "sender": '"PayPal Billing" <alerts@secure-paypa1-login.com>',
                "return_path": "<alerts@secure-paypa1-login.com>",
                "authentication_results": "spf=pass smtp.mailfrom=secure-paypa1-login.com; dkim=pass header.i=@secure-paypa1-login.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-E-005",
            "name": "Reply-to same domain trap",
            "category": "evasion_replyto_same_domain",
            "label": 1,
            "input": {
                "sender": '"Vendor" <accounts@trusted-supplier.com>',
                "reply_to": "payment-update@trusted-supplier.com",
                "return_path": "<accounts@trusted-supplier.com>",
                "authentication_results": "spf=pass smtp.mailfrom=trusted-supplier.com; dkim=pass header.i=@trusted-supplier.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-E-006",
            "name": "DMARC bestguesspass header",
            "category": "evasion_dmarc_bestguesspass",
            "label": 1,
            "input": {
                "sender": '"Admin" <admin@unknown-alerts.net>',
                "return_path": "<admin@unknown-alerts.net>",
                "authentication_results": "spf=pass smtp.mailfrom=unknown-alerts.net; dkim=pass header.i=@unknown-alerts.net; dmarc=bestguesspass (p=none)",
            },
        },
        {
            "id": "A-E-007",
            "name": "ARC only weak signal",
            "category": "evasion_arc_source",
            "label": 1,
            "input": {
                "sender": '"CEO" <ceo.alert@gmail.com>',
                "return_path": "<ceo.alert@gmail.com>",
                "authentication_results": "",
                "arc_authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-E-008",
            "name": "From parse unusual format",
            "category": "evasion_header_parse",
            "label": 1,
            "input": {
                "sender": "CEO finance@outlook.com",
                "return_path": "<finance@outlook.com>",
                "authentication_results": "spf=pass smtp.mailfrom=outlook.com; dkim=pass header.i=@outlook.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-N-001",
            "name": "Consumer sender no executive",
            "category": "benign_consumer",
            "label": 0,
            "input": {
                "sender": '"John Doe" <john.doe@gmail.com>',
                "return_path": "<john.doe@gmail.com>",
                "authentication_results": "spf=pass smtp.mailfrom=gmail.com; dkim=pass header.i=@gmail.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-N-002",
            "name": "Freelancer from outlook",
            "category": "benign_consumer",
            "label": 0,
            "input": {
                "sender": '"Graphic Designer" <studio@outlook.com>',
                "return_path": "<studio@outlook.com>",
                "authentication_results": "spf=pass smtp.mailfrom=outlook.com; dkim=pass header.i=@outlook.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-N-003",
            "name": "Subdomain marketing sender",
            "category": "benign_marketing",
            "label": 0,
            "input": {
                "sender": '"Campaign" <campaign@news.orange.com>',
                "return_path": "<bounce@news.orange.com>",
                "authentication_results": "spf=pass smtp.mailfrom=news.orange.com; dkim=pass header.i=@orange.com; dmarc=pass (p=none)",
            },
        },
        {
            "id": "A-N-004",
            "name": "Shared infra with aligned dkim",
            "category": "benign_shared_infra",
            "label": 0,
            "input": {
                "sender": '"Billing" <billing@trusted-supplier.com>',
                "reply_to": "support@trusted-supplier.com",
                "return_path": "<mailer@trusted-supplier.com>",
                "authentication_results": "spf=pass smtp.mailfrom=mailer.trusted-supplier.com; dkim=pass header.i=@trusted-supplier.com; dmarc=pass (p=quarantine)",
            },
        },
        {
            "id": "A-N-005",
            "name": "Noisy but legitimate arc",
            "category": "benign_arc",
            "label": 0,
            "input": {
                "sender": '"University IT" <helpdesk@utm.tn>',
                "return_path": "<helpdesk@utm.tn>",
                "authentication_results": "",
                "arc_authentication_results": "spf=pass smtp.mailfrom=utm.tn; dkim=pass header.i=@utm.tn; dmarc=pass (p=quarantine)",
            },
        },
    ]


def evaluate_auth_stress() -> dict[str, Any]:
    cases = build_cases()
    y_true: list[int] = []
    y_pred: list[int] = []
    results: list[dict[str, Any]] = []

    for case in cases:
        out = run_auth_agent(**case["input"])
        pred = pred_label(out)
        y_true.append(case["label"])
        y_pred.append(pred)

        results.append(
            {
                "id": case["id"],
                "name": case["name"],
                "category": case["category"],
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

    m = compute_binary_metrics(y_true, y_pred)
    cm = [[m.tn, m.fp], [m.fn, m.tp]]

    false_negatives = [r for r in results if r["true_label"] == 1 and r["pred_label"] == 0]
    false_positives = [r for r in results if r["true_label"] == 0 and r["pred_label"] == 1]

    cat_stats: dict[str, dict[str, Any]] = {}
    for r in results:
        c = r["category"]
        s = cat_stats.setdefault(c, {"total": 0, "malicious": 0, "benign": 0, "fn": 0, "fp": 0})
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

    if false_negatives:
        for fn in false_negatives:
            vulnerabilities.append(
                {
                    "id": fn["id"],
                    "name": fn["name"],
                    "category": fn["category"],
                    "risk": "high",
                    "issue": "Malicious identity bypassed as benign/partial",
                    "evidence": {
                        "score_auth": fn["score_auth"],
                        "verdict": fn["verdict"],
                        "detail": fn["detail"],
                    },
                }
            )

    for fn in false_negatives:
        signals = fn.get("signals", {})
        if not any(bool(v) for v in signals.values()):
            vulnerabilities.append(
                {
                    "id": fn["id"],
                    "name": fn["name"],
                    "category": fn["category"],
                    "risk": "critical",
                    "issue": "No anomaly signal triggered on malicious sample",
                    "evidence": signals,
                }
            )

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "agent": "agent_auth",
        "decision_rule": "pred=1 if score_auth < 55 else 0",
        "num_cases": len(cases),
        "num_malicious": sum(1 for c in cases if c["label"] == 1),
        "num_benign": sum(1 for c in cases if c["label"] == 0),
        "metrics": asdict(m),
        "confusion_matrix": {
            "labels": ["benign(0)", "malicious(1)"],
            "matrix": cm,
        },
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "category_stats": cat_stats,
        "vulnerabilities": vulnerabilities,
        "all_results": results,
    }


def save_report(data: dict[str, Any]) -> tuple[Path, Path]:
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = reports_dir / f"auth_stress_report_{ts}.json"
    md_path = reports_dir / f"auth_stress_report_{ts}.md"

    json_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    m = data["metrics"]
    cm = data["confusion_matrix"]["matrix"]
    lines = [
        "# Rapport stress test agent_auth",
        "",
        f"Date: {data['generated_at']}",
        f"Cas: {data['num_cases']} (malicious={data['num_malicious']}, benign={data['num_benign']})",
        "",
        "## Performance globale",
        f"- Confusion matrix [[TN, FP], [FN, TP]]: {cm}",
        (
            "- Metrics: "
            f"accuracy={m['accuracy']:.3f}, precision={m['precision']:.3f}, "
            f"recall={m['recall']:.3f}, f1={m['f1']:.3f}, "
            f"tp={m['tp']}, tn={m['tn']}, fp={m['fp']}, fn={m['fn']}"
        ),
        "",
        "## Faiblesses et vulnerabilites detectees",
    ]

    if data["vulnerabilities"]:
        for v in data["vulnerabilities"]:
            lines.append(
                f"- {v['id']} | {v['category']} | risk={v['risk']} | {v['issue']}"
            )
    else:
        lines.append("- Aucune vulnerabilite evidente sur ce lot")

    lines += ["", "## False negatives (attaques ratees)"]
    if data["false_negatives"]:
        for fn in data["false_negatives"]:
            lines.append(
                f"- {fn['id']} | {fn['category']} | score={fn['score_auth']} | {fn['name']} | {fn['detail']}"
            )
    else:
        lines.append("- Aucun")

    lines += ["", "## False positives (legitimes bloques)"]
    if data["false_positives"]:
        for fp in data["false_positives"]:
            lines.append(
                f"- {fp['id']} | {fp['category']} | score={fp['score_auth']} | {fp['name']} | {fp['detail']}"
            )
    else:
        lines.append("- Aucun")

    lines += ["", "## Stats par categorie"]
    for cat, st in sorted(data["category_stats"].items()):
        lines.append(
            f"- {cat}: total={st['total']} malicious={st['malicious']} benign={st['benign']} fn={st['fn']} fp={st['fp']}"
        )

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, md_path


def main() -> None:
    data = evaluate_auth_stress()
    json_path, md_path = save_report(data)

    print("=== AUTH STRESS TEST COMPLETE ===")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print("Confusion matrix:", data["confusion_matrix"]["matrix"])
    print("Metrics:", data["metrics"])
    print("Vulnerabilities:", len(data["vulnerabilities"]))


if __name__ == "__main__":
    main()
