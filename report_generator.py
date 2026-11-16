# report_generator.py — ThreatIntel v1.0
"""
Génère un rapport JSON structuré et complet pour chaque email analysé.
Inclut : scores par agent, verdicts, vulnérabilités détectées, recommandations.
Intégré dans orchestrator.py à la fin de chaque analyse.
"""

import json
import os
import re
import hashlib
from datetime import datetime, timezone

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Inches, Pt


# ─────────────────────────────────────────────────────────
# EXPLICATIONS DES VULNÉRABILITÉS
# ─────────────────────────────────────────────────────────

def explain_auth_vulnerabilities(auth_result: dict) -> list[dict]:
    """Analyse les résultats AUTH et explique les vulnérabilités trouvées."""
    vulns = []
    score = auth_result.get("score_auth", 0)

    if not auth_result.get("spf"):
        vulns.append({
            "type": "MISSING_SPF",
            "severity": "HIGH",
            "description": "Aucun enregistrement SPF détecté pour ce domaine.",
            "impact": "N'importe quel serveur peut envoyer des emails au nom de ce domaine sans être détecté.",
            "recommendation": "Ajouter un enregistrement TXT SPF dans le DNS : 'v=spf1 include:... -all'"
        })

    if not auth_result.get("dmarc"):
        vulns.append({
            "type": "MISSING_DMARC",
            "severity": "HIGH",
            "description": "Aucune politique DMARC configurée.",
            "impact": "Impossible d'instruire les serveurs de messagerie sur le traitement des emails non authentifiés.",
            "recommendation": "Ajouter '_dmarc.domaine.com TXT v=DMARC1; p=quarantine; rua=mailto:...'"
        })

    if not auth_result.get("dkim"):
        vulns.append({
            "type": "MISSING_DKIM",
            "severity": "MEDIUM",
            "description": "Aucune signature DKIM trouvée sur les sélecteurs connus.",
            "impact": "L'intégrité du contenu de l'email ne peut pas être vérifiée cryptographiquement.",
            "recommendation": "Configurer DKIM sur le serveur d'envoi et publier la clé publique dans le DNS."
        })

    if auth_result.get("spoofing"):
        vulns.append({
            "type": "DISPLAY_NAME_SPOOFING",
            "severity": "CRITICAL",
            "description": f"Usurpation possible détectée : {auth_result.get('detail', '')}",
            "impact": "L'expéditeur affiche un nom de marque connue mais envoie depuis un domaine différent — technique classique d'ingénierie sociale.",
            "recommendation": "Bloquer immédiatement. Vérifier l'adresse email réelle, pas seulement le nom affiché."
        })

    if not auth_result.get("resolvable"):
        vulns.append({
            "type": "UNRESOLVABLE_DOMAIN",
            "severity": "CRITICAL",
            "description": "Le domaine expéditeur ne peut pas être résolu via DNS.",
            "impact": "Domaine fantôme ou temporaire — caractéristique des campagnes de phishing jetables.",
            "recommendation": "Rejeter immédiatement tout email provenant d'un domaine non résolvable."
        })

    if score < 35 and not vulns:
        vulns.append({
            "type": "WEAK_IDENTITY",
            "severity": "MEDIUM",
            "description": f"Score d'authentification faible ({score}/100) sans vulnérabilité spécifique identifiée.",
            "impact": "L'identité de l'expéditeur n'est pas suffisamment vérifiable.",
            "recommendation": "Traiter avec prudence. Demander confirmation par un canal alternatif."
        })

    return vulns


def explain_url_vulnerabilities(url_result: dict) -> list[dict]:
    """Analyse les résultats URL et explique les vulnérabilités trouvées."""
    vulns = []
    urls = url_result.get("urls", [])

    for url_entry in urls:
        score = url_entry.get("score", 0)
        url   = url_entry.get("url", "")
        detail = url_entry.get("detail", "")

        if score >= 85:
            vulns.append({
                "type": "MALICIOUS_URL",
                "severity": "CRITICAL",
                "url": url,
                "description": f"URL confirmée malveillante par base de données de menaces : {detail}",
                "impact": "Lien vers un site de malware, phishing ou commande C2. Cliquer = compromission quasi-certaine.",
                "recommendation": "Bloquer l'email. Signaler l'URL à URLhaus/PhishTank. Ne jamais cliquer."
            })
        elif score >= 60:
            vulns.append({
                "type": "SUSPICIOUS_URL",
                "severity": "HIGH",
                "url": url,
                "description": f"URL suspecte détectée : {detail}",
                "impact": "Caractéristiques typiques de phishing (IP directe, TLD gratuit, raccourcisseur d'URL, imitation de marque).",
                "recommendation": "Mettre en quarantaine. Analyser l'URL dans un environnement sandbox avant tout accès."
            })
        elif score >= 35:
            vulns.append({
                "type": "POTENTIALLY_SUSPICIOUS_URL",
                "severity": "MEDIUM",
                "url": url,
                "description": f"URL potentiellement suspecte : {detail}",
                "impact": "Pourrait être un raccourcisseur légitime ou une URL de tracking marketing — à vérifier.",
                "recommendation": "Vérifier la destination réelle avant de cliquer. Utiliser un expandeur d'URL."
            })

    if not urls and url_result.get("urls_found", 0) == 0:
        pass  # Pas d'URL = pas de vulnérabilité URL

    return vulns


def explain_nlp_vulnerabilities(nlp_result: dict) -> list[dict]:
    """Analyse les résultats NLP/BEC et explique les vulnérabilités trouvées."""
    vulns = []

    score_roberta    = nlp_result.get("score_roberta", 0)
    score_distilbert = nlp_result.get("score_distilbert", 0)
    score_bec        = nlp_result.get("score_bec", 0)
    detail           = nlp_result.get("detail", "")

    if score_bec >= 35:
        # Extraire les patterns BEC du détail
        bec_match = re.search(r'BEC HIGH=(\[.*?\])', detail)
        patterns  = bec_match.group(1) if bec_match else "patterns critiques"
        vulns.append({
            "type": "BEC_ATTACK",
            "severity": "CRITICAL",
            "description": f"Patterns BEC (Business Email Compromise) détectés : {patterns}",
            "impact": "Tentative d'arnaque au président, virement frauduleux, ou demande de cartes cadeaux. Perte financière directe possible.",
            "recommendation": "Ne jamais effectuer de virement sur instruction email seule. Vérifier par téléphone au numéro officiel."
        })

    if score_distilbert >= 70:
        vulns.append({
            "type": "PHISHING_CONTENT",
            "severity": "HIGH",
            "description": f"Contenu phishing détecté par DistilBERT (score={score_distilbert}/100).",
            "impact": "Le contenu de l'email vise à voler des identifiants ou données personnelles.",
            "recommendation": "Ne jamais cliquer sur les liens ni fournir d'informations. Signaler à l'équipe sécurité."
        })

    if score_roberta >= 70 and score_bec < 35:
        vulns.append({
            "type": "SPAM_CONTENT",
            "severity": "MEDIUM",
            "description": f"Contenu spam détecté par RoBERTa (score={score_roberta}/100).",
            "impact": "Email non sollicité pouvant contenir des arnaques ou publicités trompeuses.",
            "recommendation": "Marquer comme spam. Vérifier l'expéditeur avant toute interaction."
        })

    return vulns


def explain_sandbox_vulnerabilities(sandbox_result: dict) -> list[dict]:
    """Analyse les résultats Sandbox et explique les vulnérabilités trouvées."""
    vulns = []

    if not sandbox_result.get("triggered"):
        return vulns

    threats = sandbox_result.get("threats", [])
    score   = sandbox_result.get("score_sandbox", 0)

    THREAT_EXPLANATIONS = {
        "Macros VBA":        ("MALICIOUS_MACRO",    "CRITICAL", "Macros VBA détectées dans le document Office.", "Les macros peuvent exécuter du code arbitraire au niveau système dès l'ouverture du fichier.", "Ne jamais activer les macros. Ouvrir dans un viewer en ligne (Google Docs)."),
        "JavaScript":        ("JS_IN_PDF",          "CRITICAL", "JavaScript embarqué dans un PDF.", "Peut exploiter des vulnérabilités du lecteur PDF pour exécuter du code malveillant.", "Ouvrir uniquement dans un lecteur PDF à jour avec JavaScript désactivé."),
        "PowerShell":        ("POWERSHELL_INJECTION","CRITICAL", "Commandes PowerShell détectées dans le document.", "Technique d'exécution de code malveillant typique des ransomwares et backdoors.", "Bloquer immédiatement. Analyser le poste source pour compromission."),
        "ZIP bomb":          ("ZIP_BOMB",           "HIGH",     "Archive ZIP bomb détectée.", "Conçue pour épuiser les ressources système (CPU/RAM/disque) lors de la décompression.", "Supprimer sans ouvrir. Bloquer l'expéditeur."),
        "Exécutables":       ("HIDDEN_EXECUTABLE",  "CRITICAL", "Fichiers exécutables cachés dans l'archive.", "Technique de distribution de malware dissimulé dans des archives apparemment innocentes.", "Ne jamais extraire. Supprimer et signaler."),
        "DDE":               ("DDE_INJECTION",      "HIGH",     "Injection DDE (Dynamic Data Exchange) détectée.", "Permet l'exécution de commandes système sans macros, bypasse certains antivirus.", "Bloquer. Ouvrir uniquement dans un environnement isolé."),
        "Liens externes":    ("EXTERNAL_LINKS",     "MEDIUM",   "Liens externes embarqués dans le document.", "Peut déclencher des requêtes réseau automatiques révélant l'IP ou téléchargeant du contenu malveillant.", "Ouvrir en mode déconnecté ou dans un viewer en ligne."),
    }

    for threat in threats:
        matched = False
        for keyword, (vuln_type, severity, desc, impact, rec) in THREAT_EXPLANATIONS.items():
            if keyword.lower() in threat.lower():
                vulns.append({
                    "type": vuln_type,
                    "severity": severity,
                    "description": desc,
                    "raw_threat": threat,
                    "impact": impact,
                    "recommendation": rec
                })
                matched = True
                break
        if not matched and score >= 40:
            vulns.append({
                "type": "SUSPICIOUS_ATTACHMENT",
                "severity": "MEDIUM",
                "description": f"Comportement suspect détecté dans la pièce jointe : {threat}",
                "raw_threat": threat,
                "impact": "Comportement anormal pouvant indiquer une menace non répertoriée.",
                "recommendation": "Analyser manuellement dans un environnement isolé avant tout accès."
            })

    return vulns


# ─────────────────────────────────────────────────────────
# RÉSUMÉ EXÉCUTIF
# ─────────────────────────────────────────────────────────

def generate_executive_summary(scoring: dict, all_vulns: list[dict]) -> dict:
    """Génère un résumé exécutif lisible de l'analyse."""
    action    = scoring.get("action", "UNKNOWN")
    verdict   = scoring.get("verdict", "")
    score     = scoring.get("score_final", 0)
    hard_rule = scoring.get("hard_rule")

    critical_count = sum(1 for v in all_vulns if v.get("severity") == "CRITICAL")
    high_count     = sum(1 for v in all_vulns if v.get("severity") == "HIGH")
    medium_count   = sum(1 for v in all_vulns if v.get("severity") == "MEDIUM")

    risk_level = (
        "CRITIQUE" if critical_count > 0 else
        "ÉLEVÉ"    if high_count > 0     else
        "MODÉRÉ"   if medium_count > 0   else
        "FAIBLE"
    )

    action_fr = {
        "BLOCK":      "Bloquer — Email rejeté, ne jamais délivrer",
        "QUARANTINE": "Quarantaine — Email isolé en attente d'examen manuel",
        "DELIVER":    "Délivrer — Email considéré comme sain",
    }.get(action, action)

    top_threats = [v["type"] for v in all_vulns if v.get("severity") == "CRITICAL"][:3]

    return {
        "risk_level":        risk_level,
        "action_taken":      action,
        "action_description": action_fr,
        "final_score":       score,
        "verdict":           verdict,
        "decision_basis":    hard_rule if hard_rule else "Random Forest (ML)",
        "vulnerabilities_count": {
            "critical": critical_count,
            "high":     high_count,
            "medium":   medium_count,
            "total":    len(all_vulns)
        },
        "top_threats": top_threats if top_threats else ["Aucune menace critique"],
    }


def _add_section_table(doc: Document, title: str, rows: list[tuple[str, str]]) -> None:
    doc.add_paragraph(title, style="Heading 2")
    table = doc.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    headers = table.rows[0].cells
    headers[0].text = "Champ"
    headers[1].text = "Valeur"
    for left, right in rows:
        cells = table.add_row().cells
        cells[0].text = str(left)
        cells[1].text = str(right)


def _safe_pct(value: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{(value / total) * 100:.1f}%"


def _build_stats_images(report: dict, output_docx_path: str) -> dict[str, str]:
    vulnerabilities = report.get("vulnerabilities_summary", {})
    by_severity = vulnerabilities.get("by_severity", {})
    critical = len(by_severity.get("CRITICAL", []))
    high = len(by_severity.get("HIGH", []))
    medium = len(by_severity.get("MEDIUM", []))

    scoring_agent = report.get("agents_analysis", {}).get("scoring_agent", {})
    input_scores = scoring_agent.get("input_scores", {})

    auth_score = int(input_scores.get("auth", 0))
    url_score = int(input_scores.get("url", 0))
    nlp_score = int(input_scores.get("nlp", 0))
    sandbox_score = int(input_scores.get("sandbox", 0))
    final_score = int(scoring_agent.get("score_final", 0))

    output_dir = os.path.dirname(output_docx_path) or "."
    base_name = os.path.splitext(os.path.basename(output_docx_path))[0]
    severity_chart_path = os.path.join(output_dir, f"{base_name}_severity.png")
    scores_chart_path = os.path.join(output_dir, f"{base_name}_scores.png")

    labels = ["CRITICAL", "HIGH", "MEDIUM"]
    values = [critical, high, medium]
    colors = ["#d73027", "#fc8d59", "#fee08b"]

    if sum(values) > 0:
        fig = plt.figure(figsize=(5.6, 3.6))
        plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=90, colors=colors)
        plt.title("Répartition des vulnérabilités")
        plt.tight_layout()
        fig.savefig(severity_chart_path, dpi=160)
        plt.close(fig)

    fig = plt.figure(figsize=(7.0, 3.8))
    score_labels = ["Auth", "URL", "NLP", "Sandbox", "Final"]
    score_values = [auth_score, url_score, nlp_score, sandbox_score, final_score]
    bar_colors = ["#4e79a7", "#59a14f", "#f28e2b", "#e15759", "#2f4b7c"]
    plt.bar(score_labels, score_values, color=bar_colors)
    plt.ylim(0, 100)
    plt.ylabel("Score (%)")
    plt.title("Scores des agents et score final")
    plt.tight_layout()
    fig.savefig(scores_chart_path, dpi=160)
    plt.close(fig)

    return {
        "severity_chart": severity_chart_path,
        "scores_chart": scores_chart_path,
    }


def _generate_docx_report(report: dict, filepath: str) -> None:
    doc = Document()

    section = doc.sections[0]
    section.top_margin = Inches(0.7)
    section.bottom_margin = Inches(0.7)
    section.left_margin = Inches(0.8)
    section.right_margin = Inches(0.8)

    normal_style = doc.styles["Normal"]
    normal_style.font.name = "Calibri"
    normal_style.font.size = Pt(10.5)

    title = doc.add_paragraph()
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title_run = title.add_run("Rapport d'analyse email - ThreatIntel")
    title_run.bold = True
    title_run.font.size = Pt(18)

    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    subtitle_run = subtitle.add_run("Synthèse automatique après analyse multi-agents")
    subtitle_run.italic = True
    subtitle_run.font.size = Pt(11)

    metadata = report.get("report_metadata", {})
    summary = report.get("executive_summary", {})
    email_info = report.get("email_info", {})
    agents = report.get("agents_analysis", {})
    vulnerabilities = report.get("vulnerabilities_summary", {})
    recommendations = report.get("recommendations", [])

    chart_paths = _build_stats_images(report, filepath)

    _add_section_table(doc, "Informations générales", [
        ("Généré le", metadata.get("generated_at", "")),
        ("Système", metadata.get("system", "")),
        ("Version", metadata.get("report_version", "")),
        ("Sujet", email_info.get("subject", "")),
        ("Expéditeur", email_info.get("sender", "")),
        ("Destinataires", email_info.get("to", "")),
        ("Pièces jointes", f"{email_info.get('attachment_count', 0)}"),
        ("Contient une PJ", "Oui" if email_info.get("has_attachments", False) else "Non"),
    ])

    doc.add_paragraph("Email analysé", style="Heading 2")
    doc.add_paragraph(f"Sujet: {email_info.get('subject', '')}")
    doc.add_paragraph(f"From: {email_info.get('sender', '')}")
    doc.add_paragraph(f"To: {email_info.get('to', '')}")
    doc.add_paragraph("Contenu complet du mail:", style="Heading 3")
    full_body = email_info.get("body_full", "")
    doc.add_paragraph(full_body if full_body else "(Corps du mail vide ou non récupérable)")

    attachments = email_info.get("attachments", [])
    doc.add_paragraph("Pièces jointes analysées", style="Heading 2")
    if attachments:
        pj_table = doc.add_table(rows=1, cols=5)
        pj_table.style = "Table Grid"
        pj_table.rows[0].cells[0].text = "Nom"
        pj_table.rows[0].cells[1].text = "Taille (bytes)"
        pj_table.rows[0].cells[2].text = "Type"
        pj_table.rows[0].cells[3].text = "SHA256"
        pj_table.rows[0].cells[4].text = "Fichier annexe"
        for att in attachments:
            row = pj_table.add_row().cells
            row[0].text = str(att.get("name", ""))
            row[1].text = str(att.get("size", 0))
            row[2].text = str(att.get("extension", ""))
            row[3].text = str(att.get("sha256", ""))
            row[4].text = str(att.get("saved_path", ""))
    else:
        doc.add_paragraph("Aucune pièce jointe dans ce mail.")

    _add_section_table(doc, "Résumé exécutif", [
        ("Niveau de risque", summary.get("risk_level", "")),
        ("Action", summary.get("action_description", "")),
        ("Score final", f"{summary.get('final_score', 0)}/100"),
        ("Verdict", summary.get("verdict", "")),
        ("Base de décision", summary.get("decision_basis", "")),
        ("Menaces critiques", ", ".join(summary.get("top_threats", []))),
    ])

    doc.add_paragraph("Statistiques et pourcentages", style="Heading 2")
    vuln_counts = vulnerabilities.get("by_severity", {})
    critical_count = len(vuln_counts.get("CRITICAL", []))
    high_count = len(vuln_counts.get("HIGH", []))
    medium_count = len(vuln_counts.get("MEDIUM", []))
    total_vulns = int(vulnerabilities.get("total", 0))

    stats_table = doc.add_table(rows=1, cols=3)
    stats_table.style = "Table Grid"
    stats_table.rows[0].cells[0].text = "Sévérité"
    stats_table.rows[0].cells[1].text = "Nombre"
    stats_table.rows[0].cells[2].text = "Pourcentage"
    for label, count in [
        ("CRITICAL", critical_count),
        ("HIGH", high_count),
        ("MEDIUM", medium_count),
    ]:
        row = stats_table.add_row().cells
        row[0].text = label
        row[1].text = str(count)
        row[2].text = _safe_pct(count, total_vulns)

    scoring_agent = agents.get("scoring_agent", {})
    input_scores = scoring_agent.get("input_scores", {})
    agent_table = doc.add_table(rows=1, cols=2)
    agent_table.style = "Table Grid"
    agent_table.rows[0].cells[0].text = "Score"
    agent_table.rows[0].cells[1].text = "Pourcentage"
    for label, value in [
        ("Auth", int(input_scores.get("auth", 0))),
        ("URL", int(input_scores.get("url", 0))),
        ("NLP", int(input_scores.get("nlp", 0))),
        ("Sandbox", int(input_scores.get("sandbox", 0))),
        ("Final", int(scoring_agent.get("score_final", 0))),
    ]:
        row = agent_table.add_row().cells
        row[0].text = label
        row[1].text = f"{value}%"

    severity_chart = chart_paths.get("severity_chart")
    if severity_chart and os.path.exists(severity_chart):
        doc.add_paragraph("Graphe 1 - Répartition des vulnérabilités", style="Heading 3")
        doc.add_picture(severity_chart, width=Inches(5.7))

    scores_chart = chart_paths.get("scores_chart")
    if scores_chart and os.path.exists(scores_chart):
        doc.add_paragraph("Graphe 2 - Scores des agents", style="Heading 3")
        doc.add_picture(scores_chart, width=Inches(6.3))

    doc.add_paragraph("Analyse par agent", style="Heading 2")
    for agent_name, data in agents.items():
        agent_title = doc.add_paragraph(style="Heading 3")
        agent_title.add_run(agent_name.replace("_", " ").title())
        table = doc.add_table(rows=1, cols=2)
        table.style = "Table Grid"
        table.rows[0].cells[0].text = "Champ"
        table.rows[0].cells[1].text = "Valeur"

        rows = [
            ("Version", data.get("version", "")),
            ("Score", data.get("score", data.get("score_final", 0))),
            ("Verdict", data.get("verdict", "")),
        ]
        if "action" in data:
            rows.append(("Action", data.get("action", "")))
        if "detail" in data:
            rows.append(("Détail", data.get("detail", "")))
        if "vulnerabilities" in data:
            rows.append(("Vulnérabilités", len(data.get("vulnerabilities", []))))

        for left, right in rows:
            cells = table.add_row().cells
            cells[0].text = str(left)
            cells[1].text = str(right)

    sandbox_data = agents.get("sandbox_agent", {})
    doc.add_paragraph("Comment la sandbox a analysé la pièce jointe", style="Heading 2")
    doc.add_paragraph(
        "1) Déclenchement selon le score provisoire et la présence d'une PJ."
    )
    doc.add_paragraph(
        "2) Analyse statique locale du fichier selon son type (PDF/DOCX/XLSX/ZIP)."
    )
    doc.add_paragraph(
        "3) Tentative d'analyse dynamique en environnement cloud isolé (si disponible)."
    )
    doc.add_paragraph(
        "4) Fusion des menaces détectées et calcul du score sandbox final."
    )

    sandbox_table = doc.add_table(rows=1, cols=2)
    sandbox_table.style = "Table Grid"
    sandbox_table.rows[0].cells[0].text = "Champ"
    sandbox_table.rows[0].cells[1].text = "Valeur"
    for left, right in [
        ("Sandbox déclenchée", sandbox_data.get("triggered", False)),
        ("Fichiers analysés", sandbox_data.get("files_analyzed", 0)),
        ("Score sandbox", f"{sandbox_data.get('score', 0)}/100"),
        ("Verdict sandbox", sandbox_data.get("verdict", "")),
    ]:
        row = sandbox_table.add_row().cells
        row[0].text = str(left)
        row[1].text = str(right)

    file_results = sandbox_data.get("file_results", [])
    if file_results:
        doc.add_paragraph("Résultats détaillés par pièce jointe", style="Heading 3")
        for idx, result in enumerate(file_results, start=1):
            doc.add_paragraph(
                f"Fichier {idx} - Type: {result.get('type', '')} | Risque: {result.get('risk', 0)}/100",
                style="List Bullet"
            )
            for threat in result.get("threats", []):
                doc.add_paragraph(f"- {threat}", style="List Bullet")

    threats_detected = sandbox_data.get("threats_detected", [])
    if threats_detected:
        doc.add_paragraph("Menaces remontées par la sandbox", style="Heading 3")
        for threat in threats_detected:
            doc.add_paragraph(f"- {threat}", style="List Bullet")

    doc.add_paragraph("Synthèse des vulnérabilités", style="Heading 2")
    doc.add_paragraph(f"Total détecté : {vulnerabilities.get('total', 0)}")
    vuln_counts = vulnerabilities.get("by_severity", {})
    for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
        items = vuln_counts.get(severity, [])
        if not items:
            continue
        doc.add_paragraph(f"{severity} ({len(items)})", style="List Bullet")
        for item in items:
            doc.add_paragraph(
                f"- {item.get('type', '')} : {item.get('description', '')}",
                style="List Bullet"
            )

    doc.add_paragraph("Recommandations", style="Heading 2")
    if recommendations:
        for rec in recommendations:
            doc.add_paragraph(
                f"{rec.get('action', '')} : {rec.get('description', '')}",
                style="List Bullet"
            )
    else:
        doc.add_paragraph("Aucune recommandation disponible.")

    doc.add_paragraph("Conclusion", style="Heading 2")
    doc.add_paragraph(
        "Le rapport est généré automatiquement après l'analyse du mail. Il synthétise les scores, le verdict final, les vulnérabilités détectées et les actions recommandées."
    )

    doc.save(filepath)

    for chart_path in chart_paths.values():
        if chart_path and os.path.exists(chart_path):
            try:
                os.remove(chart_path)
            except OSError:
                pass


# ─────────────────────────────────────────────────────────
# GÉNÉRATEUR PRINCIPAL
# ─────────────────────────────────────────────────────────

def generate_report(
    email_context: dict,
    agents_results: dict,
    scoring: dict,
    output_dir: str = "reports"
) -> str:
    """
    Génère un rapport JSON complet pour un email analysé.
    Retourne le chemin du fichier généré.
    """
    os.makedirs(output_dir, exist_ok=True)

    auth_result    = agents_results.get("auth",    {})
    url_result     = agents_results.get("url",     {})
    nlp_result     = agents_results.get("nlp",     {})
    sandbox_result = agents_results.get("sandbox", {})

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:20]
    subject_safe = re.sub(r'[^a-zA-Z0-9]', '_', email_context.get("subject", "unknown"))[:30]
    annex_dir = os.path.join(output_dir, "attachments", f"{timestamp}_{subject_safe}")
    os.makedirs(annex_dir, exist_ok=True)

    serialized_attachments = []
    for idx, att in enumerate(email_context.get("attachments", []), start=1):
        if not isinstance(att, dict):
            continue

        name = att.get("name", f"attachment_{idx}")
        data = att.get("data", b"")
        if not isinstance(data, (bytes, bytearray)):
            data = b""

        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)[:120] or f"attachment_{idx}"
        saved_path = os.path.join(annex_dir, safe_name)

        if data:
            with open(saved_path, "wb") as f:
                f.write(data)
            sha256 = hashlib.sha256(data).hexdigest()
            size = len(data)
        else:
            saved_path = ""
            sha256 = ""
            size = int(att.get("size", 0))

        serialized_attachments.append({
            "name": name,
            "size": size,
            "extension": os.path.splitext(name)[1].lower(),
            "sha256": sha256,
            "saved_path": saved_path,
        })

    # ── Collecter toutes les vulnérabilités ───────────────
    auth_vulns    = explain_auth_vulnerabilities(auth_result)
    url_vulns     = explain_url_vulnerabilities(url_result)
    nlp_vulns     = explain_nlp_vulnerabilities(nlp_result)
    sandbox_vulns = explain_sandbox_vulnerabilities(sandbox_result)
    all_vulns     = auth_vulns + url_vulns + nlp_vulns + sandbox_vulns

    # ── Résumé exécutif ───────────────────────────────────
    summary = generate_executive_summary(scoring, all_vulns)

    # ── Construire le rapport complet ─────────────────────
    report = {
        "report_metadata": {
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "system":         "ThreatIntel Multi-Agent v2.2",
            "report_version": "1.0",
        },

        "email_info": {
            "subject":       email_context.get("subject", ""),
            "sender":        email_context.get("sender",  ""),
            "to":            email_context.get("to_header", ""),
            "has_attachments": len(serialized_attachments) > 0,
            "attachment_count": len(serialized_attachments),
            "attachments": serialized_attachments,
            "body_full": email_context.get("body_text", ""),
            "body_preview":  email_context.get("body_text", "")[:300] + "..." if len(email_context.get("body_text", "")) > 300 else email_context.get("body_text", ""),
        },

        "executive_summary": summary,

        "agents_analysis": {

            "auth_agent": {
                "version":    "v2.2",
                "score":      auth_result.get("score_auth", 0),
                "verdict":    auth_result.get("verdict", ""),
                "domain":     auth_result.get("domain", ""),
                "checks": {
                    "spf":        auth_result.get("spf", False),
                    "dmarc":      auth_result.get("dmarc", False),
                    "dkim":       auth_result.get("dkim", False),
                    "resolvable": auth_result.get("resolvable", False),
                    "spoofing_detected": auth_result.get("spoofing", False),
                },
                "bonuses": {
                    "institutional": auth_result.get("institutional_bonus", 0),
                    "organizational": auth_result.get("organizational_bonus", 0),
                    "distribution_list": auth_result.get("distribution_bonus", 0),
                    "dns_infrastructure": auth_result.get("dns_score", 0),
                },
                "detail":        auth_result.get("detail", ""),
                "vulnerabilities": auth_vulns,
            },

            "url_agent": {
                "version":    "v2.4",
                "score":      url_result.get("score_url", 0),
                "verdict":    url_result.get("verdict", ""),
                "urls_found": url_result.get("urls_found", 0),
                "urls_analyzed": url_result.get("urls", []),
                "tranco_hits": url_result.get("tranco_hits", 0),
                "vulnerabilities": url_vulns,
            },

            "nlp_bec_agent": {
                "version":    "v2.2",
                "score":      nlp_result.get("score_nlp", 0),
                "verdict":    nlp_result.get("verdict", ""),
                "sub_scores": {
                    "roberta_spam":      nlp_result.get("score_roberta", 0),
                    "distilbert_phishing": nlp_result.get("score_distilbert", 0),
                    "bec_patterns":      nlp_result.get("score_bec", 0),
                },
                "context": {
                    "is_legitimate_context": nlp_result.get("is_legit_context", False),
                    "institutional_domain":  nlp_result.get("institutional", False),
                    "legit_confidence":      nlp_result.get("legit_confidence", 0),
                    "legit_signals":         nlp_result.get("legit_signals", []),
                    "weights_used":          nlp_result.get("weights_used", ""),
                },
                "detail":        nlp_result.get("detail", ""),
                "vulnerabilities": nlp_vulns,
            },

            "sandbox_agent": {
                "version":   "v2.1",
                "triggered": sandbox_result.get("triggered", False),
                "score":     sandbox_result.get("score_sandbox", 0),
                "verdict":   sandbox_result.get("verdict", ""),
                "files_analyzed": sandbox_result.get("files_analyzed", 0),
                "threats_detected": sandbox_result.get("threats", []),
                "file_results": sandbox_result.get("results", []),
                "vulnerabilities": sandbox_vulns,
            },

            "scoring_agent": {
                "version":     "v2.0",
                "score_final": scoring.get("score_final", 0),
                "verdict":     scoring.get("verdict", ""),
                "action":      scoring.get("action", ""),
                "hard_rule_applied": scoring.get("hard_rule"),
                "rf_prediction": scoring.get("rf_prediction"),
                "probabilities": scoring.get("probabilites", {}),
                "feature_importances": scoring.get("feature_importances", {}),
                "dominant_factor": scoring.get("facteur_dominant", ""),
                "input_scores": {
                    "auth":    scoring.get("score_auth", 0),
                    "url":     scoring.get("score_url", 0),
                    "nlp":     scoring.get("score_nlp", 0),
                    "sandbox": scoring.get("score_sandbox", 0),
                },
            },
        },

        "vulnerabilities_summary": {
            "total": len(all_vulns),
            "by_severity": {
                "CRITICAL": [v for v in all_vulns if v.get("severity") == "CRITICAL"],
                "HIGH":     [v for v in all_vulns if v.get("severity") == "HIGH"],
                "MEDIUM":   [v for v in all_vulns if v.get("severity") == "MEDIUM"],
            },
            "by_agent": {
                "auth":    auth_vulns,
                "url":     url_vulns,
                "nlp_bec": nlp_vulns,
                "sandbox": sandbox_vulns,
            }
        },

        "recommendations": _generate_recommendations(summary, all_vulns, scoring),
    }

    # ── Sauvegarder ───────────────────────────────────────
    filename_json = f"report_{timestamp}_{subject_safe}.json"
    filepath_json = os.path.join(output_dir, filename_json)
    filename_docx = f"report_{timestamp}_{subject_safe}.docx"
    filepath_docx = os.path.join(output_dir, filename_docx)

    with open(filepath_json, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    _generate_docx_report(report, filepath_docx)

    print(f"\n  [📄 RAPPORT] JSON : {filepath_json}")
    print(f"  [📄 RAPPORT] DOCX : {filepath_docx}")
    return filepath_json


def _generate_recommendations(summary: dict, all_vulns: list, scoring: dict) -> list[dict]:
    """Génère des recommandations priorisées basées sur l'analyse."""
    recs = []
    action = scoring.get("action", "")

    if action == "BLOCK":
        recs.append({
            "priority": 1,
            "action": "BLOQUER",
            "description": "Rejeter cet email immédiatement et ne pas le délivrer.",
            "rationale": summary.get("decision_basis", "Menaces critiques détectées")
        })
        recs.append({
            "priority": 2,
            "action": "SIGNALER",
            "description": "Signaler l'expéditeur et les URLs détectées aux bases de données de menaces (URLhaus, PhishTank, abuse.ch).",
            "rationale": "Contribue à la protection collective contre cette campagne."
        })
        recs.append({
            "priority": 3,
            "action": "INVESTIGUER",
            "description": "Vérifier si d'autres utilisateurs ont reçu le même email. Chercher des indicateurs de compromission (IOC).",
            "rationale": "Les campagnes ciblées touchent souvent plusieurs destinataires simultanément."
        })

    elif action == "QUARANTINE":
        recs.append({
            "priority": 1,
            "action": "ISOLER",
            "description": "Maintenir en quarantaine. Demander une revue manuelle par un analyste sécurité.",
            "rationale": "Score suspect mais pas suffisamment confirmé pour blocage automatique."
        })
        recs.append({
            "priority": 2,
            "action": "VÉRIFIER",
            "description": "Contacter l'expéditeur présumé par un canal alternatif (téléphone) pour confirmer l'authenticité.",
            "rationale": "Élimine les faux positifs sur les emails légitimes suspects."
        })

    elif action == "DELIVER":
        if all_vulns:
            recs.append({
                "priority": 1,
                "action": "SURVEILLER",
                "description": "Email délivré mais des points d'attention mineurs ont été détectés. Rester vigilant.",
                "rationale": f"{len(all_vulns)} point(s) d'attention identifié(s) malgré le verdict sain."
            })
        else:
            recs.append({
                "priority": 1,
                "action": "AUCUNE",
                "description": "Email considéré comme sain. Aucune action requise.",
                "rationale": "Tous les agents confirment l'authenticité et la sécurité du contenu."
            })

    # Recommandations spécifiques aux vulnérabilités critiques
    critical_types = {v["type"] for v in all_vulns if v.get("severity") == "CRITICAL"}

    if "BEC_ATTACK" in critical_types:
        recs.append({
            "priority": 1,
            "action": "FORMATION URGENTE",
            "description": "Former immédiatement les équipes financières sur les attaques BEC. Implémenter une validation multi-personnes pour tout virement.",
            "rationale": "Les attaques BEC causent en moyenne 130,000$ de pertes par incident."
        })

    if "DISPLAY_NAME_SPOOFING" in critical_types:
        recs.append({
            "priority": 2,
            "action": "RÈGLE ANTI-SPOOFING",
            "description": "Configurer des règles de messagerie pour alerter quand le display name contient des marques connues mais le domaine ne correspond pas.",
            "rationale": "Prévention proactive du spoofing de display name."
        })

    return sorted(recs, key=lambda x: x["priority"])


def _find_latest_json_report(reports_dir: str = "reports") -> str | None:
    if not os.path.isdir(reports_dir):
        return None

    json_files = [
        os.path.join(reports_dir, name)
        for name in os.listdir(reports_dir)
        if name.lower().endswith(".json")
    ]
    if not json_files:
        return None

    return max(json_files, key=os.path.getmtime)


def build_docx_from_report_json(json_path: str, docx_path: str | None = None) -> str:
    with open(json_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    if docx_path is None:
        docx_path = os.path.splitext(json_path)[0] + ".docx"

    _generate_docx_report(report, docx_path)
    return docx_path


if __name__ == "__main__":
    import sys

    source_path = sys.argv[1] if len(sys.argv) > 1 else _find_latest_json_report()
    if not source_path:
        print("Aucun rapport JSON trouvé dans reports/. Lance d'abord orchestrator.py pour analyser un email.")
        raise SystemExit(1)

    output_path = build_docx_from_report_json(source_path)
    print(f"DOCX généré : {output_path}")