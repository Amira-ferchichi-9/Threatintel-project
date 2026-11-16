import os
from dotenv import load_dotenv
load_dotenv()
import os, base64, re, requests, time, dns.resolver, logging, json
from datetime import datetime
from transformers import pipeline as hf_pipeline
from transformers import logging as transformers_logging
from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# =========================================================
# CONFIGURATION SILENCIEUSE
# =========================================================
transformers_logging.set_verbosity_error()
logging.getLogger("azure").setLevel(logging.ERROR)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# =========================================================
# CONFIGURATION
# =========================================================
VT_API_KEY            = os.getenv("VT_API_KEY")
AZURE_TENANT_ID       = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID       = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET   = os.getenv("AZURE_CLIENT_SECRET") 
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

RESOURCE_GROUP = "PFA_Email_Sandbox_RG"
LOCATION       = "francecentral"
SCOPES         = ['https://www.googleapis.com/auth/gmail.readonly']
MODEL_PATH = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

TRUSTED_DOMAINS = ["google.com", "microsoft.com", "enit.utm.tn",
                   "linkedin.com", "github.com", "instagram.com", "facebook.com",
                   "apple.com", "amazon.com", "pinterest.com", "pdfaid.com",
                   "canva.com", "engage.canva.com", "inspire.pinterest.com",
                "mail.instagram.com", "notifications.instagram.com"]

# =========================================================
# MATRICE DE SCORING — Algorithme de Fusion Formalisé
# =========================================================
#
#  COMPOSANTE                   POIDS    DECLENCHEUR
#  ──────────────────────────────────────────────────────
#  IA BERT-Phishing              +50     confiance > 0.85
#  IA BERT-Phishing              +30     0.60 < confiance <= 0.85
#  SPF/DMARC echoue              +25     aucun enregistrement valide
#  VirusTotal malveillant        +35     >= 1 moteur positif
#  VirusTotal suspect            +15     score suspect > 0
#  Domaine de confiance          -30     whitelist + SPF OK
#  ──────────────────────────────────────────────────────
#  SEUILS : 0-39 SAIN | 40-69 SUSPECT | 70-100 MALVEILLANT

def compute_final_score(ia_risk, ia_confidence, spf_failed,
                        vt_malicious, vt_suspicious, is_trusted):
    breakdown = {}
    score = 0

    if ia_confidence > 0.85 and ia_risk > 50:
        breakdown["IA (haute confiance)"] = 50;  score += 50
    elif ia_confidence > 0.60 and ia_risk > 50:
        breakdown["IA (confiance moderee)"] = 30; score += 30
    else:
        breakdown["IA (faible risque)"] = 0

    if spf_failed:
        breakdown["SPF/DMARC echoue"] = 25; score += 25
    else:
        breakdown["SPF/DMARC OK"] = 0

    if vt_malicious:
        breakdown["VirusTotal (malveillant)"] = 35; score += 35
    elif vt_suspicious:
        breakdown["VirusTotal (suspect)"] = 15;     score += 15
    else:
        breakdown["VirusTotal (propre)"] = 0

    if is_trusted and not spf_failed:
        breakdown["Domaine de confiance"] = -30; score -= 30

    final = max(0, min(100, score))
    if final < 40:   verdict, label = "SAIN",        "AUTORISE"
    elif final < 70: verdict, label = "SUSPECT",     "QUARANTAINE"
    else:            verdict, label = "MALVEILLANT", "BLOQUE"

    breakdown["SCORE FINAL"] = final
    return {"score": final, "verdict": verdict, "label": label, "breakdown": breakdown}

# =========================================================
# 1. MODULE IA
# =========================================================
print("\n[IA] Chargement du modele BERT-Phishing depuis le dossier local...")
classifier = hf_pipeline("text-classification", model=MODEL_PATH, truncation=True)
print("[IA] Modele charge.")

def ai_deep_analysis(text):
    if not text or len(text.strip()) < 10:
        return 0.0, 0.0, "Texte insuffisant"
    prediction = classifier(text[:512])[0]
    label, confidence = prediction['label'], prediction['score']
    is_phishing = label.lower() in ("phishing", "phishing_email", "label_1", "spam")
    risk_pct = confidence * 100 if is_phishing else (1 - confidence) * 100
    return risk_pct, confidence, f"BERT -> {label} (confiance {confidence:.2%})"

# =========================================================
# 2. MODULE DNS
# =========================================================
def check_spf_dmarc(domain):
    if not domain: return True, "Domaine absent"
    try:
        records = dns.resolver.resolve(domain, 'TXT')
        txt_all = " ".join(str(r) for r in records).lower()
        has_spf = "v=spf1" in txt_all
        has_dmarc = False
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            has_dmarc = any("v=dmarc1" in str(r).lower() for r in dmarc)
        except: pass
        if has_spf and has_dmarc: return False, "SPF OK + DMARC OK"
        elif has_spf:             return False, "SPF OK / DMARC absent"
        else:                     return True,  "SPF ECHEC / DMARC absent"
    except Exception as e:
        return True, f"DNS echoue : {e}"

# =========================================================
# 3. MODULE VIRUSTOTAL
# =========================================================
def scan_urls_virustotal(text):
    if not VT_API_KEY:
        return False, False, [{"url": "N/A", "status": "Cle VT non configuree", "malicious": 0, "suspicious": 0}]
    urls = re.findall(r'https?://[^\s<>"]+', text)
    if not urls:
        return False, False, [{"url": "Aucune URL", "status": "N/A", "malicious": 0, "suspicious": 0}]
    results, malicious, suspicious = [], False, False
    for url in urls[:5]:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}",
                             headers={"x-apikey": VT_API_KEY}, timeout=10)
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
                if mal > 0: malicious  = True
                if sus > 0: suspicious = True
                status = "MALVEILLANT" if mal > 0 else ("SUSPECT" if sus > 0 else "PROPRE")
                results.append({"url": url[:60], "status": status, "malicious": mal, "suspicious": sus})
            else:
                results.append({"url": url[:60], "status": "Non trouve", "malicious": 0, "suspicious": 0})
        except Exception as e:
            results.append({"url": url[:60], "status": f"Erreur: {e}", "malicious": 0, "suspicious": 0})
    return malicious, suspicious, results

# =========================================================
# 4. MODULE AZURE SANDBOX
# =========================================================
def manage_azure_sandbox(action):
    if not all([AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_SUBSCRIPTION_ID]):
        return "Sandbox non configuree"
    try:
        creds  = ClientSecretCredential(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
        client = ResourceManagementClient(creds, AZURE_SUBSCRIPTION_ID)
        if action == "CREATE":
            print("   [AZURE] Creation sandbox...")
            client.resource_groups.create_or_update(RESOURCE_GROUP, {"location": LOCATION})
            print(f"   [AZURE] Sandbox active dans {LOCATION}.")
            return f"Sandbox creee — {LOCATION}"
        elif action == "DELETE":
            print("   [AZURE] Destruction (Zero Persistence).")
            client.resource_groups.begin_delete(RESOURCE_GROUP)
            return "Sandbox detruite"
    except Exception as e:
        print(f"   [AZURE ERROR] {e}")
        return f"Echec Azure : {e}"

# =========================================================
# 5. RAPPORT HTML
# =========================================================
def generate_html_report(subject, sender, domain, result, 
                         ia_detail, ia_confidence, 
                         dns_detail, spf_failed, 
                         vt_results, sandbox_status):
    
    score = result["score"]
    verdict = result["verdict"]
    ts = datetime.now().strftime("%d/%m/%Y - %H:%M")
    
    # --- CONFIGURATION COULEURS ---
    COLOR_PRIMARY = "#00adb5"   # Ton Teal
    COLOR_BG_DARK = "#28384d"   # Ton Deep Blue
    COLOR_LIGHT   = "#f2f2f2"   # Ton Light Gray
    COLOR_DANGER  = "#ff4d4d"
    
    # Couleur d'état dynamique basée sur le score
    status_color = COLOR_PRIMARY if score < 40 else ("#ffbc11" if score < 70 else COLOR_DANGER)

    # Préparation des données Radar
    ia_val = int(ia_confidence * 100) if ia_confidence > 0.5 else 15
    dns_val = 20 if not spf_failed else 85
    vt_val = 90 if any(u.get("malicious", 0) > 0 for u in vt_results) else (40 if any(u.get("suspicious", 0) > 0 for u in vt_results) else 10)
    sand_val = 80 if "Sandbox active" in sandbox_status else 15
    radar_data = [ia_val, dns_val, vt_val, 30, sand_val]

    # Construction du tableau de décomposition du score
    breakdown_rows = ""
    for key, pts in result["breakdown"].items():
        if key == "SCORE FINAL": continue
        cls = "text-danger" if pts > 0 else ("text-success" if pts < 0 else "")
        sign = "+" if pts > 0 else ""
        breakdown_rows += f"<tr><td style='color:{COLOR_LIGHT}'>{key}</td><td class='{cls} fw-bold'>{sign}{pts}</td></tr>"

    # Construction de la table des URLs (IoC)
    url_rows = ""
    for u in vt_results:
        st = u.get("status", "N/A")
        badge_style = f"background:{COLOR_PRIMARY}22; color:{COLOR_PRIMARY}; border:1px solid {COLOR_PRIMARY}44"
        if "MAL" in st: badge_style = "background:#ff4d4d22; color:#ff4d4d; border:1px solid #ff4d4d44"
        url_rows += f"""
        <tr>
            <td class="text-truncate" style="max-width:450px; font-family:'JetBrains Mono',monospace; font-size:0.8rem; color:{COLOR_LIGHT}">{u['url']}</td>
            <td><span class="badge" style="{badge_style}">{st}</span></td>
            <td class="text-center fw-bold" style="color:{COLOR_LIGHT}">{u.get('malicious', 0)}</td>
        </tr>"""

    html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600;800&family=JetBrains+Mono&display=swap" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ background-color: #1a2634; color: {COLOR_LIGHT}; font-family: 'Montserrat', sans-serif; padding: 50px 0; }}
            .main-card {{ background-color: {COLOR_BG_DARK}; border: 1px solid #3e4f63; border-radius: 20px; padding: 40px; box-shadow: 0 20px 40px rgba(0,0,0,0.3); }}
            .accent-line {{ width: 60px; height: 4px; background: {COLOR_PRIMARY}; border-radius: 2px; margin-bottom: 20px; }}
            .stat-card {{ background: #1a2634; border-radius: 15px; padding: 20px; height: 100%; border: 1px solid #3e4f63; }}
            .section-title {{ font-size: 0.7rem; font-weight: 800; text-transform: uppercase; letter-spacing: 2px; color: {COLOR_PRIMARY}; margin-bottom: 20px; }}
            .verdict-box {{ border: 2px solid {status_color}; border-radius: 12px; padding: 15px 30px; background: {status_color}11; color: {status_color}; font-weight: 800; font-size: 1.4rem; }}
            .score-display {{ font-size: 4rem; font-weight: 800; color: {status_color}; font-family: 'JetBrains Mono'; line-height: 1; }}
            .table {{ --bs-table-bg: transparent; border-color: #3e4f63; vertical-align: middle; }}
            .progress {{ background-color: #1a2634; height: 8px; border-radius: 4px; }}
            .progress-bar {{ background-color: {COLOR_PRIMARY}; }}
            footer {{ text-align: center; margin-top: 50px; font-size: 0.65rem; color: #5c6d82; letter-spacing: 1px; font-family: 'JetBrains Mono'; }}
        </style>
    </head>
    <body>
        <div class="container report-container" style="max-width: 1140px;">
            <div class="main-card">
                <!-- HEADER -->
<div class="d-flex justify-content-between align-items-center mb-5">
    <div>
        <div class="accent-line"></div>
        <h2 class="fw-bold mb-1" style="letter-spacing:-1px; text-transform: uppercase;">Pipeline de <span style="color:{COLOR_PRIMARY}">détection des menaces emails</span></h2>
    </div>
    <div class="verdict-box">{verdict}</div>
</div>

                <!-- TOP ROW: INFO & SCORE -->
                <div class="row g-4 mb-4">
                    <div class="col-md-8">
                        <div class="stat-card">
                            <div class="section-title">Métadonnées de l'Email</div>
                            <h5 class="fw-bold mb-3">{subject}</h5>
                            <div class="row">
                                <div class="col-6">
                                    <small class="text-muted d-block">Source</small>
                                    <span class="small fw-semibold">{sender}</span>
                                </div>
                                <div class="col-6 text-end">
                                    <small class="text-muted d-block">Domaine Analysé</small>
                                    <code style="color:{COLOR_PRIMARY}">{domain}</code>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card text-center d-flex flex-column justify-content-center">
                            <div class="section-title">Indice de Menace</div>
                            <div class="score-display">{score}<span style="font-size:1.5rem">/100</span></div>
                            <p class="small mt-2 mb-0" style="color:{status_color}">Verdict : {result['label']}</p>
                        </div>
                    </div>
                </div>

                <!-- MIDDLE ROW: IA, DNS, SANDBOX -->
                <div class="row g-4 mb-4">
                    <div class="col-md-4">
                        <div class="stat-card">
                            <div class="section-title">Analyse IA (RoBERTa)</div>
                            <p class="small mb-3" style="min-height:40px">{ia_detail}</p>
                            <div class="progress mb-2">
                                <div class="progress-bar" style="width: {ia_confidence*100}%"></div>
                            </div>
                            <div class="d-flex justify-content-between" style="font-size: 0.65rem; font-weight:700">
                                <span class="text-muted">CONFIDENCE</span>
                                <span style="color:{COLOR_PRIMARY}">{ia_confidence*100:.1f}%</span>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card">
                            <div class="section-title">Identité (DNS)</div>
                            <div class="d-flex align-items-center mb-2">
                                <div style="width:12px; height:12px; background:{'#10b981' if not spf_failed else COLOR_DANGER}; border-radius:50%; margin-right:10px"></div>
                                <span class="fw-bold">{'AUTHENTIFIÉ' if not spf_failed else 'SPOOFING DÉTECTÉ'}</span>
                            </div>
                            <p class="text-muted tiny mb-0" style="font-size:0.75rem">{dns_detail}</p>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="stat-card">
                            <div class="section-title">Infrastructure Sandbox</div>
                            <div class="badge mb-2" style="background:{COLOR_PRIMARY}22; color:{COLOR_PRIMARY}; border:1px solid {COLOR_PRIMARY}44; font-size:0.6rem">AZURE ORCHESTRATION</div>
                            <p class="small text-white mb-0">{sandbox_status}</p>
                            <span class="text-muted" style="font-size:0.6rem">Instance éphémère détruite après analyse.</span>
                        </div>
                    </div>
                </div>

                <!-- CHARTS & BREAKDOWN -->
                <div class="row g-4 mb-4">
                    <div class="col-md-6">
                        <div class="stat-card">
                            <div class="section-title">Vecteurs de Risque</div>
                            <canvas id="threatRadar" style="max-height:280px"></canvas>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="stat-card">
                            <div class="section-title">Audit du Scoring</div>
                            <table class="table table-sm small">
                                <thead><tr class="text-muted"><th>Composante du Pipeline</th><th class="text-end">Poids</th></tr></thead>
                                <tbody>{breakdown_rows}</tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- IoC TABLE (URLs) -->
                <div class="stat-card mt-4">
                    <div class="section-title">Indicateurs de Compromission (IoC) - URLs</div>
                    <div class="table-responsive">
                        <table class="table align-middle mt-2">
                            <thead>
                                <tr class="text-muted" style="font-size: 0.7rem; border-bottom: 2px solid #3e4f63;">
                                    <th>URL DÉTECTÉE</th>
                                    <th>VERDICT CLOUD</th>
                                    <th class="text-center">DETECTIONS VT</th>
                                </tr>
                            </thead>
                            <tbody>{url_rows}</tbody>
                        </table>
                    </div>
                </div>

                <footer>
                    GÉNÉRÉ PAR THREATINTEL AGENT v2.4 &middot; ARCHITECTURE MULTI-CLOUD (GCP/AZURE) &middot; CONFIDENTIEL INTERNE
                </footer>
            </div>
        </div>

        <script>
            // Configuration du graphique Radar Pro
            const ctx = document.getElementById('threatRadar').getContext('2d');
            new Chart(ctx, {{
                type: 'radar',
                data: {{
                    labels: ['IA (Sémantique)', 'SPF/DMARC', 'VirusTotal', 'Réputation', 'Sandbox'],
                    datasets: [{{
                        label: 'Vecteur de Menace',
                        data: {radar_data},
                        fill: true,
                        backgroundColor: 'rgba(0, 173, 181, 0.2)',
                        borderColor: '#00adb5',
                        pointBackgroundColor: '#00adb5',
                        pointBorderColor: '#fff',
                        pointHoverBackgroundColor: '#fff',
                        pointHoverBorderColor: '#00adb5',
                        borderWidth: 3
                    }}]
                }},
                options: {{
                    scales: {{
                        r: {{
                            angleLines: {{ color: '#3e4f63' }},
                            grid: {{ color: '#3e4f63' }},
                            pointLabels: {{
                                color: '#f2f2f2',
                                font: {{ family: 'Montserrat', size: 10, weight: '600' }}
                            }},
                            ticks: {{ display: false }},
                            min: 0,
                            max: 100
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    
    # Sauvegarde du fichier
    filename = f"rapport_expert_{int(time.time())}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return filename

# =========================================================
# 6. EXTRACTION CORPS EMAIL
# =========================================================
def extract_body(payload):
    def get_text(parts):
        text = ""
        for part in parts:
            if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                text += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
            elif 'parts' in part:
                text += get_text(part['parts'])
        return text
    if 'parts' in payload:
        return get_text(payload['parts'])
    elif 'body' in payload and 'data' in payload['body']:
        return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
    return ""

# =========================================================
# 7. ANALYSE D'UN EMAIL
# =========================================================
def analyze_email(msg_id, service):
    msg     = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = msg['payload']
    headers = payload['headers']

    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "Sans Sujet")
    sender  = next((h['value'] for h in headers if h['name'] == 'From'),    "Inconnu")

    print(f"\n{'='*65}")
    print(f"  EMAIL  : {subject[:55]}")
    print(f"  SOURCE : {sender[:55]}")
    print(f"{'='*65}")

    body_text = extract_body(payload)

    # A. IA
    ia_risk, ia_conf, ia_detail = ai_deep_analysis(body_text)
    print(f"  [IA]    {ia_detail}")

    # B. DNS
    domain = re.search(r"@([\w.-]+)", sender).group(1) if "@" in sender else ""
    spf_failed, dns_detail = check_spf_dmarc(domain)
    print(f"  [DNS]   {dns_detail}")

    # C. VirusTotal
    vt_malicious, vt_suspicious, vt_results = scan_urls_virustotal(body_text)
    print(f"  [VT]    {len(vt_results)} URL(s) — malicious={vt_malicious}")

    # D. Score
    is_trusted = any(td in sender.lower() for td in TRUSTED_DOMAINS)
    result = compute_final_score(ia_risk, ia_conf, spf_failed,
                                 vt_malicious, vt_suspicious, is_trusted)
    print(f"  [SCORE] {result['score']}/100 -> {result['label']}")
    print(f"  [DETAIL] {result['breakdown']}")

    # E. Sandbox
    has_attachment = any(p.get('filename') for p in payload.get('parts', []))
    sandbox_status = "Non requise"
    if result['score'] >= 40 or has_attachment:
        sandbox_status = manage_azure_sandbox("CREATE") or "Sandbox creee"
        manage_azure_sandbox("DELETE")

    # F. Rapport HTML
    report_file = generate_html_report(
        subject, sender, domain, result,
        ia_detail, ia_conf,
        dns_detail, spf_failed,
        vt_results, sandbox_status
    )
    print(f"  [RAPPORT] {report_file}")
    print(f"{'='*65}")

# =========================================================
# GMAIL AUTH
# =========================================================
def get_gmail_service(session):
    creds      = None
    token_file = f'token_{session}.json'
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow  = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_file, 'w') as f:
            f.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

# =========================================================
# POINT D'ENTREE
# =========================================================
if __name__ == '__main__':
    print("\n" + "#"*65)
    print("  THREATINTEL v2.0 — Detection Automatisee des Menaces Email")
    print("#"*65)
    user = input("\nSession utilisateur (ex: amira, aziz) : ").strip().lower()
    try:
        service  = get_gmail_service(user)
        results  = service.users().messages().list(userId='me', maxResults=5).execute()
        messages = results.get('messages', [])
        if not messages:
            print("Aucun email trouve.")
        else:
            print(f"\n{len(messages)} email(s) a analyser.\n")
            for m in messages:
                analyze_email(m['id'], service)
    except Exception as e:
        print(f"\n[ERREUR] {e}")

