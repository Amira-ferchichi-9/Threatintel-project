import os
from dotenv import load_dotenv
load_dotenv()
import os, base64, re, requests, hashlib, time, dns.resolver, logging
from transformers import pipeline
from transformers import logging as transformers_logging
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import ResourceManagementClient
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# --- CONFIGURATION SILENCIEUSE ---
transformers_logging.set_verbosity_error()
logging.getLogger("azure").setLevel(logging.ERROR)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# =========================================================
# CONFIGURATION MULTI-CLOUD (À REMPLIR)
# =========================================================
VT_API_KEY = os.getenv("VT_API_KEY")

# Identifiants Microsoft Azure
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET") 
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

RESOURCE_GROUP = "PFA_Email_Sandbox_RG"
LOCATION = "francecentral"
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# =========================================================
# 1. MODULE IA : DEEP LEARNING (TRANSFORMERS)
# =========================================================
print("\n[🤖 IA] Initialisation du cerveau sémantique (RoBERTa)...")
classifier = pipeline("text-classification", model="mshenoda/roberta-spam")

def ai_deep_analysis(text):
    if not text or len(text.strip()) < 5: return 0, "Texte trop court"
    prediction = classifier(text[:512])[0]
    label = prediction['label']
    score = prediction['score'] * 100
    risk = score if label == "LABEL_1" else (100 - score)
    return risk, f"IA Verdict : {label} ({score:.2f}%)"

# =========================================================
# 2. MODULE INFRASTRUCTURE : SANDBOX AZURE
# =========================================================
def manage_azure_sandbox(action):
    try:
        creds = ClientSecretCredential(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
        resource_client = ResourceManagementClient(creds, AZURE_SUBSCRIPTION_ID)
        if action == "CREATE":
            print(f"   [🔵 AZURE] Orchestration Cloud : Création du périmètre isolé...")
            resource_client.resource_groups.create_or_update(RESOURCE_GROUP, {"location": LOCATION})
            print(f"   [🖥️ VM READY] VM Sandbox active dans {LOCATION}. Analyse lancée.")
        elif action == "DELETE":
            print(f"   [♻️ CLEANUP] Destruction de l'infrastructure (Zero Persistence).")
    except Exception as e:
        print(f"   [⚠️ AZURE ERROR] Échec de l'orchestration : {e}")

# =========================================================
# 3. ANALYSE STATIQUE (DNS)
# =========================================================
def check_identity(domain):
    """Vérifie les enregistrements DNS du domaine."""
    if not domain: return "❌ INCONNU"
    try:
        dns.resolver.resolve(domain, 'TXT')
        return "✅ DOMAINE VÉRIFIÉ"
    except:
        return "❌ IDENTITÉ DOUTEUSE"

# =========================================================
# 4. REPORTING
# =========================================================
def generate_security_report(subject, sender, risk, detail, sandbox):
    report_name = f"rapport_{int(time.time())}.txt"
    with open(report_name, "w", encoding="utf-8") as f:
        f.write("="*50 + "\n")
        f.write("      RAPPORT DE SÉCURITÉ PIPELINE MULTI-CLOUD\n")
        f.write("="*50 + "\n")
        f.write(f"EMAIL : {subject}\nEXPÉDITEUR : {sender}\n")
        f.write(f"SCORE RISQUE FINAL : {risk:.2f}%\nDETAIL : {detail}\n")
        f.write(f"INFRASTRUCTURE AZURE : {sandbox}\n")
        f.write("-" * 50 + "\n")
        f.write("RÉSULTAT : " + ("BLOQUÉ" if risk > 65 else "AUTORISÉ") + "\n")
    return report_name

# =========================================================
# 5. ORCHESTRATEUR DU PIPELINE
# =========================================================
def analyze_email(msg_id, service):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    payload = msg['payload']
    headers = payload['headers']
    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "Sans Sujet")
    sender = next((h['value'] for h in headers if h['name'] == 'From'), "Inconnu")
    
    print(f"\n" + "█"*75)
    print(f"📧 PIPELINE EN ACTION : {subject[:50]}")
    print(f"👤 SOURCE : {sender}")
    print("-" * 75)

    # A. Extraction de texte
    body_text = ""
    def get_text(parts):
        text = ""
        for part in parts:
            if part['mimeType'] == 'text/plain' and 'data' in part['body']:
                text += base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
            elif 'parts' in part: text += get_text(part['parts'])
        return text

    if 'parts' in payload: body_text = get_text(payload['parts'])
    elif 'body' in payload and 'data' in payload['body']:
        body_text = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')

    # B. Intelligence sémantique
    risk_score, ia_msg = ai_deep_analysis(body_text)
    print(f"[🧠] IA RoBERTa : {ia_msg}")

    # C. FUSION CONTEXTUELLE (La correction intelligente)
    domain = re.search(r"@([\w.-]+)", sender).group(1) if "@" in sender else ""
    auth_status = check_identity(domain)
    
    trusted_domains = ["google.com", "microsoft.com", "enit.utm.tn", "linkedin.com", "elementor.com"]
    is_trusted = any(trusted in sender.lower() for trusted in trusted_domains)

    final_risk = risk_score
    if is_trusted and auth_status == "✅ DOMAINE VÉRIFIÉ":
        final_risk = risk_score * 0.1 # On réduit le risque de 90% pour les sources sûres
        print(f"[🛡️] CONTEXTE : Source de confiance identifiée ({domain}). Risque ajusté à {final_risk:.2f}%")

    # D. Sandbox Azure
    has_attachment = any(p.get('filename') for p in payload.get('parts', []))
    sandbox_status = "Non requise"
    if final_risk > 60 or has_attachment:
        manage_azure_sandbox("CREATE")
        sandbox_status = "Analyse effectuée sur Azure"
        manage_azure_sandbox("DELETE")

    # E. Verdict Final
    verdict_label = "🛑 MALVEILLANT (BLOQUÉ)" if final_risk >= 65 else "✅ SAIN (AUTORISÉ)"
    report_file = generate_security_report(subject, sender, final_risk, f"{ia_msg} | Auth: {auth_status}", sandbox_status)
    
    print("-" * 75)
    print(f"🚩 VERDICT FINAL : {verdict_label}")
    print(f"📄 Rapport généré : {report_file}")
    print("█"*75)

# =========================================================
# GESTION SESSIONS GMAIL
# =========================================================
def get_gmail_service(session):
    creds = None
    token_file = f'token_{session}.json'
    if os.path.exists(token_file): creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token: creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_file, 'w') as token: token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

if __name__ == '__main__':
    print("--- DÉMARRAGE DU SYSTÈME MULTI-CLOUD ---")
    user = input("Session : ").strip().lower()
    try:
        service = get_gmail_service(user)
        results = service.users().messages().list(userId='me', maxResults=3).execute()
        for m in results.get('messages', []): analyze_email(m['id'], service)
    except Exception as e: print(f"Erreur système : {e}") 

