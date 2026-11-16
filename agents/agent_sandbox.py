# agents/agent_sandbox.py — RÉVISÉ v2.3 FINAL
"""
Sandbox v2.3 FINAL :
- FIX v2.1 : sanitize_blob_name défini une seule fois
- FIX v2.1 : parse_vm_result défini avant run_sandbox_agent
- FIX v2.2 : regex JSON greedy + re.DOTALL pour parse_vm_result
- FIX v2.2 : upload échoué → score pénalisé (pas silencieux)
- FIX v2.2 : logs VM vides → vm_ok forcé False
- FIX v2.2 : filtre phishing PDF renforcé (lookahead corrigé)
- FIX v2.2 : timeout ACI augmenté à 240s
- NEW v2.3 : analyze_docx — liens externes repondérés (+45 inconnu / +20 connu)
- NEW v2.3 : analyze_docx — BEC faible +12/mot (était +8)
- NEW v2.3 : analyze_docx — bonus combinaison BEC + lien/contexte +15
- NEW v2.3 : seuil opérationnel recommandé maintenu à 40 (borderline franchissent désormais)
"""
import io
import re
import time
import uuid
import json
import zipfile
import logging
import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerinstance.models import (
    ContainerGroup, Container,
    ResourceRequirements, ResourceRequests,
    OperatingSystemTypes, ContainerGroupRestartPolicy,
    EnvironmentVariable
)
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions
from azure.core.exceptions import AzureError
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)
logging.getLogger("azure").setLevel(logging.ERROR)

load_dotenv()

AZURE_TENANT_ID       = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID       = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET   = os.getenv("AZURE_CLIENT_SECRET")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP        = os.getenv("RESOURCE_GROUP")
LOCATION              = os.getenv("LOCATION", "francecentral")
STORAGE_ACCOUNT_NAME  = os.getenv("STORAGE_ACCOUNT_NAME")
STORAGE_ACCOUNT_KEY   = os.getenv("STORAGE_ACCOUNT_KEY")
CONTAINER_NAME        = os.getenv("SANDBOX_CONTAINER_NAME", "sandbox-files")

ALLOWED_EXTENSIONS = [".pdf", ".docx", ".docm", ".doc", ".xlsx", ".xlsm", ".zip"]
MAX_FILE_SIZE_MB   = 20


# ─────────────────────────────────────────────────────────
# SANITIZE BLOB NAME — UNIQUE DÉFINITION
# ─────────────────────────────────────────────────────────
def sanitize_blob_name(name: str) -> str:
    """
    Remplace caractères spéciaux par '_' pour Azure Blob.
    Version consolidée : strip + limit + dédoublonnage underscores.
    """
    safe = re.sub(r'[^a-zA-Z0-9.\-_]', '_', name)
    safe = re.sub(r'_+', '_', safe)
    safe = safe.strip('._-')
    return safe[:200] if safe else "file"


# ─────────────────────────────────────────────────────────
# ANALYSE STATIQUE — PDF
# ─────────────────────────────────────────────────────────
def analyze_pdf(data: bytes) -> dict:
    """
    FIX v2.2 : filtre phishing renforcé.
    Le lookahead (?!\.com) était mal placé et laissait passer
    des domaines comme 'microsoft.com.evil.ru'.
    Nouvelle logique : on vérifie que le domaine racine n'est PAS légitime.
    """
    threats, risk = [], 0
    try:
        text = data.decode('latin-1', errors='ignore')
        checks = [
            ('/JS',           '/JavaScript',    50, "JavaScript embarqué"),
            ('/AA',           '/OpenAction',    40, "Action automatique à l'ouverture"),
            ('/Launch',       None,             65, "Action Launch (exécution externe)"),
            ('/EmbeddedFile', None,             35, "Fichier embarqué dans PDF"),
        ]
        for kw1, kw2, pts, label in checks:
            if kw1 in text or (kw2 and kw2 in text):
                threats.append(label)
                risk += pts

        if '/AcroForm' in text and '/Action' in text:
            threats.append("Formulaire avec action suspecte")
            risk += 25

        urls = re.findall(r'https?://[^\s\x00-\x1f\x7f-\xff]{5,}', text)

        # FIX v2.2 : domaines légitimes connus → exclure proprement
        LEGIT_DOMAINS = {
            'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
            'google.com', 'adobe.com', 'office.com', 'live.com',
        }

        def is_suspicious_url(url: str) -> bool:
            url_lower = url.lower()
            # Raccourcisseurs toujours suspects
            if re.search(r'(bit\.ly|tinyurl\.com|t\.co|goo\.gl)', url_lower):
                return True
            # Mots-clés suspects dans le path/query
            if re.search(r'(redirect|login|verify|secure|account|confirm|update)', url_lower):
                # Extraire le domaine racine
                domain_match = re.match(r'https?://([^/\?]+)', url_lower)
                if domain_match:
                    host = domain_match.group(1).lstrip('www.')
                    # Légit si domaine racine exact connu
                    if any(host == d or host.endswith('.' + d) for d in LEGIT_DOMAINS):
                        return False
                return True
            return False

        phishing_urls = [u for u in urls if is_suspicious_url(u)]
        if phishing_urls:
            threats.append(f"URLs suspectes dans PDF : {phishing_urls[:2]}")
            risk += 30

    except Exception as e:
        threats.append(f"Erreur analyse PDF : {e}")
    return {"type": "PDF", "risk": min(100, risk), "threats": threats}


# ─────────────────────────────────────────────────────────
# ANALYSE STATIQUE — DOCX
# ─────────────────────────────────────────────────────────

# Domaines Office légitimes — liens vers ces domaines sont moins suspects
_DOCX_KNOWN_DOMAINS = {
    'microsoft.com', 'office.com', 'sharepoint.com', 'onedrive.com',
    'google.com', 'drive.google.com', 'dropbox.com', 'adobe.com',
}

def _is_known_domain(url: str) -> bool:
    """Retourne True si l'URL appartient à un domaine Office/cloud connu."""
    try:
        host = re.match(r'https?://([^/\?]+)', url.lower())
        if not host:
            return False
        h = host.group(1).lstrip('www.')
        return any(h == d or h.endswith('.' + d) for d in _DOCX_KNOWN_DOMAINS)
    except Exception:
        return False


def analyze_docm(data: bytes) -> dict:
    """OLE2 binary macro-enabled format (.docm, .doc) — byte-scan approach."""
    threats, risk = [], 0
    if len(data) < 8 or data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return {"type": "DOCM", "risk": 20, "threats": ["Fichier OLE2 malformé"]}
    risk += 45
    threats.append("Format OLE2 binaire (macro-ready)")
    data_upper = data.upper()
    for kw, score, msg in [
        (b"VBAPROJECT",    40, "Stream VBA Project présent"),
        (b"VBA",           30, "Marqueur VBA détecté"),
        (b"AUTOOPEN",      30, "Auto-exec: AutoOpen"),
        (b"AUTO_OPEN",     30, "Auto-exec: Auto_Open"),
        (b"AUTOEXEC",      30, "Auto-exec: AutoExec"),
        (b"DOCUMENT_OPEN", 25, "Auto-exec: Document_Open"),
        (b"SHELL",         20, "Appel Shell dans macro"),
        (b"WSCRIPT",       25, "WScript dans macro"),
        (b"POWERSHELL",    25, "PowerShell dans macro"),
        (b"HTTP://",       15, "URL HTTP dans macro"),
    ]:
        if kw in data_upper:
            threats.append(msg)
            risk += score
    return {"type": "DOCM", "risk": min(100, risk), "threats": threats}


def analyze_docx(data: bytes) -> dict:
    """
    NEW v2.3 :
    - Liens externes : +45 si domaine inconnu, +20 si domaine connu
      (était flat +35 quelle que soit la destination)
    - BEC faible : +12/mot-clé (était +8) → 3 mots = 36 pts, franchit seuil 30
    - Bonus combinaison BEC + lien externe ou BEC critique : +15
      (signal multi-vecteur = plus fiable)
    """
    threats, risk = [], 0
    ext_links_found: list = []
    fl_found: list        = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            files = z.namelist()

            # ── Macros VBA ──────────────────────────────────────────────
            if 'word/vbaProject.bin' in files:
                threats.append("Macros VBA détectées")
                risk += 70

            # ── Liens externes — NEW v2.3 repondération ─────────────────
            if 'word/_rels/document.xml.rels' in files:
                rels = z.read('word/_rels/document.xml.rels').decode('utf-8', errors='ignore')
                if 'TargetMode="External"' in rels:
                    ext_links_found = re.findall(r'Target="(https?://[^"]+)"', rels)
                    if ext_links_found:
                        unknown = [l for l in ext_links_found if not _is_known_domain(l)]
                        known   = [l for l in ext_links_found if     _is_known_domain(l)]
                        if unknown:
                            threats.append(f"Liens externes suspects (domaine inconnu) : {unknown[:2]}")
                            risk += 45   # v2.3 : +45 (était +35 flat)
                        if known:
                            threats.append(f"Liens externes vers domaine connu : {known[:2]}")
                            risk += 20   # v2.3 : +20 pour domaine connu légitime

            # ── BEC — NEW v2.3 repondération ────────────────────────────
            if 'word/document.xml' in files:
                content    = z.read('word/document.xml').decode('utf-8', errors='ignore')
                text_clean = re.sub(r'<[^>]+>', ' ', content).lower()
                bec_high   = ['wire transfer', 'virement urgent', 'mot de passe', 'gift card']
                bec_low    = ['urgent', 'invoice', 'facture', 'click here', 'verify your']
                fh = [p for p in bec_high if p in text_clean]
                fl_found   = [p for p in bec_low  if p in text_clean]
                if fh:
                    threats.append(f"BEC critique : {fh[:3]}")
                    risk += len(fh) * 25
                if fl_found:
                    threats.append(f"BEC faible : {fl_found[:3]}")
                    risk += len(fl_found) * 12   # v2.3 : +12/mot (était +8)

            # ── Bonus combinaison — NEW v2.3 ────────────────────────────
            # Signal multi-vecteur : BEC faible + lien externe = comportement
            # d'un vrai phishing DOCX (texte urgence + redirection externe)
            if fl_found and ext_links_found:
                threats.append("Signal combiné : BEC faible + lien externe")
                risk += 15   # v2.3 : bonus cumulatif

            # ── PowerShell / CMD ────────────────────────────────────────
            for f in files:
                if f.endswith('.xml'):
                    try:
                        c = z.read(f).decode('utf-8', errors='ignore').lower()
                        if 'powershell' in c or 'cmd.exe' in c:
                            threats.append("PowerShell/CMD dans DOCX")
                            risk += 70
                            break
                    except Exception:
                        continue

    except Exception as e:
        threats.append(f"Erreur analyse DOCX : {e}")
    return {"type": "DOCX", "risk": min(100, risk), "threats": threats}


# ─────────────────────────────────────────────────────────
# ANALYSE STATIQUE — XLSX
# ─────────────────────────────────────────────────────────
def analyze_xlsx(data: bytes) -> dict:
    threats, risk = [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            files = z.namelist()
            if 'xl/vbaProject.bin' in files:
                threats.append("Macros VBA dans Excel")
                risk += 70
            for f in files:
                if 'sheet' in f and f.endswith('.xml'):
                    try:
                        c = z.read(f).decode('utf-8', errors='ignore').lower()
                        if 'dde' in c or 'powershell' in c:
                            threats.append("DDE/PowerShell dans XLSX")
                            risk += 65
                            break
                        if '=http' in c or 'webservice' in c:
                            threats.append("Appel réseau depuis formule Excel")
                            risk += 45
                    except Exception:
                        continue
    except Exception as e:
        threats.append(f"Erreur analyse XLSX/XLSM : {e}")
        data_upper = data.upper()
        for kw, score, msg in [
            (b"VBAPROJECT",  60, "VBA Project (scan binaire)"),
            (b"PRIVATE SUB", 25, "Macro VBA détectée"),
            (b"KEYLOG",      30, "Comportement keylogger"),
            (b"SMTP",        20, "SMTP (exfiltration probable)"),
            (b"SHELL",       20, "Appel Shell"),
            (b"AUTOOPEN",    25, "Auto-exec macro"),
        ]:
            if kw in data_upper:
                threats.append(msg)
                risk += score
    return {"type": "XLSX", "risk": min(100, risk), "threats": threats}


# ─────────────────────────────────────────────────────────
# ANALYSE STATIQUE — ZIP (ZIP bomb detection)
# ─────────────────────────────────────────────────────────
def analyze_zip(data: bytes, depth: int = 0) -> dict:
    """
    Seuils ZIP bomb abaissés pour moins de faux positifs.
    """
    threats           = []
    risk              = 0
    MAX_NESTED_SIZE   = 10 * 1024 * 1024   # 10 MB
    MAX_UNCOMPRESSED  = 200 * 1024 * 1024  # 200 MB total

    if depth > 3:
        return {"type": "ZIP", "risk": 60, "threats": ["ZIP trop imbriqué (>3 niveaux)"]}

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            files  = z.namelist()
            infos  = z.infolist()

            total_decomp = sum(i.file_size for i in infos)
            if total_decomp > MAX_UNCOMPRESSED:
                return {"type": "ZIP", "risk": 100,
                        "threats": [f"ZIP bomb : {total_decomp//(1024*1024)} MB décompressé"]}

            total_comp = sum(i.compress_size for i in infos)
            if total_comp > 0 and (total_decomp / total_comp) > 100:
                threats.append(f"Ratio compression suspect : {total_decomp//total_comp}x")
                risk += 80

            if len(files) > 500:
                threats.append(f"Archive suspecte : {len(files)} fichiers")
                risk += 60

            dangerous_ext   = ['.exe', '.bat', '.ps1', '.vbs', '.js', '.scr', '.cmd', '.dll', '.hta', '.jar']
            found_dangerous = [f for f in files if any(f.lower().endswith(e) for e in dangerous_ext)]
            if found_dangerous:
                threats.append(f"Exécutables : {found_dangerous[:3]}")
                risk += 85

            for f in files:
                if f.lower().endswith('.zip') and depth < 3:
                    info = z.getinfo(f)
                    if info.file_size > MAX_NESTED_SIZE:
                        threats.append(f"Archive imbriquée trop lourde : {f}")
                        risk += 40
                        continue
                    nested = analyze_zip(z.read(f), depth + 1)
                    if nested['risk'] > 0:
                        threats.append(f"Archive imbriquée suspecte : {f}")
                        risk += nested['risk'] // 2

    except zipfile.BadZipFile:
        threats.append("ZIP corrompu ou malformé")
        risk += 30
        data_upper = data.upper()
        for kw, score, msg in [
            (b"WSCRIPT.SHELL", 40, "WScript.Shell (ZIP corrompu)"),
            (b"POWERSHELL",    35, "PowerShell (ZIP corrompu)"),
            (b"HTTP://",       20, "URL HTTP (ZIP corrompu)"),
        ]:
            if kw in data_upper:
                threats.append(msg)
                risk += score
    except Exception as e:
        threats.append(f"Erreur analyse ZIP : {e}")

    return {"type": "ZIP", "risk": min(100, risk), "threats": threats}


def analyze_attachment(attachment: dict) -> dict:
    name = attachment.get("name", "").lower()
    data = attachment.get("data", b"")
    if not data:
        return {"type": "INCONNU", "risk": 0, "threats": ["Fichier vide"]}
    if name.endswith(".pdf"):               return analyze_pdf(data)
    elif name.endswith(".docx"):            return analyze_docx(data)
    elif name.endswith((".docm", ".doc")):  return analyze_docm(data)
    elif name.endswith((".xlsx", ".xlsm")): return analyze_xlsx(data)
    elif name.endswith(".zip"):             return analyze_zip(data)
    return {"type": "AUTRE", "risk": 0, "threats": []}


# ─────────────────────────────────────────────────────────
# PARSE VM RESULT — FIX v2.2 : regex greedy + DOTALL
# ─────────────────────────────────────────────────────────
def parse_vm_result(log_content: str) -> tuple[int, list, str]:
    """
    Parse les logs de la VM pour extraire vm_risk, vm_threats, sha256.

    FIX v2.2 :
    - Regex était r'\\{.*?\\}' (non-greedy) → coupait les JSON longs
    - Corrigé en r'\\{.*\\}' avec re.DOTALL pour matcher tout le JSON
    """
    vm_risk    = 0
    vm_threats = []
    sha256     = "N/A"

    try:
        # FIX v2.2 : greedy + DOTALL
        match = re.search(r'\[VM RESULT\]\s*(\{.*\})', log_content, re.DOTALL)
        if match:
            result_json = json.loads(match.group(1))
            vm_risk    = result_json.get("vm_risk", 0)
            vm_threats = result_json.get("vm_threats", [])
            sha256     = result_json.get("sha256", "N/A")

        sha_match = re.search(r'\[VM\] SHA256\s*:\s*([a-f0-9]{64})', log_content)
        if sha_match:
            sha256 = sha_match.group(1)

    except Exception as e:
        print(f"   [⚠️] Erreur parsing VM result : {e}")

    return vm_risk, vm_threats, sha256


# ─────────────────────────────────────────────────────────
# BLOB STORAGE
# ─────────────────────────────────────────────────────────
def get_blob_service_client() -> BlobServiceClient:
    conn_str = (
        f"DefaultEndpointsProtocol=https;"
        f"AccountName={STORAGE_ACCOUNT_NAME};"
        f"AccountKey={STORAGE_ACCOUNT_KEY};"
        f"EndpointSuffix=core.windows.net"
    )
    return BlobServiceClient.from_connection_string(conn_str)


def upload_to_blob(data: bytes, blob_name: str) -> str:
    try:
        client = get_blob_service_client()
        try:
            client.create_container(CONTAINER_NAME)
        except Exception:
            pass

        blob_client = client.get_blob_client(CONTAINER_NAME, blob_name)
        blob_client.upload_blob(data, overwrite=True)

        sas_token = generate_blob_sas(
            account_name   = STORAGE_ACCOUNT_NAME,
            container_name = CONTAINER_NAME,
            blob_name      = blob_name,
            account_key    = STORAGE_ACCOUNT_KEY,
            permission     = BlobSasPermissions(read=True),
            expiry         = datetime.now(timezone.utc) + timedelta(minutes=15)
        )
        url = (f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
               f"/{CONTAINER_NAME}/{blob_name}?{sas_token}")
        print(f"   [☁️ BLOB] Uploadé : {blob_name}")
        return url
    except Exception as e:
        print(f"   [⚠️ BLOB] Erreur upload : {e}")
        return ""


def delete_from_blob(blob_name: str):
    try:
        client = get_blob_service_client()
        client.get_blob_client(CONTAINER_NAME, blob_name).delete_blob()
        print(f"   [🗑️ BLOB] Supprimé : {blob_name}")
    except Exception as e:
        print(f"   [⚠️ BLOB] Erreur suppression : {e}")


# ─────────────────────────────────────────────────────────
# SCRIPT VM — analyse dynamique
# ─────────────────────────────────────────────────────────
def build_vm_script(blob_url: str, blob_name: str) -> str:
    return f"""
import urllib.request, os, zipfile, re, json, sys, hashlib

url      = '{blob_url}'
filename = '{blob_name}'

try:
    urllib.request.urlretrieve(url, filename)
    print(f'[VM] Téléchargé : {{filename}} ({{os.path.getsize(filename)}} bytes)')
except Exception as e:
    print(f'[VM ERROR] Téléchargement : {{e}}')
    print('[VM RESULT] {{"vm_risk": 0, "vm_threats": ["Téléchargement échoué"], "sha256": ""}}')
    sys.exit(0)

with open(filename, 'rb') as f:
    sha256 = hashlib.sha256(f.read()).hexdigest()
print(f'[VM] SHA256 : {{sha256}}')

threats, risk = [], 0

if filename.endswith('.docx') or filename.endswith('.xlsx'):
    try:
        with zipfile.ZipFile(filename) as z:
            files = z.namelist()
            if 'word/vbaProject.bin' in files or 'xl/vbaProject.bin' in files:
                threats.append('Macros VBA (VM)')
                risk += 70
            for f in files:
                if f.endswith('.xml'):
                    try:
                        c = z.read(f).decode('utf-8', errors='ignore').lower()
                        if 'powershell' in c or 'cmd.exe' in c:
                            threats.append('PowerShell/CMD (VM)')
                            risk += 65
                        if 'dde' in c:
                            threats.append('DDE (VM)')
                            risk += 60
                    except: pass
    except Exception as e:
        threats.append(f'Erreur DOCX/XLSX VM : {{e}}')

elif filename.endswith('.pdf'):
    try:
        with open(filename, 'rb') as f:
            text = f.read().decode('latin-1', errors='ignore')
        if '/JavaScript' in text or '/JS' in text:
            threats.append('JavaScript PDF (VM)')
            risk += 55
        if '/OpenAction' in text or '/AA' in text:
            threats.append('OpenAction (VM)')
            risk += 45
        if '/Launch' in text:
            threats.append('Launch action (VM)')
            risk += 70
        if '/EmbeddedFile' in text:
            threats.append('Fichier embarqué PDF (VM)')
            risk += 35
    except Exception as e:
        threats.append(f'Erreur PDF VM : {{e}}')

elif filename.endswith('.zip'):
    try:
        with zipfile.ZipFile(filename) as z:
            files = z.namelist()
            dangerous = ['.exe','.bat','.ps1','.vbs','.js','.scr','.cmd','.dll']
            found = [f for f in files if any(f.lower().endswith(e) for e in dangerous)]
            if found:
                threats.append(f'Exécutables ZIP (VM) : {{found[:3]}}')
                risk += 85
            total = sum(i.file_size for i in z.infolist())
            if total > 100*1024*1024:
                threats.append(f'ZIP bomb (VM) : {{total//(1024*1024)}} MB')
                risk += 90
    except Exception as e:
        threats.append(f'Erreur ZIP VM : {{e}}')

result = {{'vm_risk': min(100, risk), 'vm_threats': threats, 'sha256': sha256}}
print(f'[VM RESULT] {{json.dumps(result)}}')
print('[VM DONE]')
"""


# ─────────────────────────────────────────────────────────
# AZURE CONTAINER INSTANCE
# ─────────────────────────────────────────────────────────
def run_azure_container(blob_url: str, blob_name: str) -> tuple[bool, str]:
    """
    FIX v2.2 :
    - MAX_WAIT augmenté à 240s (était 180s, insuffisant pour cold-start)
    - Logs vides → retourne (False, "") au lieu de (True, "")
    """
    container_name = f"sandbox-{str(uuid.uuid4())[:8]}"
    try:
        creds  = ClientSecretCredential(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
        client = ContainerInstanceManagementClient(creds, AZURE_SUBSCRIPTION_ID)

        python_script = build_vm_script(blob_url, blob_name)

        container = Container(
            name      = container_name,
            image     = "python:3.11-slim",
            resources = ResourceRequirements(
                requests=ResourceRequests(memory_in_gb=1.0, cpu=1.0)
            ),
            command   = ["python3", "-c", python_script],
            environment_variables = [
                EnvironmentVariable(name="BLOB_URL",  value=blob_url),
                EnvironmentVariable(name="BLOB_NAME", value=blob_name),
            ]
        )

        group = ContainerGroup(
            location       = LOCATION,
            containers     = [container],
            os_type        = OperatingSystemTypes.LINUX,
            restart_policy = ContainerGroupRestartPolicy.NEVER,
        )

        print(f"   [🔵 VM] Création ACI : {container_name}")
        op = client.container_groups.begin_create_or_update(
            RESOURCE_GROUP, container_name, group
        )
        op.result(timeout=180)
        print(f"   [✅ VM] ACI créée — attente exécution...")

        MAX_WAIT = 240  # FIX v2.2 : augmenté de 180 → 240s
        INTERVAL = 8
        elapsed  = 0
        log_content = ""

        while elapsed < MAX_WAIT:
            time.sleep(INTERVAL)
            elapsed += INTERVAL
            try:
                grp   = client.container_groups.get(RESOURCE_GROUP, container_name)
                iv    = grp.containers[0].instance_view
                state = iv.current_state.state if iv and iv.current_state else "Pending"
                print(f"   [⏳ VM] État : {state} ({elapsed}s)")
                if state in ("Terminated", "Failed", "Stopped"):
                    break
            except Exception as e:
                print(f"   [⚠️ VM] Erreur poll : {e}")
                break

        try:
            logs        = client.containers.list_logs(RESOURCE_GROUP, container_name, container_name)
            log_content = logs.content or ""
            if log_content:
                print(f"   [📋 VM LOGS]\n{log_content}")
            else:
                # FIX v2.2 : logs vides = échec VM, pas succès silencieux
                print(f"   [⚠️ VM] Logs vides après {elapsed}s — VM considérée en échec")
                try:
                    client.container_groups.begin_delete(RESOURCE_GROUP, container_name)
                except Exception:
                    pass
                return False, ""
        except Exception as e:
            print(f"   [⚠️ VM] Logs indisponibles : {e}")
            return False, str(e)

        try:
            client.container_groups.begin_delete(RESOURCE_GROUP, container_name)
            print(f"   [🗑️ VM] ACI détruite : {container_name}")
        except Exception as e:
            print(f"   [⚠️ VM] Suppression ACI échouée : {e}")

        return True, log_content

    except AzureError as e:
        print(f"   [⚠️ VM] AzureError : {e}")
        return False, str(e)
    except Exception as e:
        print(f"   [⚠️ VM] Erreur inattendue : {e}")
        return False, str(e)


# ─────────────────────────────────────────────────────────
# AGENT PRINCIPAL — v2.2 FINAL
# ─────────────────────────────────────────────────────────
def run_sandbox_agent(attachments: list, score_provisoire: int) -> dict:
    """
    v2.3 FINAL — inchangé par rapport à v2.2 sur la logique principale.
    Les améliorations v2.3 sont dans analyze_docx (repondération scores).
    - Upload échoué → penalité score +20
    - VM échouée → signalé dans le verdict final
    - vm_failures dans le retour
    """
    if not attachments:
        return {
            "triggered":     False,
            "score_sandbox": 0,
            "detail":        "Sandbox non requise — pas de PJ",
            "verdict":       "✅ PAS DE SANDBOX",
        }

    print(f"\n   [🔬 SANDBOX] Déclenchée — {len(attachments)} PJ détectée(s)")

    all_results, all_threats = [], []
    max_risk    = 0
    vm_failures = 0  # FIX v2.2 : compter les échecs VM

    for att in attachments:
        name = att.get("name", "unknown")
        data = att.get("data", b"")

        size_mb = len(data) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            print(f"   [🚫] Fichier trop lourd : {name} ({size_mb:.1f} MB)")
            all_threats.append(f"Fichier trop lourd ignoré : {name}")
            max_risk = max(max_risk, 15)
            continue

        ext = os.path.splitext(name)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            print(f"   [🚫] Extension non supportée : {name}")
            all_results.append({
                "type":    ext.upper().lstrip(".") or "INCONNU",
                "risk":    25,
                "threats": [f"Extension non autorisée : '{ext}'"]
            })
            all_threats.append(f"Extension non autorisée : {name}")
            max_risk = max(max_risk, 25)
            continue

        print(f"   [📁] Analyse locale : {name} ({size_mb:.2f} MB)")

        local_result = analyze_attachment(att)
        all_results.append(local_result)
        all_threats.extend(local_result["threats"])
        max_risk = max(max_risk, local_result["risk"])

        print(f"   [📊] {local_result['type']} — Risque local : {local_result['risk']}/100")
        for t in local_result["threats"]:
            print(f"        ⚠️  {t}")

        safe_name = sanitize_blob_name(name)
        blob_name = f"{uuid.uuid4()}-{safe_name}"

        blob_url = upload_to_blob(data, blob_name)

        if blob_url:
            vm_ok, vm_logs = run_azure_container(blob_url, safe_name)
            delete_from_blob(blob_name)  # zero persistence

            if vm_ok:
                vm_risk, vm_threats, vm_sha256 = parse_vm_result(vm_logs)
                if vm_risk > 0 or vm_threats:
                    max_risk = max(max_risk, vm_risk)
                    all_threats.extend(vm_threats)
                    print(f"   [🖥️ VM] Risque : {vm_risk}/100 | SHA256 : {vm_sha256[:16]}...")
                else:
                    print(f"   [🖥️ VM] Aucune menace supplémentaire")
            else:
                # FIX v2.2 : VM échouée → signalé, pas ignoré silencieusement
                vm_failures += 1
                all_threats.append(f"Analyse VM échouée pour : {name} (résultat local uniquement)")
                print(f"   [⚠️ VM] Analyse VM échouée pour {name}")
        else:
            # FIX v2.2 : upload échoué → pénalité +20 pour signaler l'anomalie
            vm_failures += 1
            max_risk = max(max_risk, max_risk + 20)
            all_threats.append(f"Upload blob échoué pour : {name} (pénalité appliquée)")
            print(f"   [⚠️] Upload échoué pour {name} — pénalité score +20")

    score_sandbox = min(100, max_risk)

    if score_sandbox >= 75:
        verdict = "🛑 SANDBOX : MENACE DÉTECTÉE"
    elif score_sandbox >= 40:
        verdict = "⚠️ SANDBOX : COMPORTEMENT SUSPECT"
    elif vm_failures > 0:
        # FIX v2.2 : si VM a échoué, on ne peut pas garantir "SAIN"
        verdict = "⚠️ SANDBOX : RÉSULTAT PARTIEL (VM indisponible)"
    else:
        verdict = "✅ SANDBOX : FICHIERS SAINS"

    return {
        "triggered":      True,
        "score_sandbox":  score_sandbox,
        "files_analyzed": len(attachments),
        "vm_failures":    vm_failures,   # FIX v2.2 : nouveau champ
        "results":        all_results,
        "threats":        all_threats,
        "detail":         f"{len(all_threats)} menace(s) dans {len(attachments)} PJ",
        "verdict":        verdict,
    }