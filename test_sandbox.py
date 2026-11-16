import sys
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Test 1: Vérifier config Azure
print("=" * 70)
print("🔍 VÉRIFICATION CONFIGURATION AZURE")
print("=" * 70)

required_vars = [
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_SUBSCRIPTION_ID",
    "RESOURCE_GROUP",
    "STORAGE_ACCOUNT_NAME",
    "STORAGE_ACCOUNT_KEY",
]

missing = [v for v in required_vars if not os.getenv(v)]

if missing:
    print(f"\n❌ Variables manquantes : {', '.join(missing)}")
    print("\n📝 Ajoute ces variables dans .env :")
    for var in missing:
        print(f"   {var}=<valeur>")
    sys.exit(1)
else:
    print("✅ Toutes les variables sont présentes\n")
    for var in required_vars:
        val = os.getenv(var)
        print(f"   {var:.<40} {'✅' if val else '❌'}")

print("\n" + "=" * 70)
print("🧪 TEST 1 : ANALYSE STATIQUE LOCALE (rapide)")
print("=" * 70)

# Importer les fonctions d'analyse
from agents.agent_sandbox import analyze_pdf, analyze_docx, analyze_xlsx, analyze_zip

# Créer des fichiers de test
import io
import zipfile

print("\n[1️⃣] Créer fichier PDF de test...")
pdf_data = b"""%PDF-1.4
1 0 obj
<</Type /Catalog /Pages 2 0 R>>
endobj
2 0 obj
<</Type /Pages /Kids [3 0 R] /Count 1>>
endobj
3 0 obj
<</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]>>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<</Size 4 /Root 1 0 R>>
startxref
203
%%EOF"""

result_pdf = analyze_pdf(pdf_data)
print(f"   Résultat : {result_pdf}")
print(f"   ├─ Risque : {result_pdf['risk']}/100")
print(f"   └─ Menaces : {result_pdf['threats']}")

print("\n[2️⃣] Créer fichier DOCX de test (ZIP vide)...")
docx_buffer = io.BytesIO()
with zipfile.ZipFile(docx_buffer, 'w') as z:
    z.writestr('word/document.xml', '<document/>')
docx_data = docx_buffer.getvalue()

result_docx = analyze_docx(docx_data)
print(f"   Résultat : {result_docx}")
print(f"   ├─ Risque : {result_docx['risk']}/100")
print(f"   └─ Menaces : {result_docx['threats']}")

print("\n[3️⃣] Créer fichier XLSX de test...")
xlsx_buffer = io.BytesIO()
with zipfile.ZipFile(xlsx_buffer, 'w') as z:
    z.writestr('xl/worksheets/sheet1.xml', '<sheet/>')
xlsx_data = xlsx_buffer.getvalue()

result_xlsx = analyze_xlsx(xlsx_data)
print(f"   Résultat : {result_xlsx}")
print(f"   ├─ Risque : {result_xlsx['risk']}/100")
print(f"   └─ Menaces : {result_xlsx['threats']}")

print("\n[4️⃣] Créer fichier ZIP de test...")
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w') as z:
    z.writestr('file.txt', 'test content')
zip_data = zip_buffer.getvalue()

result_zip = analyze_zip(zip_data)
print(f"   Résultat : {result_zip}")
print(f"   ├─ Risque : {result_zip['risk']}/100")
print(f"   └─ Menaces : {result_zip['threats']}")

print("\n" + "=" * 70)
print("✅ PHASE 1 TERMINÉE — Analyses statiques OK")
print("=" * 70)

# Test 2: Vérifier connexion Azure
print("\n" + "=" * 70)
print("🔷 TEST 2 : CONNEXION AZURE")
print("=" * 70)

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    
    print("\n[🔑] Authentification Azure...")
    creds = ClientSecretCredential(tenant_id, client_id, client_secret)
    print("   ✅ Authentification réussie")
    
    print("\n[🖥️] Connexion au service Container Instance...")
    client = ContainerInstanceManagementClient(creds, subscription_id)
    print("   ✅ Connexion réussie")
    
    print("\n[📋] Récupération des groupes de conteneurs existants...")
    rg = os.getenv("RESOURCE_GROUP")
    groups = list(client.container_groups.list_by_resource_group(rg))
    print(f"   ✅ {len(groups)} groupe(s) trouvé(s)")
    for g in groups[:5]:  # Afficher les 5 premiers
        print(f"      ├─ {g.name}")
    
    print("\n" + "=" * 70)
    print("✅ PHASE 2 TERMINÉE — Azure OK")
    print("=" * 70)
    
except Exception as e:
    print(f"\n❌ Erreur Azure : {e}")
    print("\nDiagnostic :")
    print("1. Vérifiez que vos credentials Azure sont valides")
    print("2. Vérifiez que le resource group existe")
    print("3. Lancez : az login && az account set --subscription <sub_id>")
    sys.exit(1)

print("\n" + "=" * 70)
print("🎉 TOUS LES TESTS RÉUSSIS — Prêt pour sandbox!")
print("=" * 70)