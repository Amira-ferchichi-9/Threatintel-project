# test_cosmos.py — à lancer à la racine du projet
import os
from dotenv import load_dotenv
load_dotenv()

from cosmos_client import get_container, get_stats, save_analysis

print("1. Test connexion...")
try:
    container = get_container()
    print(f"   ✅ Connecté → container '{container.id}'")
except Exception as e:
    print(f"   ❌ Erreur : {e}")
    exit(1)

print("2. Test écriture...")
try:
    doc_id = save_analysis(
        email_context={
            "email_hash": "test_hash_123",
            "subject": "Test ThreatIntel",
            "sender": "test@example.com",
            "source_folder": "INBOX",
            "has_attachment": False,
        },
        result={
            "auth_score": 10,
            "url_score": 5,
            "nlp_score": 0,
            "sandbox_score": 0,
            "final_score": 15,
            "verdict": "SAIN",
            "verdict_label": "Email légitime",
            "agent_details": {},
            "report_path": "",
        }
    )
    print(f"   ✅ Document créé → id: {doc_id}")
except Exception as e:
    print(f"   ❌ Erreur écriture : {e}")

print("3. Test stats...")
try:
    stats = get_stats()
    print(f"   ✅ Stats : {stats}")
except Exception as e:
    print(f"   ❌ Erreur stats : {e}")