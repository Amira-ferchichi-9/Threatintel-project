import time
from google.cloud import compute_v1

# --- TA CONFIGURATION ---
# Remplace par l'ID de ton projet (ex: pfa-2-487613)
PROJECT_ID = "pfa-2-487613" 
ZONE = "us-central1-a"
SERVICE_ACCOUNT_FILE = "service_account.json"

def create_instance():
    """Crée une micro-VM isolée (la Sandbox)."""
    print(f"🚀 [CLOUD] Demande de création de la VM Sandbox...")
    client = compute_v1.InstancesClient.from_service_account_json(SERVICE_ACCOUNT_FILE)
    
    # Configuration minimale (e2-micro) pour économiser tes futurs crédits
    instance = {
        "name": "pfa-sandbox-test",
        "machine_type": f"zones/{ZONE}/machineTypes/e2-micro",
        "disks": [{
            "boot": True,
            "auto_delete": True,
            "initialize_params": {
                "source_image": "projects/debian-cloud/global/images/family/debian-11"
            }
        }],
        "network_interfaces": [{"name": "global/networks/default"}]
    }

    operation = client.insert(project=PROJECT_ID, zone=ZONE, instance_resource=instance)
    print("⏳ [WAIT] En attente du démarrage de la VM...")
    operation.result() # Attend que la VM soit prête
    print("🖥️ [VM READY] La machine virtuelle est active dans le Cloud !")

def delete_instance():
    """Détruit la VM immédiatement."""
    print("♻️ [CLEANUP] Suppression de la VM Sandbox...")
    client = compute_v1.InstancesClient.from_service_account_json(SERVICE_ACCOUNT_FILE)
    operation = client.delete(project=PROJECT_ID, zone=ZONE, instance="pfa-sandbox-test")
    operation.result()
    print("✅ [SECURE] Environnement détruit avec succès.")

if __name__ == "__main__":
    try:
        create_instance()
        print("💡 Simulation : Le fichier suspect est ouvert dans cette VM...")
        time.sleep(10) # On la laisse vivre 10 secondes pour le test
    finally:
        delete_instance()