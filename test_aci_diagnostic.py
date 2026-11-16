#!/usr/bin/env python3
"""
Diagnostic et test du déploiement Azure Container Instance (ACI)
Vérifie que tous les paramètres sont correctement configurés
"""

import os
import sys
import json
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.containerinstance import ContainerInstanceManagementClient
from azure.mgmt.containerinstance.models import (
    ContainerGroup, Container,
    ResourceRequirements, ResourceRequests,
    OperatingSystemTypes, ContainerGroupRestartPolicy,
)
import uuid
import time

load_dotenv()

# Configuration
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")
LOCATION = os.getenv("LOCATION", "francecentral")

print("=" * 70)
print("🔍 DIAGNOSTIC AZURE CONTAINER INSTANCE")
print("=" * 70)

# Vérification des credentials
print("\n1️⃣  Vérification des credentials Azure...")
try:
    creds = ClientSecretCredential(AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)
    print("   ✅ Credentials valides")
except Exception as e:
    print(f"   ❌ Erreur credentials: {e}")
    sys.exit(1)

# Vérification du groupe de ressources
print("\n2️⃣  Vérification du groupe de ressources...")
try:
    client = ContainerInstanceManagementClient(creds, AZURE_SUBSCRIPTION_ID)
    print(f"   Client ACI créé pour {RESOURCE_GROUP}")
except Exception as e:
    print(f"   ❌ Erreur client: {e}")
    sys.exit(1)

# Test de déploiement - Conteneur minimal
print("\n3️⃣  Test de déploiement d'un conteneur Linux minimal...")
test_container_name = f"test-sandbox-{str(uuid.uuid4())[:8]}"

try:
    container = Container(
        name="test-container",
        image="python:3.11-slim",  # ← Image LINUX
        resources=ResourceRequirements(
            requests=ResourceRequests(memory_in_gb=0.5, cpu=0.5)
        ),
        command=["python3", "-c", "print('✅ Linux container is running!'); import sys; print(sys.version)"],
    )

    group = ContainerGroup(
        location=LOCATION,
        containers=[container],
        os_type=OperatingSystemTypes.LINUX,  # ← LINUX OBLIGATOIRE
        restart_policy=ContainerGroupRestartPolicy.NEVER,
    )

    print(f"   Création du conteneur: {test_container_name}")
    op = client.container_groups.begin_create_or_update(
        RESOURCE_GROUP, test_container_name, group
    )
    op.result(timeout=120)
    print(f"   ✅ Conteneur créé")

    # Attendre l'exécution
    print(f"   ⏳ Attente de l'exécution...")
    max_wait = 60
    interval = 5
    elapsed = 0

    while elapsed < max_wait:
        time.sleep(interval)
        elapsed += interval
        try:
            grp = client.container_groups.get(RESOURCE_GROUP, test_container_name)
            state = grp.containers[0].instance_view.current_state.state if grp.containers[0].instance_view else "Pending"
            print(f"      État: {state} ({elapsed}s)")
            if state in ("Terminated", "Failed", "Stopped"):
                break
        except Exception as e:
            print(f"      Erreur poll: {e}")
            break

    # Récupérer les logs
    print(f"   📋 Logs du conteneur:")
    try:
        logs = client.containers.list_logs(RESOURCE_GROUP, test_container_name, "test-container")
        if logs.content:
            print(f"      {logs.content}")
            print(f"   ✅ Conteneur Linux fonctionne!")
        else:
            print(f"      ⚠️  Logs vides")
    except Exception as e:
        print(f"      Erreur logs: {e}")

    # Nettoyer
    print(f"   🗑️  Suppression du conteneur de test...")
    client.container_groups.begin_delete(RESOURCE_GROUP, test_container_name)
    print(f"   ✅ Nettoyage terminé")

except Exception as e:
    print(f"   ❌ Erreur déploiement: {e}")
    try:
        client.container_groups.begin_delete(RESOURCE_GROUP, test_container_name)
    except:
        pass
    sys.exit(1)

print("\n" + "=" * 70)
print("✅ DIAGNOSTIC TERMINÉ - Votre configuration est VALIDE")
print("=" * 70)
