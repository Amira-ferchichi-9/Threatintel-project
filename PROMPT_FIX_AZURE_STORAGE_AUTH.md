PROMPT POUR CLAUDE PRO — FIX ERREUR AZURE STORAGE AUTHENTICATION

═══════════════════════════════════════════════════════════════════════════════════

**CONTEXTE**

Je déploie une Azure Function via `func azure functionapp publish` depuis une machine Windows 11 (PowerShell).
L'erreur reçue est :

```
Server failed to authenticate the request. Make sure the value of Authorization header is formed correctly 
including the signature.
...
AuthenticationErrorDetail: Signed expiry time [Tue, 28 Apr 2026 00:27:34 GMT] must be after signed start time 
[Tue, 28 Apr 2026 00:27:34 GMT]
```

**DESCRIPTION DU PROBLÈME**

Cela indique un time skew : le SAS token (Shared Access Signature) généré par Azure CLI a une durée de validité invalide 
ou l'horloge système de la machine est désynchronisée.

**DIAGNOSTIC ET ÉTAPES DE FIX — S'IL VOUS PLAÎT SUIVRE CET ORDRE EXACT**

### Étape 1 — Vérifier l'horloge système

**Pourquoi** : Azure rejette les requêtes avec timestamp invalide si l'horloge est désynchronisée de > 5 min.

```powershell
# Afficher l'heure système actuelle
Get-Date

# Comparer avec l'heure Azure (faire une requête et vérifier le header Date)
# Ou vérifier manuellement en ligne : https://www.timeanddate.com/gmt/now

# Si l'horloge est en retard ou en avance > 5 min :
# Resynchroniser l'horloge Windows
w32tm /resync
# Ou via l'interface : Paramètres → Heure et date → Synchroniser maintenant
```

**Effet attendu** : l'horloge système et Azure sont synchronisées (< 30 secondes de différence).

---

### Étape 2 — Vérifier les credentials Azure CLI

**Pourquoi** : les credentials expirées ou invalides génèrent des tokens malformés.

```powershell
# Vérifier le login Azure actuel
az account show

# Si not connected ou account invalide :
az logout
az login

# Vérifier que vous êtes sur le bon abonnement (Azure for Students)
az account set --subscription "<subscription-id>"

# Vérifier que la subscription contient le Storage Account
az storage account show --name stthreatintel2761 --resource-group rg-threatintel
```

**Effet attendu** : `stthreatintel2761` listée, status = Succeeded.

---

### Étape 3 — Régénérer la connection string et les credentials

**Pourquoi** : forcer une nouvelle génération des SAS tokens.

```powershell
# Récupérer la clé d'accès au Storage Account
$storageKey = az storage account keys list --account-name stthreatintel2761 --resource-group rg-threatintel --query [0].value -o tsv

# Afficher la connection string
$connString = "DefaultEndpointsProtocol=https;AccountName=stthreatintel2761;AccountKey=$storageKey;EndpointSuffix=core.windows.net"
Write-Host $connString

# Vérifier que la connection string est valide (tester une connexion)
az storage blob list --account-name stthreatintel2761 --container-name "gmail-tokens"
```

**Effet attendu** : connection string affichée, pas d'erreur d'auth.

---

### Étape 4 — Mettre à jour local.settings.json et env vars

**Pourquoi** : les variables locales peuvent être expirées ou mal formatées.

```powershell
# Copier la nouvelle connection string dans threatintel-function/local.settings.json
# Chercher "AZURE_STORAGE_CONNECTION_STRING" et remplacer la valeur

# Ou via CLI :
$connString = "DefaultEndpointsProtocol=https;AccountName=stthreatintel2761;AccountKey=$storageKey;EndpointSuffix=core.windows.net"

# Mettre à jour env var dans Windows (optionnel, test local)
[Environment]::SetEnvironmentVariable("AZURE_STORAGE_CONNECTION_STRING", $connString, "User")

# Relancer PowerShell pour appliquer
```

**Effet attendu** : local.settings.json contient une connection string valide.

---

### Étape 5 — Nettoyer le cache local et les artefacts

**Pourquoi** : les fichiers de build en cache peuvent contenir des credentials expirées.

```powershell
# Dans threatintel-function/
cd threatintel-function

# Supprimer les artefacts de build
Remove-Item -Path ".funcignore" -ErrorAction SilentlyContinue
Remove-Item -Path ".python_packages" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "__pycache__" -Recurse -ErrorAction SilentlyContinue

# Reconstruire le package
func extensions install --python
pip install -r requirements.txt
```

**Effet attendu** : build artifacts nettoyés, dependencies réinstallées.

---

### Étape 6 — Test de déploiement local d'abord

**Pourquoi** : s'assurer que la Function fonctionne en local avant de déployer sur Azure.

```powershell
# Tester localement
func start

# Dans un autre terminal, envoyer un message test
Invoke-WebRequest -Uri "http://localhost:7071/api/emailanalyzer" `
  -Method POST `
  -Body '{"from":"test@test.com","subject":"test"}' `
  -ContentType "application/json"
```

**Effet attendu** : la Function démarre sans erreur locale, traite le message test.

---

### Étape 7 — Redéployer sur Azure avec credentials fraîches

**Pourquoi** : le déploiement avec credentials à jour devrait réussir.

```powershell
# S'assurer que vous êtes dans le bon répertoire
cd C:\Users\amira\Desktop\PFA_2\threatintel-function

# Arrêter la Function locale (Ctrl+C dans le terminal func start)

# Redéployer
func azure functionapp publish fa-threatintel

# Ou, forcer une nouvelle build avec --build=remote
func azure functionapp publish fa-threatintel --build=remote
```

**Effet attendu** : déploiement réussit (exit code 0), Function publiée sur Azure.

---

### Étape 8 — Vérifier le déploiement sur Azure Portal

**Pourquoi** : confirmer que la Function est active et accessible.

```powershell
# Vérifier le status de la Function
az functionapp show --name fa-threatintel --resource-group rg-threatintel --query "state"

# Afficher les logs Azure (optionnel)
func azure functionapp logstream fa-threatintel
```

**Effet attendu** : state = Succeeded, logs affichés sans erreur auth.

---

## SI L'ERREUR PERSISTE — DIAGNOSTIQUES AVANCÉS

Si après toutes les étapes ci-dessus l'erreur persiste, essayer :

### Option A — Vérifier le SAS token manuellement

```powershell
# Générer un SAS token avec délai expiré configurable
$sasToken = az storage account generate-sas --account-name stthreatintel2761 `
  --account-key $storageKey `
  --resource-types sco `
  --services bfqt `
  --expiry (Get-Date).AddHours(1).ToString("yyyy-MM-ddTHH:mm:ssZ") `
  --https-only `
  --query ""

# Afficher la structure du token
Write-Host "SAS Token : $sasToken"

# Vérifier qu'il contient les champs attendus (st, se, sp, sig, etc.)
```

### Option B — Utiliser l'authentification par identité managée (plus robuste)

```powershell
# Au lieu de SAS tokens, configurer l'identité managée de la Function
az functionapp identity assign --resource-group rg-threatintel --name fa-threatintel --role "Storage Blob Data Contributor"

# Mettre à jour local.settings.json : enlever AZURE_STORAGE_CONNECTION_STRING
# et utiliser auth DefaultAzureCredential (bibliothèque azure-identity Python)
```

### Option C — Déboguer la requête exacte envoyée

```powershell
# Activer le debug Azure CLI
$env:AZURE_CLI_TRACE = 'true'

# Redéployer pour voir exactement la requête d'authentification
func azure functionapp publish fa-threatintel 2>&1 | Tee-Object -FilePath "deploy_debug.log"

# Afficher le log complet
Get-Content "deploy_debug.log" | Select-String -Pattern "Authorization", "expiry", "signature"
```

---

## RÉSUMÉ FINAL

**Cause racine probable** : horloge système désynchronisée + credentials expirées.

**Actions prioritaires** :
1. Resynchroniser l'horloge Windows (`w32tm /resync`).
2. Re-login Azure CLI (`az logout` → `az login`).
3. Régénérer connection string.
4. Tester localement (`func start`).
5. Redéployer sur Azure.

**Si toujours bloqué** : contacter support Azure ou fournir le log complet (deploy_debug.log) pour analyse approfondie.

---

**FIN DU PROMPT**

