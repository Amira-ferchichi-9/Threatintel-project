# PFA Email Threat Detection — Docker + Cosmos DB

## Structure du projet

```
PFA_2/
├── docker-compose.yml       ← orchestration
├── Dockerfile               ← image Python
├── .env                     ← tes clés (ne jamais commit)
├── .env.template            ← modèle sans clés
├── requirements.txt         ← dépendances Python
├── api.py                   ← serveur FastAPI (nouveau)
├── orchestrator.py          ← pipeline principal (existant)
├── cache.py                 ← Redis + Cosmos (mis à jour)
├── cosmos_client.py         ← intégration Cosmos DB (nouveau)
├── report_generator.py      ← existant
└── agents/
    ├── agent_auth.py
    ├── agent_url.py
    ├── agent_nlp_bec.py
    ├── agent_sandbox.py
    └── agent_scoring.py
```

---

## Étape 1 — Créer Cosmos DB sur Azure

1. Va sur https://portal.azure.com
2. Recherche **"Azure Cosmos DB"** → Créer
3. Choisis **"Core (SQL)"** 
4. Nom du compte : `pfa-email-threats`
5. Mode capacité : **Serverless** (gratuit pour test)
6. Région : `France Central`
7. Après création → **Clés** → copie `URI` et `Clé primaire`

---

## Étape 2 — Remplis ton .env

Copie `.env.template` → `.env` et remplis :

```
COSMOS_ENDPOINT=https://pfa-email-threats.documents.azure.com:443/
COSMOS_KEY=ta_cle_primaire_ici
```

⚠️ Mets aussi tes nouvelles clés Azure régénérées !

---

## Étape 3 — Lance Docker

```powershell
# Dans le dossier PFA_2
docker compose up --build
```

C'est tout ! Docker va :
- Construire l'image Python
- Démarrer Redis
- Démarrer ton API sur http://localhost:8000

---

## Utilisation

### Analyser un email
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"subject":"Test","sender":"test@gmail.com","body":"Hello"}'
```

### Voir l'historique
```
http://localhost:8000/history
```

### Statistiques
```
http://localhost:8000/stats
```

### Documentation API interactive
```
http://localhost:8000/docs
```

---

## Comment ça marche

```
Email entrant
     │
     ▼
[Hash SHA256]
     │
     ▼
[Redis Cache] ──hit──→ Réponse immédiate (< 1ms)
     │ miss
     ▼
[Cosmos DB] ──hit──→ Réponse rapide + recharge Redis
     │ miss
     ▼
[Pipeline IA complet]
(Auth + URL + NLP + Sandbox + Scoring)
     │
     ▼
[Sauvegarde Redis + Cosmos DB]
     │
     ▼
Verdict + Rapport HTML
```

---

## Arrêter Docker

```powershell
docker compose down
```

## Voir les logs

```powershell
docker compose logs -f orchestrator
```
