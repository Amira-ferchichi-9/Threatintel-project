Chapitre 3 — Analyse et Spécification des Besoins

3.1 Contexte et objectifs

Ce chapitre décrit les besoins non fonctionnels et fonctionnels liés au pipeline ThreatIntel développé dans ce projet. Le système prend en entrée des e-mails Gmail (via Logic Apps), poste des messages sur une queue Service Bus, déclenche l'Azure Function `EmailAnalyzer` qui orchestre 5 agents d'analyse en parallèle (NLP, sandbox, URL reputation, IP/WHOIS, scoring). Les résultats sont stockés dans Cosmos DB et mis en cache dans Redis. L'objectif principal est d'assurer une analyse automatique fiable, réactive et résiliente, avec intervention humaine minimale.

3.2 Exigences générales

- Disponibilité cible : 99,5 % pour l'ensemble du pipeline d'analyse (depuis la réception de l'e-mail jusqu'à l'enregistrement du rapport dans Cosmos DB).
- Latence cible : p50 ≤ 1.8 s en production small (voir tableau de déploiement).
- Résilience : le pipeline doit tolérer l'indisponibilité partielle (API externes, modèles ML, sandbox) sans bloquer la réception des e-mails.
- Observabilité : logs structurés (structlog), métriques Prometheus, traces distribuées pour les flux critiques.
- Sécurité : stockage des secrets dans Azure Key Vault, sandbox isolation (cgroups/seccomp pour VM de sandbox), audit des accès.

3.3 Disponibilité et Scalabilité

Le service de messagerie est critique : la perte de disponibilité doit rester transparente pour la réception des e-mails. Pour atteindre cet objectif nous proposons :

- Scalabilité horizontale : déployer plusieurs instances de l'API et de la Function App (ou conteneur) derrière l'API Gateway/Service Bus pour absorber les pics.
- Mode asynchrone : la réception des e-mails (Logic App → Service Bus) est découplée du traitement pour garantir la non-perte de messages.
- Objectif chiffré : 99,5 % de disponibilité pour la chaîne d'analyse complète.

Mécanismes de résilience appliqués (réglages concrets pour ce projet) :

1. Circuit Breaker
- Seuil : 3 échecs consécutifs pour un endpoint externe ou pour l'appel d'un agent.
- Durée OPEN : 60 s (pendant ce temps, les appels échoués suivent le fallback).
- Fallback : heuristique locale ou score neutre selon le composant (voir ci-dessous).

2. Retry avec backoff exponentiel
- Tentatives : jusqu'à 2 répétitions (soit 3 appels au total).
- Delais : 100 ms puis 500 ms avant la dernière tentative.
- Usage : appliqué aux requêtes vers API externes (GSB, AbuseIPDB, WHOIS) et aux accès réseau temporaires.

3. Graceful Fallback
- NLP indisponible : renvoyer un score neutre pour la partie NLP et marquer l’analyse comme "partielle". L’agrégateur combine les autres sources.
- OSINT (API externes) indisponible : utiliser règles heuristiques locales (liste noire localisée, signatures simples) comme fallback.
- Sandbox indisponible : reporter l’inspection binaire et marquer le verdict comme « pending sandbox » ou utiliser heuristique si d’autres signaux sont forts.

4. Healthchecks
- Endpoint : GET /health
- Vérifie : connexion Redis (PING), accès Cosmos DB (simple query), présence des fichiers modèles dans le container (p.ex. distilbert files) et état du worker de sandbox.

3.4 Configuration de déploiement recommandée

Tableau 3.8 – Configurations selon l’environnement

| Environnement       | Instances API | Redis (RAM)   | Cosmos RU/s | Latence p50 |
|---------------------|---------------:|--------------:|------------:|------------:|
| Développement       | 1              | Single (1 GB) | 100         | 2.5 s      |
| Pré-production      | 2              | Cluster (3 GB)| 200         | 2.0 s      |
| Production (small)  | 3              | Cluster (6 GB)| 400         | 1.8 s      |
| Production (large)  | 5+             | Cluster (10 GB)| 1000+      | 1.5 s      |

Remarques d’implémentation :
- Pour la Function App en Consumption, le modèle PyTorch est trop lourd pour le remote build (exit code 137). Solution adoptée : construire une image Docker basée sur `mcr.microsoft.com/azure-functions/python:4-python3.11`, pousser l'image sur Azure Container Registry (`acrthreatintel2761`) et configurer `fa-threatintel` pour utiliser le conteneur.
- Le build context doit fournir les modules partagés (orchestrator, cosmos_client, cache, agents). Pour limiter la taille de l'image, exclure datasets, checkpoints de modèle et artefacts locaux via `.dockerignore`.

3.5 Modélisation UML des interactions

Les diagrammes décrits ci-dessous complètent la description textuelle et servent de support aux tests d’intégration et à la revue d’architecture.

3.5.1 Diagramme de cas d’utilisation (Figure 3.2)
- Acteurs : Administrateur, Analyste SOC, Système de messagerie (MTA), Services externes (GSB, AbuseIPDB, WHOIS).
- Cas d’usage principaux : configurer seuils, monitorer healthchecks, recevoir alertes, consulter rapport, valider/invalider verdict, soumettre e-mail, recevoir verdict, exécuter action.

(Figure 3.2 doit être intégrée au rapport final. Chaque figure sera référencée dans le texte au premier paragraphe où elle est mentionnée.)

3.5.2 Diagramme de séquence — Analyse d’un e-mail suspect (Figure 3.3)

Flux adapté au projet :
1. MTA envoie POST /v1/analyze (JWT) → API Gateway/Function
2. Orchestrator loggue la requête et déclenche les agents en parallèle (NLP, sandbox, URL, IP/OSINT, scoring)
3. Cache Redis : lookup (hit/miss)
4. Agents requis effectuent requêtes externes (GSB, AbuseIPDB, WHOIS) avec retry/backoff et circuit breaker
5. Résultats renvoyés à l’agrégateur, scores pondérés, calcul score final (ex : s_final = 0.756)
6. Upsert du rapport dans Cosmos DB, mise en cache verdict TTL 1h dans Redis
7. Notification asynchrone vers SOC via Service Bus ou webhook
8. Logs structurés + exposer métriques Prometheus

Durée observée en test local/prototype : ~3.9 s pour un flux complet avec sandbox actif. Cette durée dépend fortement de la sandbox (VM) et des appels externes.

3.5.3 Diagramme de séquence — Soumission de feedback SOC (Figure 3.4)

Flux adapté :
1. Analyste SOC POST /v1/analysis/{id}/feedback (JWT, scope: write)
2. API vérifie le token, upsert du feedback dans Cosmos DB
3. Acknowledgement (200 OK + feedback_id)
4. Trigger (flag) pour pipeline ML : marquer l’échantillon pour ré-entraînement (asynchrone)

3.6 Risques et stratégies de mitigation

Tableau 3.9 – Risques identifiés et mitigations adaptées au projet

| Risque                                 | Sévérité | Mitigation concrète pour ce projet |
|----------------------------------------|---------:|-----------------------------------|
| Latence excessive                      | Haute    | Cache Redis pour résultats fréquents; profiler modèles; timeouts agressifs côté API; découpler sandbox (asynchrone) |
| Faux positifs                          | Haute    | Boucle de feedback SOC; seuils ajustables depuis l’interface Admin; ré-entraînement périodique avec échantillons labellisés |
| Dépendances externes indisponibles     | Moyenne  | Circuit breaker + retry; fallback heuristique; marquer l’analyse comme partielle et réessayer en tâche batch |
| Injection / exploit via pièces jointes | Critique  | Sandbox isolée (VM dédiée, cgroups/seccomp), scan antivirus préalable, traitement asynchrone des binaires |
| Compromission de secrets               | Critique  | Azure Key Vault pour secrets; rotation et audit; accès restreint RBAC |
| Downtime Cosmos / Redis                | Moyenne  | Réplication multi-région (si budget), failover, circuit breaker et cache warm sur bascule |
| Attaque DDoS sur l’API                 | Moyenne  | Rate limiting API, Azure WAF, métriques Prometheus et alerting, scaling automatique sous contrôle |
| Build container trop gros (modèle PyTorch)| Moyenne | Construire image ACR, réduire dépendances inutiles, stocker checkpoints dans Blob Storage et charger au runtime si nécessaire |

3.7 Stratégie de test

Pour garantir la qualité, la stratégie de test du projet couvre cinq niveaux :

- Tests unitaires : couverture ≥ 90 % par agent. Les tests ciblent les fonctions de scoring, parsers d’e-mails, et wrappers API externes.
- Tests d’intégration : pipeline bout-en-bout en environnement de pré-prod avec e-mails fixtures et sandbox répliquée.
- Tests de charge : simuler 100 req/s soutenues ; objectif p99 ≤ 5 s. Utiliser k6 ou locust pour les scénarios d’analyse.
- Tests de sécurité : vérifier OWASP Top 10 pour l’API, fuzzing des endpoints, protection contre l’injection de payloads (attachments, URLs).
- Chaos engineering : tests périodiques où la sandbox est arrêtée, APIs externes renvoient des erreurs, ou Cosmos devient lent; vérifier que circuit breaker et fallback fonctionnent.

3.8 Annexes – Vérifications opérationnelles (checklist rapide)

- Vérifier que `AZURE_STORAGE_CONNECTION_STRING` pointe vers `stthreatintel2761`.
- S’assurer que `GMAIL_SESSION` (token_default.json) est uploadé dans le container Blob `gmail-tokens` avant le test E2E.
- Valider que `fa-threatintel` est configuré pour utiliser l'image ACR `acrthreatintel2761`.
- Confirmer que les métriques Prometheus sont exposées et scrapables par l’agent de monitoring.

---

Figures et tables à insérer :
- Figure 3.2 : Diagramme de cas d’utilisation (acteurs et cas d’usage)
- Figure 3.3 : Diagramme de séquence — Analyse d’un e-mail suspect
- Figure 3.4 : Diagramme de séquence — Soumission de feedback SOC
- Tableau 3.8 : Configurations par environnement (déjà inclus)
- Tableau 3.9 : Risques et mitigations (déjà inclus)

Notes bibliographiques et références :
- Référencer chaque paragraphe selon la méthode demandée lors de la mise en page finale (liens cliquables vers la bibliographie). Exemples de sources à mentionner : documentation Azure Functions, Azure Cosmos DB SLA, articles techniques sur circuit breaker et retry, documentation PyTorch et meilleures pratiques pour déploiement en production.



