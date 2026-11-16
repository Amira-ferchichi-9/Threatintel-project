GUIDE STRUCTURÉ POUR CAPTURER LES ÉCRANS DU CHAPITRE 4

⚠️ IMPORTANT : Ce guide vous assure zéro oubli. Suivez chaque item et cochezle après capture.

═══════════════════════════════════════════════════════════════════════════════════

## PHASE 1 : PRÉPARATION ENVIRONNEMENT

### ☐ 1.1 — Préparer l'environnement de test
- Démarrer Function App en local : `func start` dans `threatintel-function/`
- Démarrer l'API Python (si separate) ou vérifier déploiement Azure.
- Vérifier service bus connexion : `az servicebus namespace authorization-rule keys list --namespace-name sb-threatintel-2761 --resource-group rg-threatintel`
- Vérifier Cosmos DB accessibilité : portal Azure ou Azure CLI.
- Vérifier Redis disponibilité (si applicable).
- **État cible** : tous les services en vert (health check OK).

### ☐ 1.2 — Configurer Prometheus + Grafana (optionnel mais recommandé)
- Démarrer Prometheus : `docker run -d -p 9090:9090 prom/prometheus --config.file=prometheus.yml`
- Démarrer Grafana : `docker run -d -p 3000:3000 grafana/grafana`
- Importer dashboard custom pour métriques ThreatIntel.

### ☐ 1.3 — Préparer les outils de test de charge
- Installer k6 : `choco install k6` (Windows) ou `brew install k6` (Mac).
- Créer/configurer script k6 pour load test (voir section 4.3.5 du rapport).

### ☐ 1.4 — Préparer les e-mails de test
- Email phishing simple : créer un brouillon Gmail avec contenu suspect.
- Email avec malware : préparer fichier `invoice.exe` (ou eicar test file, inoffensif).
- E-mail neutre : comme témoin (verdict ALLOW attendu).

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 1 : E-MAIL PHISHING SIMPLE

**Objectif** : montrer détection phishing sans pièce jointe.

### ☐ Capture 1.1 — E-mail reçu dans Gmail
- **Description** : afficher l'e-mail complet dans Gmail.
- **À surligner** : From (expéditeur suspect), Subject, URL malveillante dans le corps.
- **Format** : screenshot, dimensions min 1024x768.
- **À exporter** : Save as `chapter4_scen1_01_gmail_phishing.png`.

### ☐ Capture 1.2 — Message dans Service Bus
- **Où aller** : Azure Portal → Service Bus Namespace `sb-threatintel-2761` → Queues → `email-analysis-queue`.
- **Action** : Peek messages ou afficher un message reçu.
- **À afficher** : JSON payload avec champs `from`, `subject`, `body`, `attachments` (vide pour ce scénario).
- **À exporter** : `chapter4_scen1_02_servicebus_message.png`.

### ☐ Capture 1.3 — Function App logs (en cours d'exécution)
- **Où aller** : Azure Portal → Function App `fa-threatintel` → Functions → EmailAnalyzer.
- **Action** : onglet "Monitor" ou "Logs" → afficher les logs en temps réel.
- **À afficher** : logs structurés montrant :
  - `[INFO] request_id=...`
  - `[INFO] cache_lookup: key=...`
  - `[INFO] agent_nlp: status=running`
  - `[INFO] agent_url: status=running`
  - `[INFO] agent_ip: status=running`
  - `[INFO] analysis_complete: verdict=QUARANTINE, latency_ms=2300`
- **À exporter** : `chapter4_scen1_03_function_logs.png`.

### ☐ Capture 1.4 — Résultats des agents (détail)
- **Où aller** : afficher un JSON ou tableau résumé des résultats par agent (mock ou réel).
- **Format** : JSON ou tableau :
```
┌─────────────┬────────────┬─────────────────────────┐
│ Agent       │ Score      │ Decision/Risk           │
├─────────────┼────────────┼─────────────────────────┤
│ NLP         │ 0.82       │ Phishing detected       │
│ Sandbox     │ LOW        │ No binaries             │
│ URL         │ MALICIOUS  │ Detected by GSB         │
│ IP/OSINT    │ 0.55       │ Suspicious domain       │
│ Scoring     │ 0.756      │ QUARANTINE              │
└─────────────┴────────────┴─────────────────────────┘
```
- **À exporter** : `chapter4_scen1_04_agent_results.png`.

### ☐ Capture 1.5 — Rapport stocké dans Cosmos DB
- **Où aller** : Azure Portal → Cosmos DB Account → Database `threatintel` → Container `email_analysis`.
- **Action** : Afficher un document (rapport) de ce scénario.
- **À afficher** : structure JSON complet du rapport (id, agents, verdict, score_final, confidence, etc.).
- **À exporter** : `chapter4_scen1_05_cosmos_report.png`.

### ☐ Capture 1.6 — Verdict en cache Redis
- **Où aller** : Redis CLI ou Redis portal (si Redis Azure).
- **Commande** : `redis-cli keys "*" | head -20` puis `redis-cli get key_du_verdict`.
- **À afficher** : clé (hash), valeur (verdict JSON), TTL (exemple: 3599 sec = ~1h).
- **À exporter** : `chapter4_scen1_06_redis_cache.png`.

### ☐ Capture 1.7 — Notification SOC
- **Où aller** : Teams, Slack, email de notification, ou dashboard SOC interne.
- **À afficher** : alerte avec severity, email_from, subject, verdict, lien vers rapport.
- **À exporter** : `chapter4_scen1_07_soc_alert.png`.

### ☐ Capture 1.8 — Interface SOC (dashboard rapport)
- **Où aller** : interface web SOC ou portal personnalisé pour ThreatIntel.
- **À afficher** : rapport avec verdict QUARANTINE, score 0.756, boutons Confirm/Reject, historique agent.
- **À exporter** : `chapter4_scen1_08_soc_dashboard.png`.

### ☐ Résumé Scénario 1
- Cocher : latence = 2.3 s ✓, confiance = 0.95 ✓, verdicttest = QUARANTINE ✓

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 2 : E-MAIL AVEC PIÈCE JOINTE MALVEILLANTE

**Objectif** : montrer détection malware via sandbox.

### ☐ Capture 2.1 — E-mail + pièce jointe dans Gmail
- **Description** : afficher l'e-mail avec icône pièce jointe visible.
- **À surligner** : From, Subject, pièce jointe `invoice.exe`.
- **À exporter** : `chapter4_scen2_01_gmail_with_attachment.png`.

### ☐ Capture 2.2 — Message Service Bus (avec base64 pièce jointe)
- **Où aller** : Service Bus Queue → peek message.
- **À afficher** : JSON avec champ `attachments[0]` contenant `filename`, `mime_type`, `base64`.
- **À exporter** : `chapter4_scen2_02_servicebus_attachment.png`.

### ☐ Capture 2.3 — Function App logs (sandbox task)
- **À afficher** : logs montrant :
  - `[INFO] agent_sandbox: task_started`
  - `[INFO] sandbox: executing file invoice.exe in isolated environment`
  - `[INFO] sandbox: timeout_set=30s, network_access=restricted`
  - `[INFO] sandbox: detecting_syscalls...`
  - `[DEBUG] sandbox: syscall CreateProcess(cmd.exe, ...)`
  - `[INFO] sandbox: risk_level=CRITICAL`
  - `[INFO] analysis_complete: latency_ms=5200`
- **À exporter** : `chapter4_scen2_03_function_logs_sandbox.png`.

### ☐ Capture 2.4 — Exécution sandbox (capture comportement)
- **Où aller** : afficher résultats détaillés de la sandbox (simulé ou réel).
- **À afficher** :
```
SANDBOX ANALYSIS RESULTS
========================
File: invoice.exe
Risk: CRITICAL
Indicators:
  - Syscall: CreateProcess("cmd.exe /c del C:\*.*")
  - Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\...
  - DLL: kernel32.dll, advapi32.dll (suspectes)
  - Behavior: Tentative suppression fichiers système
```
- **À exporter** : `chapter4_scen2_04_sandbox_results.png`.

### ☐ Capture 2.5 — Résultats agrégés (sandbox CRITICAL)
- **Format** : tableau agent scores :
```
┌─────────────┬────────────┬─────────────────────────┐
│ NLP         │ 0.45       │ Texte neutre            │
│ Sandbox     │ CRITICAL   │ Malware detected        │
│ URL         │ SAFE       │ Domaine connu           │
│ IP/OSINT    │ 0.30       │ IP légitime             │
│ Scoring     │ 0.89       │ QUARANTINE (malware)    │
└─────────────┴────────────┴─────────────────────────┘
```
- **À exporter** : `chapter4_scen2_05_aggregate_scores.png`.

### ☐ Capture 2.6 — Rapport Cosmos (avec détails sandbox)
- **À afficher** : document JSON avec champ `agents.sandbox` détaillé (risk, indicators array).
- **À exporter** : `chapter4_scen2_06_cosmos_report_sandbox.png`.

### ☐ Capture 2.7 — Redis cache (verdict)
- **À afficher** : clé + valeur verdict QUARANTINE avec TTL.
- **À exporter** : `chapter4_scen2_07_redis_verdict.png`.

### ☐ Capture 2.8 — Notification critique SOC
- **À afficher** : alerte urgente (red badge, "CRITICAL - MALWARE DETECTED").
- **À exporter** : `chapter4_scen2_08_soc_alert_critical.png`.

### ☐ Résumé Scénario 2
- Cocher : latence = 5.2 s ✓, confiance = 0.98 ✓, verdict = QUARANTINE (malware) ✓

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 3 : DÉFAILLANCE & FALLBACK (API indisponible)

**Objectif** : montrer résilience via fallback heuristique.

### ☐ Capture 3.1 — Configuration circuit breaker (avant test)
- **Où aller** : afficher métriques ou dashboard circuit breaker state.
- **À afficher** : CB state, error count, last failure timestamp.
- **À exporter** : `chapter4_scen3_01_cb_state.png`.

### ☐ Capture 3.2 — Retry + backoff logs
- **À afficher** : logs montrant :
  - `[INFO] agent_url: attempt 1 - timeout after 1000ms`
  - `[INFO] agent_url: retry in 100ms`
  - `[INFO] agent_url: attempt 2 - timeout after 1000ms`
  - `[INFO] agent_url: retry in 500ms`
  - `[INFO] agent_url: attempt 3 - failure, circuit breaker OPEN`
- **À exporter** : `chapter4_scen3_02_retry_backoff.png`.

### ☐ Capture 3.3 — Fallback heuristique activé
- **À afficher** : logs :
  - `[WARN] agent_url: CB OPEN, applying fallback heuristic`
  - `[DEBUG] fallback: checking local_blacklist for domain...`
  - `[DEBUG] fallback: found in blocklist → risk=SUSPICIOUS`
- **À exporter** : `chapter4_scen3_03_fallback_active.png`.

### ☐ Capture 3.4 — Rapport avec flag fallback
- **À afficher** : JSON report champ `url_fallback: true`, `url_reputation: "SUSPICIOUS (heuristique)"`, scores :
  - NLP: 0.55, URL: 0.60 (heuristique), IP: 0.40, Sandbox: N/A → verdict = SUSPICIOUS
- **À exporter** : `chapter4_scen3_04_report_fallback.png`.

### ☐ Capture 3.5 — Notification SOC (verdict partiel)
- **À afficher** : alerte avec mention `analysis_partial: true`, `fallback_used: true`.
- **À exporter** : `chapter4_scen3_05_soc_notification_partial.png`.

### ☐ Capture 3.6 — Latence résilience
- **À afficher** : logs ou métrique : latence totale = 1.8 s (pas de grave timeout).
- **À exporter** : `chapter4_scen3_06_latency_resilience.png`.

### ☐ Résumé Scénario 3
- Cocher : latence = 1.8 s ✓, confiance = 0.72 ✓, fallback_rate = 1/3 ✓

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 4 : CACHE HIT (réduction latence)

**Objectif** : montrer impact cache sur latence.

### ☐ Capture 4.1 — Première requête (miss cache)
- **À afficher** : logs + métrique latence totale = 2.3 s, orchestrator lance 5 agents.
- **À exporter** : `chapter4_scen4_01_first_request_latency.png`.

### ☐ Capture 4.2 — Redis cache avant deuxième requête
- **À afficher** : Redis keys et TTL (50 min remaining sur clé).
- **À exporter** : `chapter4_scen4_02_redis_ttl.png`.

### ☐ Capture 4.3 — Deuxième requête (cache hit)
- **À afficher** : logs :
  - `[INFO] request_id=... cache_lookup`
  - `[INFO] cache_hit: latency_ms=15`
- **À exporter** : `chapter4_scen4_03_cache_hit_latency.png`.

### ☐ Capture 4.4 — Métriques Prometheus (cache stats)
- **Où aller** : Prometheus dashboard ou Grafana.
- **À afficher** : graphiques :
  - `cache_hit_rate = 50%`
  - `average_latency_cache_hit = 15ms`
  - `average_latency_cache_miss = 2200ms`
- **À exporter** : `chapter4_scen4_04_prometheus_cache_metrics.png`.

### ☐ Résumé Scénario 4
- Cocher : miss latency = 2.3 s ✓, hit latency = 0.015 s ✓, reduction = 99.35% ✓

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 5 : TEST DE CHARGE (100 req/s, 5 min)

**Objectif** : valider scalabilité et SLA en charge.

### ☐ Capture 5.1 — Script k6 load test
- **À afficher** : configuration k6 (stages, ramp-up, sustained load).
- **À exporter** : `chapter4_scen5_01_k6_script.png`.

### ☐ Capture 5.2 — Graphique charge en temps réel
- **Où aller** : k6 output ou Prometheus/Grafana pendant le test.
- **À afficher** : graphiques RPS, latence p50/p95/p99 durant 5 min.
- **À exporter** : `chapter4_scen5_02_load_graph_realtime.png`.

### ☐ Capture 5.3 — Résultats k6 (résumé final)
- **À afficher** : tableau résumé :
```
Total Requests:      30,000
Successful:          29,700 (99%)
Failed:              300 (1%)
p50 Latency:         1.2 s
p95 Latency:         3.8 s
p99 Latency:         4.5 s ✓ (< 5s target)
Throughput (RPS):    99 req/s (≈ 100 target)
```
- **À exporter** : `chapter4_scen5_03_k6_results.png`.

### ☐ Capture 5.4 — Azure Function App metrics
- **Où aller** : Azure Portal → Function App → Monitor.
- **À afficher** : graphiques Invocations, Execution Duration, Error Rate.
- **À exporter** : `chapter4_scen5_04_function_metrics.png`.

### ☐ Capture 5.5 — Cosmos DB RU consumption
- **Où aller** : Azure Portal → Cosmos DB → Insights → RU consumption.
- **À afficher** : graphique RU/s durant test (pic ≈ 280 RU/s, capacity = 400 RU/s → 70% OK).
- **À exporter** : `chapter4_scen5_05_cosmos_ru_consumption.png`.

### ☐ Capture 5.6 — Service Bus queue metrics
- **Où aller** : Azure Portal → Service Bus → Queue metrics.
- **À afficher** : Processed Messages, Active Messages, Dead Letters.
- **À exporter** : `chapter4_scen5_06_servicebus_metrics.png`.

### ☐ Résumé Scénario 5
- Cocher : throughput = 99 req/s ✓, p99 = 4.5s ✓, error rate = 1% ✓, Cosmos RU = 70% ✓

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 6 : SOC FEEDBACK & REENTRAINING

**Objectif** : montrer boucle feedback et ML.

### ☐ Capture 6.1 — Dashboard SOC (rapport initial)
- **À afficher** : rapport SUSPICIOUS (verdict, score 0.65), boutons Confirm/Reject/Review.
- **À exporter** : `chapter4_scen6_01_soc_dashboard_report.png`.

### ☐ Capture 6.2 — Feedback form
- **À afficher** : formulaire avec dropdown `verdict_actual` (options: ALLOW, SUSPICIOUS, QUARANTINE), textarea notes, bouton Submit.
- **À exporter** : `chapter4_scen6_02_feedback_form.png`.

### ☐ Capture 6.3 — Feedback soumis (logs API)
- **À afficher** : logs fonction :
  - `[INFO] POST /v1/analysis/{id}/feedback received`
  - `[INFO] feedback: verdict_actual=ALLOW, analyst_id=..., timestamp=...`
- **À exporter** : `chapter4_scen6_03_feedback_api_logs.png`.

### ☐ Capture 6.4 — Cosmos DB feedback document
- **Où aller** : Cosmos DB → Container `analysis_feedback`.
- **À afficher** : document JSON feedback enregistré (id, original_verdict, corrected_verdict, analyst_id, notes).
- **À exporter** : `chapter4_scen6_04_cosmos_feedback.png`.

### ☐ Capture 6.5 — Retrain flag levé
- **À afficher** : champ `retrain_flag=true` dans rapport Cosmos.
- **À exporter** : `chapter4_scen6_05_retrain_flag.png`.

### ☐ Capture 6.6 — Pipeline ML batch job
- **Où aller** : Azure ML / Databricks / custom job status.
- **À afficher** : job ré-entraînement avec status=RUNNING, logs, dataset size (nb feedbacks labellisés).
- **À exporter** : `chapter4_scen6_06_ml_retrain_job.png`.

### ☐ Résumé Scénario 6
- Cocher : feedback latency = 0.5 s ✓, retrain flag = true ✓, job started ✓

═══════════════════════════════════════════════════════════════════════════════════

## SCÉNARIO 7 : MONITORING & ALERTES

**Objectif** : montrer observabilité et alertes actionnables.

### ☐ Capture 7.1 — Prometheus metrics (fallback rate)
- **Où aller** : Prometheus expression : `rate(fallback_rate[5m])`.
- **À afficher** : graphique montrant fallback_rate = 6% (> 5% seuil).
- **À exporter** : `chapter4_scen7_01_prometheus_fallback_rate.png`.

### ☐ Capture 7.2 — Alert rule Prometheus
- **À afficher** : configuration YAML :
```yaml
alert: HighFallbackRate
expr: rate(fallback_rate[5m]) > 0.05
for: 5m
...
```
- **À exporter** : `chapter4_scen7_02_alert_rule_config.png`.

### ☐ Capture 7.3 — Alert notification (Teams/Slack)
- **À afficher** : message d'alerte reçu en temps réel (embeds, mention @channel, lien runbook).
- **À exporter** : `chapter4_scen7_03_alert_teams_notification.png`.

### ☐ Capture 7.4 — Grafana dashboard (optionnel)
- **À afficher** : dashboard avec gauges fallback_rate, latency_p99, error_rate, uptime.
- **À exporter** : `chapter4_scen7_04_grafana_dashboard.png`.

### ☐ Capture 7.5 — Application Insights live metrics
- **Où aller** : Azure Portal → Application Insights → Live Metrics.
- **À afficher** : flux logs/erreurs en temps réel, CPU, memory, request rate.
- **À exporter** : `chapter4_scen7_05_appinsights_live_metrics.png`.

### ☐ Résumé Scénario 7
- Cocher : MTTD < 5 min ✓, alert notifications working ✓

═══════════════════════════════════════════════════════════════════════════════════

## ÉTAPE FINALE : ORGANISATION & FINALISATION

### ☐ F1 — Vérifier nommage fichiers captures
- Tous les fichiers nommés selon pattern `chapter4_scen{N}_{N:02d}_{description}.png` ✓

### ☐ F2 — Vérifier résolutions captures
- Chaque capture ≥ 1024x768 pixels ✓
- Format PNG ✓

### ☐ F3 — Créer dossier `reports/screenshots/` dans PFA_2
```bash
mkdir -p c:\Users\amira\Desktop\PFA_2\reports\screenshots\
```

### ☐ F4 — Copier toutes les captures dans `reports/screenshots/`
```bash
copy chapter4_scen*_*.png c:\Users\amira\Desktop\PFA_2\reports\screenshots\
```

### ☐ F5 — Créer fichier index des captures
- Créer `reports/screenshots/INDEX.md` avec liste de toutes les captures et description courte.
- Exemple :
```markdown
# Screenshots Index - Chapitre 4

## Scénario 1 : Phishing simple
- [chapter4_scen1_01_gmail_phishing.png] - E-mail suspect dans Gmail
- [chapter4_scen1_02_servicebus_message.png] - Message Service Bus avec payload JSON
... (etc pour tous)
```

### ☐ F6 — Mettre à jour rapport markdown
- Ajouter références aux figures dans `chapter4_realisation_simulation.md` :
```markdown
![Capture 1.1 — E-mail phishing](screenshots/chapter4_scen1_01_gmail_phishing.png)
```

### ☐ F7 — Valider cohérence rapport ↔ captures
- Lire le rapport et vérifier que chaque capture mentionnée est présente et pertinente ✓

### ☐ F8 — Préparer PDF + ZIP final
- Générer PDF du rapport (markdown → pandoc ou word).
- Créer ZIP : `chapters_3_4_with_screenshots.zip` contenant :
  - `chapter_3_analysis_and_specification.md` (ou PDF)
  - `chapter_4_realisation_simulation.md` (ou PDF)
  - Dossier `screenshots/` (tous les fichiers PNG)
  - `INDEX.md` (liste captures)

═══════════════════════════════════════════════════════════════════════════════════

## CHECKLIST FINALE

- [ ] Chapitre 4 rédigé : 8 sections ✓
- [ ] 7 scénarios couverts ✓
- [ ] 40+ captures d'écran identifiées et nommées ✓
- [ ] Dossier screenshots/ créé et rempli ✓
- [ ] Références images insérées dans markdown ✓
- [ ] Rapports validés (cohérence contenu) ✓
- [ ] PDF généré ✓
- [ ] ZIP créé ✓

═══════════════════════════════════════════════════════════════════════════════════

**Fin du Guide Structuré** — Vous avez maintenant une roadmap zéro-oubli pour capturer et documenter le Chapitre 4.
