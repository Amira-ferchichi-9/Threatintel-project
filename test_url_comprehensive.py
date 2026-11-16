from agents.agent_url import check_url, run_url_agent, extract_urls, is_in_tranco
import time

print("\n" + "="*80)
print("TEST COMPLET — AGENT URL v2.4")
print("="*80)

# ============================================================================
# TEST 1: Heuristique Locale (URLs suspects patterns)
# ============================================================================
print("\n📋 TEST 1: Heuristique Locale (Patterns Suspects)")
print("-"*80)

heuristic_tests = [
    ("https://192.168.1.1/login", "IP directe", 75),
    ("https://bit.ly/phishing", "URL shortener", 35),
    ("https://example.tk/", "TLD gratuit (.tk)", 60),
    ("https://ngrok.io/admin", "Tunnel ngrok", 65),
    ("https://login-secure.xyz", "Domaine phishing pattern", 70),
    ("https://paypal-verify.top", "Imitation PayPal", 75),
    ("https://amazon-login.xyz", "Imitation Amazon", 75),
    ("https://microsoft365-update.club", "Imitation Microsoft", 70),
    ("https://apple-id.online", "Imitation Apple ID", 70),
    ("https://legit-unsubscribe.com/opt-out", "URL légitime (unsubscribe)", 0),
]

heur_passed = 0
for url, label, expected_min_score in heuristic_tests:
    score, detail, is_tranco = check_url(url)
    status = "✅" if score >= expected_min_score else "❌"
    if score >= expected_min_score:
        heur_passed += 1
    print(f"{status} {label:<35} | Score: {score:>3}/100 | {detail}")

print(f"\nRésultat: {heur_passed}/{len(heuristic_tests)} tests heuristique passed")

# ============================================================================
# TEST 2: Tranco Top 1M (Domaines de confiance)
# ============================================================================
print("\n\n📋 TEST 2: Tranco Top 1M (Domaines Légitimes)")
print("-"*80)

tranco_tests = [
    ("https://www.google.com", "Google", True),
    ("https://www.facebook.com", "Facebook", True),
    ("https://www.amazon.com", "Amazon", True),
    ("https://www.microsoft.com", "Microsoft", True),
    ("https://www.github.com", "GitHub", True),
    ("https://soprasteria.com", "Soprasteria", True),
    ("https://random-unknown-site-12345.xyz", "Unknown site", False),
]

tranco_passed = 0
for url, label, should_be_tranco in tranco_tests:
    in_tranco, _ = is_in_tranco(url)
    status = "✅" if in_tranco == should_be_tranco else "❌"
    if in_tranco == should_be_tranco:
        tranco_passed += 1
    tranco_str = "OUI" if in_tranco else "NON"
    expected_str = "OUI" if should_be_tranco else "NON"
    print(f"{status} {label:<25} | Tranco: {tranco_str} (expected: {expected_str})")

print(f"\nRésultat: {tranco_passed}/{len(tranco_tests)} tests Tranco passed")

# ============================================================================
# TEST 3: Agent URL Global (Body Text avec URLs)
# ============================================================================
print("\n\n📋 TEST 3: Agent URL Global (Body Text avec URLs)")
print("-"*80)

body_tests = [
    {
        "body": "Cliquez ici pour vérifier votre compte PayPal: https://paypal-secure.xyz/verify",
        "label": "Phishing PayPal + IP",
        "expected_verdict_contains": "SUSPECT",
    },
    {
        "body": "Vérifiez votre compte Microsoft: https://microsoft365-update.club/login",
        "label": "Phishing Microsoft",
        "expected_verdict_contains": "SUSPECT",
    },
    {
        "body": "Bienvenue sur Google: https://www.google.com",
        "label": "URL légitime Google",
        "expected_verdict_contains": "SAIN",
    },
    {
        "body": "Visitez notre site: https://soprasteria.com et https://amazon.com",
        "label": "Deux URLs légitimes",
        "expected_verdict_contains": "SAIN",
    },
    {
        "body": "Aucune URL ici, juste du texte ordinaire.",
        "label": "Pas d'URL",
        "expected_verdict_contains": "AUCUN",
    },
    {
        "body": "Shortener suspect: https://bit.ly/xyz123 et https://tinyurl.com/abc",
        "label": "Deux URL shorteners",
        "expected_verdict_contains": "SUSPECT",
    },
]

agent_passed = 0
for test in body_tests:
    result = run_url_agent(test["body"])
    verdict = result["verdict"]
    status = "✅" if test["expected_verdict_contains"] in verdict else "❌"
    if test["expected_verdict_contains"] in verdict:
        agent_passed += 1
    
    print(f"\n{status} {test['label']}")
    print(f"   URLs trouvées: {result['urls_found']}")
    print(f"   Score URL: {result['score_url']}/100")
    print(f"   Verdict: {verdict}")
    if result['urls']:
        for url_info in result['urls'][:2]:
            print(f"     → {url_info['url'][:60]:<60} | {url_info['score']:>3} | {url_info['detail']}")

print(f"\nRésultat: {agent_passed}/{len(body_tests)} tests Agent URL passed")

# ============================================================================
# TEST 4: Performance & Latence
# ============================================================================
print("\n\n📋 TEST 4: Performance & Latence")
print("-"*80)

perf_tests = [
    "https://www.google.com",
    "https://paypal-secure.xyz",
    "https://bit.ly/test",
    "https://192.168.1.1",
    "https://amazon-login.top",
]

times = []
for url in perf_tests:
    start = time.time()
    score, detail, is_tranco = check_url(url)
    elapsed = time.time() - start
    times.append(elapsed)
    status = "⚡" if elapsed < 0.5 else "⏱️" if elapsed < 1.5 else "🐢"
    print(f"{status} {url:<45} | {elapsed*1000:>6.1f}ms | Score: {score:>3}")

avg_time = sum(times) / len(times)
max_time = max(times)
min_time = min(times)
print(f"\nPerformance: avg={avg_time*1000:.1f}ms | min={min_time*1000:.1f}ms | max={max_time*1000:.1f}ms")

# ============================================================================
# TEST 5: Extract URLs (Parser)
# ============================================================================
print("\n\n📋 TEST 5: Extract URLs (Parser)")
print("-"*80)

extract_tests = [
    {
        "text": "Visit https://google.com and https://facebook.com for more info",
        "expected_count": 2,
        "label": "Deux URLs simples",
    },
    {
        "text": "Lien: https://bit.ly/test123 et https://example.com/path?query=1",
        "expected_count": 2,
        "label": "URLs avec paramètres",
    },
    {
        "text": "Pas d'URL ici, juste du texte.",
        "expected_count": 0,
        "label": "Pas d'URL",
    },
    {
        "text": "Multiple: https://a.com, https://b.com (https://c.com) et https://d.com.",
        "expected_count": 4,
        "label": "Multiple URLs avec punctuation",
    },
]

extract_passed = 0
for test in extract_tests:
    urls = extract_urls(test["text"])
    status = "✅" if len(urls) == test["expected_count"] else "❌"
    if len(urls) == test["expected_count"]:
        extract_passed += 1
    print(f"{status} {test['label']:<35} | Found: {len(urls)}/{test['expected_count']}")
    for url in urls[:3]:
        print(f"     → {url[:60]}")

print(f"\nRésultat: {extract_passed}/{len(extract_tests)} tests Extract passed")

# ============================================================================
# SUMMARY
# ============================================================================
print("\n\n" + "="*80)
print("📊 RÉSUMÉ GÉNÉRAL")
print("="*80)

total_tests = len(heuristic_tests) + len(tranco_tests) + len(body_tests) + len(extract_tests)
total_passed = heur_passed + tranco_passed + agent_passed + extract_passed

summary_data = {
    "Heuristique Locale": (heur_passed, len(heuristic_tests)),
    "Tranco Top 1M": (tranco_passed, len(tranco_tests)),
    "Agent URL Global": (agent_passed, len(body_tests)),
    "Extract URLs": (extract_passed, len(extract_tests)),
}

for test_name, (passed, total) in summary_data.items():
    percentage = (passed / total * 100) if total > 0 else 0
    status_icon = "✅" if passed == total else "⚠️" if passed >= total * 0.8 else "❌"
    print(f"{status_icon} {test_name:<25} | {passed}/{total} ({percentage:>5.1f}%)")

print(f"\n{'─'*80}")
print(f"Total: {total_passed}/{total_tests} tests passés ({total_passed/total_tests*100:.1f}%)")
print("="*80)
