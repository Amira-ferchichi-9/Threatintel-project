# Rapport blindspots auth

Date: 2026-04-18T17:48:38
Cas: 12 (malicious=10, benign=2)

## Performance
- Matrice [[TN, FP], [FN, TP]]: [[2, 0], [2, 8]]
- Metrics: accuracy=0.833, precision=1.000, recall=0.800, f1=0.889, tp=8, tn=2, fp=0, fn=2

## Resultats par angle mort
- arabic_rtl_display_name: total=2 malicious=2 benign=0 fn=0 fp=0
- compromised_legit_relay: total=2 malicious=2 benign=0 fn=2 fp=0
- control_benign: total=2 malicious=0 benign=2 fn=0 fp=0
- exotic_tld_deceptive: total=2 malicious=2 benign=0 fn=0 fp=0
- no_display_name_spoof: total=2 malicious=2 benign=0 fn=0 fp=0
- subtle_multi_signal_combo: total=2 malicious=2 benign=0 fn=0 fp=0

## Vulnerabilites detectees
- B-REL-001 | angle=compromised_legit_relay | risk=high | Blindspot bypass (malicious sample not blocked)
- B-REL-002 | angle=compromised_legit_relay | risk=high | Blindspot bypass (malicious sample not blocked)

## False negatives
- B-REL-001 | angle=compromised_legit_relay | score=100 | Legit corporate domain with all pass (possible account takeover) | SPF ✅ | DKIM ✅ | DMARC ✅ (reject) | ℹ️ HVT — revue BEC requise : High-Value Target : signal exec (display) sur domaine corporate 'acme-corp.com' — possible compromised relay
- B-REL-002 | angle=compromised_legit_relay | score=90 | Compromised shared provider scenario (all pass) | SPF ✅ | DKIM ✅ | DMARC ✅ (quarantine)