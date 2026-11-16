# Rapport blindspots auth

Date: 2026-04-18T17:30:20
Cas: 12 (malicious=10, benign=2)

## Performance
- Matrice [[TN, FP], [FN, TP]]: [[2, 0], [1, 9]]
- Metrics: accuracy=0.917, precision=1.000, recall=0.900, f1=0.947, tp=9, tn=2, fp=0, fn=1

## Resultats par angle mort
- arabic_rtl_display_name: total=2 malicious=2 benign=0 fn=0 fp=0
- compromised_legit_relay: total=2 malicious=2 benign=0 fn=1 fp=0
- control_benign: total=2 malicious=0 benign=2 fn=0 fp=0
- exotic_tld_deceptive: total=2 malicious=2 benign=0 fn=0 fp=0
- no_display_name_spoof: total=2 malicious=2 benign=0 fn=0 fp=0
- subtle_multi_signal_combo: total=2 malicious=2 benign=0 fn=0 fp=0

## Vulnerabilites detectees
- B-REL-002 | angle=compromised_legit_relay | risk=high | Blindspot bypass (malicious sample not blocked)

## False negatives
- B-REL-002 | angle=compromised_legit_relay | score=90 | Compromised shared provider scenario (all pass) | SPF ✅ | DKIM ✅ | DMARC ✅ (quarantine)