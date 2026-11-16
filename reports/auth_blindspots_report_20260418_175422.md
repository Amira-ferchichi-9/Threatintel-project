# Rapport blindspots auth

Date: 2026-04-18T17:54:22
Cas: 12 (malicious=10, benign=2)

## Performance
- Matrice [[TN, FP], [FN, TP]]: [[2, 0], [0, 10]]
- Metrics: accuracy=1.000, precision=1.000, recall=1.000, f1=1.000, tp=10, tn=2, fp=0, fn=0

## Resultats par angle mort
- arabic_rtl_display_name: total=2 malicious=2 benign=0 fn=0 fp=0
- compromised_legit_relay: total=2 malicious=2 benign=0 fn=0 fp=0
- control_benign: total=2 malicious=0 benign=2 fn=0 fp=0
- exotic_tld_deceptive: total=2 malicious=2 benign=0 fn=0 fp=0
- no_display_name_spoof: total=2 malicious=2 benign=0 fn=0 fp=0
- subtle_multi_signal_combo: total=2 malicious=2 benign=0 fn=0 fp=0

## Vulnerabilites detectees
- Aucune

## False negatives
- Aucun