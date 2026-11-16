# Rapport blindspots auth

Date: 2026-04-18T17:11:32
Cas: 12 (malicious=10, benign=2)

## Performance
- Matrice [[TN, FP], [FN, TP]]: [[2, 0], [6, 4]]
- Metrics: accuracy=0.500, precision=1.000, recall=0.400, f1=0.571, tp=4, tn=2, fp=0, fn=6

## Resultats par angle mort
- arabic_rtl_display_name: total=2 malicious=2 benign=0 fn=1 fp=0
- compromised_legit_relay: total=2 malicious=2 benign=0 fn=2 fp=0
- control_benign: total=2 malicious=0 benign=2 fn=0 fp=0
- exotic_tld_deceptive: total=2 malicious=2 benign=0 fn=1 fp=0
- no_display_name_spoof: total=2 malicious=2 benign=0 fn=2 fp=0
- subtle_multi_signal_combo: total=2 malicious=2 benign=0 fn=0 fp=0

## Vulnerabilites detectees
- B-EXO-002 | angle=exotic_tld_deceptive | risk=high | Blindspot bypass (malicious sample not blocked)
- B-RTL-001 | angle=arabic_rtl_display_name | risk=high | Blindspot bypass (malicious sample not blocked)
- B-NODISP-001 | angle=no_display_name_spoof | risk=high | Blindspot bypass (malicious sample not blocked)
- B-NODISP-002 | angle=no_display_name_spoof | risk=high | Blindspot bypass (malicious sample not blocked)
- B-REL-001 | angle=compromised_legit_relay | risk=high | Blindspot bypass (malicious sample not blocked)
- B-REL-002 | angle=compromised_legit_relay | risk=high | Blindspot bypass (malicious sample not blocked)

## False negatives
- B-EXO-002 | angle=exotic_tld_deceptive | score=80 | Corporate lookalike on deceptive TLD | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none)
- B-RTL-001 | angle=arabic_rtl_display_name | score=70 | Arabic executive title + free mail | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (gmail.com)
- B-NODISP-001 | angle=no_display_name_spoof | score=70 | No display name, free domain ceo alias | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (gmail.com)
- B-NODISP-002 | angle=no_display_name_spoof | score=70 | No display, executive keyword in local-part | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (gmail.com)
- B-REL-001 | angle=compromised_legit_relay | score=100 | Legit corporate domain with all pass (possible account takeover) | SPF ✅ | DKIM ✅ | DMARC ✅ (reject)
- B-REL-002 | angle=compromised_legit_relay | score=90 | Compromised shared provider scenario (all pass) | SPF ✅ | DKIM ✅ | DMARC ✅ (quarantine)