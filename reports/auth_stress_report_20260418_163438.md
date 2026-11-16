# Rapport stress test agent_auth

Date: 2026-04-18T16:34:38
Cas: 29 (malicious=18, benign=11)

## Performance globale
- Confusion matrix [[TN, FP], [FN, TP]]: [[11, 0], [8, 10]]
- Metrics: accuracy=0.724, precision=1.000, recall=0.556, f1=0.714, tp=10, tn=11, fp=0, fn=8

## Faiblesses et vulnerabilites detectees
- A-M-004 | executive_free_domain | risk=high | Malicious identity bypassed as benign/partial
- A-E-001 | evasion_display_obfuscation | risk=high | Malicious identity bypassed as benign/partial
- A-E-002 | evasion_display_obfuscation | risk=high | Malicious identity bypassed as benign/partial
- A-E-003 | evasion_punycode | risk=high | Malicious identity bypassed as benign/partial
- A-E-004 | evasion_cousin_root | risk=high | Malicious identity bypassed as benign/partial
- A-E-005 | evasion_replyto_same_domain | risk=high | Malicious identity bypassed as benign/partial
- A-E-006 | evasion_dmarc_bestguesspass | risk=high | Malicious identity bypassed as benign/partial
- A-E-008 | evasion_header_parse | risk=high | Malicious identity bypassed as benign/partial
- A-M-004 | executive_free_domain | risk=critical | No anomaly signal triggered on malicious sample
- A-E-001 | evasion_display_obfuscation | risk=critical | No anomaly signal triggered on malicious sample
- A-E-002 | evasion_display_obfuscation | risk=critical | No anomaly signal triggered on malicious sample
- A-E-003 | evasion_punycode | risk=critical | No anomaly signal triggered on malicious sample
- A-E-004 | evasion_cousin_root | risk=critical | No anomaly signal triggered on malicious sample
- A-E-005 | evasion_replyto_same_domain | risk=critical | No anomaly signal triggered on malicious sample
- A-E-006 | evasion_dmarc_bestguesspass | risk=critical | No anomaly signal triggered on malicious sample
- A-E-008 | evasion_header_parse | risk=critical | No anomaly signal triggered on malicious sample

## False negatives (attaques ratees)
- A-M-004 | executive_free_domain | score=70 | Executive spoof FR accent | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (gmail.com)
- A-E-001 | evasion_display_obfuscation | score=70 | Exec obfuscated with digit | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (gmail.com)
- A-E-002 | evasion_display_obfuscation | score=70 | Exec abbreviation punctuated | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (gmail.com)
- A-E-003 | evasion_punycode | score=80 | Punycode brand spoof | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none)
- A-E-004 | evasion_cousin_root | score=80 | Long cousin root evasion | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none)
- A-E-005 | evasion_replyto_same_domain | score=90 | Reply-to same domain trap | SPF ✅ | DKIM ✅ | DMARC ✅ (quarantine)
- A-E-006 | evasion_dmarc_bestguesspass | score=65 | DMARC bestguesspass header | SPF ✅ | DKIM ✅ | DMARC absent
- A-E-008 | evasion_header_parse | score=70 | From parse unusual format | SPF ✅ | DKIM ✅ | DMARC ✅ (p=none) | Domaine gratuit (outlook.com)

## False positives (legitimes bloques)
- Aucun

## Stats par categorie
- alignment_attack: total=2 malicious=2 benign=0 fn=0 fp=0
- auth_absent_combo: total=1 malicious=1 benign=0 fn=0 fp=0
- auth_fail_combo: total=1 malicious=1 benign=0 fn=0 fp=0
- benign_arc: total=1 malicious=0 benign=1 fn=0 fp=0
- benign_baseline: total=4 malicious=0 benign=4 fn=0 fp=0
- benign_consumer: total=2 malicious=0 benign=2 fn=0 fp=0
- benign_edge: total=2 malicious=0 benign=2 fn=0 fp=0
- benign_marketing: total=1 malicious=0 benign=1 fn=0 fp=0
- benign_shared_infra: total=1 malicious=0 benign=1 fn=0 fp=0
- cousin_domain: total=1 malicious=1 benign=0 fn=0 fp=0
- evasion_arc_source: total=1 malicious=1 benign=0 fn=0 fp=0
- evasion_cousin_root: total=1 malicious=1 benign=0 fn=1 fp=0
- evasion_display_obfuscation: total=2 malicious=2 benign=0 fn=2 fp=0
- evasion_dmarc_bestguesspass: total=1 malicious=1 benign=0 fn=1 fp=0
- evasion_header_parse: total=1 malicious=1 benign=0 fn=1 fp=0
- evasion_punycode: total=1 malicious=1 benign=0 fn=1 fp=0
- evasion_replyto_same_domain: total=1 malicious=1 benign=0 fn=1 fp=0
- executive_free_domain: total=2 malicious=2 benign=0 fn=1 fp=0
- homograph: total=1 malicious=1 benign=0 fn=0 fp=0
- reply_to_trap: total=1 malicious=1 benign=0 fn=0 fp=0
- return_path_mismatch: total=1 malicious=1 benign=0 fn=0 fp=0