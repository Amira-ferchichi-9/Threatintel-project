# Rapport stress test agent_auth

Date: 2026-04-18T17:54:21
Cas: 29 (malicious=18, benign=11)

## Performance globale
- Confusion matrix [[TN, FP], [FN, TP]]: [[11, 0], [0, 18]]
- Metrics: accuracy=1.000, precision=1.000, recall=1.000, f1=1.000, tp=18, tn=11, fp=0, fn=0

## Faiblesses et vulnerabilites detectees
- Aucune vulnerabilite evidente sur ce lot

## False negatives (attaques ratees)
- Aucun

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
- evasion_cousin_root: total=1 malicious=1 benign=0 fn=0 fp=0
- evasion_display_obfuscation: total=2 malicious=2 benign=0 fn=0 fp=0
- evasion_dmarc_bestguesspass: total=1 malicious=1 benign=0 fn=0 fp=0
- evasion_header_parse: total=1 malicious=1 benign=0 fn=0 fp=0
- evasion_punycode: total=1 malicious=1 benign=0 fn=0 fp=0
- evasion_replyto_same_domain: total=1 malicious=1 benign=0 fn=0 fp=0
- executive_free_domain: total=2 malicious=2 benign=0 fn=0 fp=0
- homograph: total=1 malicious=1 benign=0 fn=0 fp=0
- reply_to_trap: total=1 malicious=1 benign=0 fn=0 fp=0
- return_path_mismatch: total=1 malicious=1 benign=0 fn=0 fp=0