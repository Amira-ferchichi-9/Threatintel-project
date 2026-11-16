# Rapport blindspots NLP/BEC

Date: 2026-04-18T18:23:10
Matrice [[TN, FP], [FN, TP]]: [[6, 2], [0, 8]]
Metrics: accuracy=0.875, precision=0.800, recall=1.000, f1=0.889, tp=8, tn=6, fp=2, fn=0

## False negatives
- Aucun

## False positives
- NB-B-003 | score=70 | Customer support neutral | RoBERTa neutralisé (texte court : 10 mots) | DistilBERT : SAFE (99.8%) [sem] | BEC HIGH=['updated banking details', 'update your payment'] LOW=['dear customer'] IMPERSONATE=[]
- NB-B-005 | score=60 | Automated no-reply | RoBERTa neutralisé (texte court : 11 mots) | DistilBERT : PHISHING (93.0%) [sem] | BEC HIGH=['reply only to me'] LOW=[] IMPERSONATE=['reply only to me']