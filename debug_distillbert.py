# debug_distilbert.py
from transformers import pipeline

clf = pipeline("text-classification", model="Amira789/distilbert-phishing-pfa2")

tests = [
    "Verify your account now. Enter your password immediately.",
    "Bonjour, nous avons bien reçu votre candidature. Cordialement.",
    "Click here to confirm your identity. Your account will be suspended.",
]

for t in tests:
    result = clf(t[:512])[0]
    print(f"Label: {result['label']:<15} Score: {result['score']:.3f} | {t[:60]}")