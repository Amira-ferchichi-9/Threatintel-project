from transformers import pipeline

print('=== TEST MODELE LOCAL ===')
clf_local = pipeline('text-classification', model='./models/distilbert-phishing-finetuned')
tests = [
    'Verify your account now. Enter your password immediately.',
    'Bonjour, merci pour votre candidature. Cordialement.',
]
for t in tests:
    r = clf_local(t[:512])[0]
    label = r['label']
    score = r['score']
    print(f'Label: {label:<15} Score: {score:.3f} | {t[:50]}')
