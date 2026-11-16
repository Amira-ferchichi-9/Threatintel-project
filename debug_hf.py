from transformers import pipeline
print('=== TEST MODELE HUGGINGFACE ===')
clf = pipeline('text-classification', model='Amira789/distilbert-phishing-pfa2')
tests = [
    'Verify your account now. Enter your password immediately.',
    'Bonjour, merci pour votre candidature. Cordialement.',
]
for t in tests:
    r = clf(t[:512])[0]
    label = r['label']
    score = r['score']
    print(f'Label: {label:<15} Score: {score:.3f} | {t[:50]}')
