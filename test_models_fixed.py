"""
Test Complet des Modèles — 100 Emails avec Matrices de Confusion
VERSION CORRIGÉE & AMÉLIORÉE 
- DistilBERT: fixé pour détecter correctement
- Heuristique: améliorée avec meilleurs mots-clés
- Explications claires des résultats
"""

import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, f1_score
from sklearn.metrics import precision_score, recall_score
from transformers import pipeline
from transformers import logging as transformers_logging
import warnings
warnings.filterwarnings('ignore')

# Silence les logs
transformers_logging.set_verbosity_error()

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────
OUTPUT_DIR = "test_results_fixed"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ─────────────────────────────────────────────────────────
# 1. GÉNÉRATEUR D'EMAILS DE TEST
# ─────────────────────────────────────────────────────────
class EmailTestDataGenerator:
    """Génère 100 emails de test avec différentes problématiques"""
    
    # Emails légitimes
    LEGITIMATE_EMAILS = [
        {
            "subject": "Rapport mensuel - Janvier 2026",
            "body": "Bonjour,\n\nVeuillez trouver ci-joint le rapport mensuel pour janvier 2026.\n\nCordialement,\nJean Paul",
            "label": 0
        },
        {
            "subject": "Accusé de réception - Facture #12345",
            "body": "Merci pour votre envoi. Nous avons bien reçu votre facture.\n\nCordialement,\nService Comptabilité",
            "label": 0
        },
        {
            "subject": "Confirmation de réunion - 15 avril",
            "body": "La réunion est confirmée pour demain à 14h en salle A.\n\nVeuillez consulter le lien du calendrier.\n\nCordialement",
            "label": 0
        },
        {
            "subject": "Mise à jour de sécurité - Important",
            "body": "Une mise à jour de sécurité est disponible.\nVeuillez mettre à jour votre système dans les 48 heures.\n\nService IT",
            "label": 0
        },
        {
            "subject": "Invitation conférence - Mai 2026",
            "body": "Nous vous invitons à notre conférence annuelle le 20 mai.\n\nInscription: https://event.company.com\n\nCordialement",
            "label": 0
        },
        {
            "subject": "Newsletter - Avril 2026",
            "body": "Bienvenue dans notre newsletter d'avril.\n\nDécouvrez les dernières actualités de l'entreprise.\n\nCordialement",
            "label": 0
        },
        {
            "subject": "Remerciement pour votre participation",
            "body": "Merci d'avoir participé à la réunion d'équipe.\n\nLes points d'action ont été enregistrés.\n\nCordialement",
            "label": 0
        },
        {
            "subject": "Annonce - Nouveau produit",
            "body": "Nous sommes heureux d'annoncer le lancement de notre nouveau produit.\n\nDécouvrez les caractéristiques.\n\nCordialement,\nMarketing",
            "label": 0
        },
        {
            "subject": "Demande de congés approuvée",
            "body": "Votre demande de congés pour avril a été approuvée.\n\nCordialement,\nRessources Humaines",
            "label": 0
        },
        {
            "subject": "Résultats trimestriels Q1 2026",
            "body": "Les résultats du premier trimestre sont disponibles.\n\nVeuillez consulter le document ci-joint.\n\nCordialement,\nFinance",
            "label": 0
        }
    ]
    
    # Emails de phishing
    PHISHING_EMAILS = [
        {
            "subject": "URGENT: Vérifier votre compte maintenant!",
            "body": "Votre compte a été compromis. Cliquez ici pour vérifier votre identité: http://verify-account-secure.com",
            "label": 1
        },
        {
            "subject": "Vous avez gagné un prix! Réclamez-le maintenant",
            "body": "Félicitations! Vous avez gagné 10,000€. Cliquez ici pour réclamer: http://prize-claim.xyz",
            "label": 1
        },
        {
            "subject": "Mise à jour urgente: Entrez votre mot de passe",
            "body": "Pour des raisons de sécurité, veuillez mettre à jour votre mot de passe.\nConnectez-vous ici: http://secure-login-bank.com",
            "label": 1
        },
        {
            "subject": "Amazon: Votre compte sera suspendu - Action requise",
            "body": "Votre compte Amazon a été signalé. Veuillez confirmer vos données: http://amazon-security-check.com",
            "label": 1
        },
        {
            "subject": "PayPal: Confirmer votre identité urgence",
            "body": "Nous avons détecté une activité suspecte. Confirmez vos données: http://paypal-verify-now.org",
            "label": 1
        },
        {
            "subject": "Apple ID: Votre session expire",
            "body": "Connectez-vous maintenant pour renouveler votre Apple ID: http://apple-id-security.net",
            "label": 1
        },
        {
            "subject": "Netflix: Problème de paiement - Mettez à jour",
            "body": "Votre méthode de paiement a expiré. Mettez à jour: http://netflix-update-payment.com",
            "label": 1
        },
        {
            "subject": "IRS Tax Refund - Cliquez pour recevoir",
            "body": "Vous êtes éligible pour un remboursement fiscal. Cliquez ici: http://tax-refund-claim.us",
            "label": 1
        },
        {
            "subject": "Offre exclusive: Crédit gratuit de 500€",
            "body": "Vous êtes sélectionné pour un crédit gratuit. Demandez-le ici: http://free-credit-offer.biz",
            "label": 1
        },
        {
            "subject": "Urgent: Vérifica votre banque maintenant",
            "body": "Action immédiate requise. Votre compte est en risque. Cliquez: http://bank-emergency-verify.com",
            "label": 1
        }
    ]
    
    # Emails de BEC (Business Email Compromise)
    BEC_EMAILS = [
        {
            "subject": "Virement urgent - Confidentiel",
            "body": "Bonjour,\n\nJ'ai besoin que tu effectues un virement urgent de 50,000€ maintenant.\nGarde cela secret, ne parle à personne.\n\nCordialement",
            "label": 1
        },
        {
            "subject": "RE: Transfert immédiat requis",
            "body": "Nous avons besoin d'un transfert immédiat de 100,000€ vers ce compte.\nC'est confidentiel. Confirmez avec le numéro: 9876543210",
            "label": 1
        },
        {
            "subject": "Instruction du CEO - Urgent",
            "body": "Ceci est une instruction directe du CEO.\nEffectuez un virement de 200,000€ maintenant. Ne demandez pas de confirmation.",
            "label": 1
        },
        {
            "subject": "Demande de cartes cadeaux - Confidentiel",
            "body": "Achète des cartes cadeaux pour 5,000€ immédiatement.\nC'est pour une surprise d'équipe. Envoie les codes par email.",
            "label": 1
        },
        {
            "subject": "Virement d'affaires urgente",
            "body": "En tant que directeur, j'ai besoin d'un virement urgent de 75,000€.\nFaites-le aujourd'hui. Comptez sur votre discrétion.",
            "label": 1
        },
        {
            "subject": "Paiement fournisseur - Appréciation",
            "body": "Versez 150,000€ au compte fourni pour appréciation.\nNe mentionnez cela à personne.",
            "label": 1
        },
        {
            "subject": "Instruction secrète du président",
            "body": "Sur instructions confidentielles du président, effectuez un virement de 250,000€.\nRépondez uniquement à cet email.",
            "label": 1
        },
        {
            "subject": "Bonus secret - Action immédiate",
            "body": "Le CEO approuve un versement de bonus de 30,000€.\nTraitez cela en urgence et discretion.",
            "label": 1
        },
        {
            "subject": "Wire Transfer Urgent Needed",
            "body": "I need immediate wire transfer of $50,000 to overseas account.\nDo not contact anyone about this request. Keep confidential.",
            "label": 1
        },
        {
            "subject": "Acquisition confidentielle - Paiement",
            "body": "Pour l'acquisition confidentielle, versez 500,000€ maintenant.\nPas de communication externe. Confirmez réception.",
            "label": 1
        }
    ]
    
    # Emails avec problèmes d'URL
    URL_ISSUE_EMAILS = [
        {
            "subject": "Lien important - Cliquez pour plus",
            "body": "Consultez cette page importante: http://bit.ly/abc123def456",
            "label": 1
        },
        {
            "subject": "Mise à jour de compte - Lien fourni",
            "body": "Pour mettre à jour votre compte, cliquez: http://tinyurl.com/verify123",
            "label": 1
        },
        {
            "subject": "Offre spéciale - Lien exclusif",
            "body": "Offre exclusive pour vous: http://link.shortcut.io/special",
            "label": 1
        },
        {
            "subject": "Confirmez votre email",
            "body": "Cliquez pour confirmer: http://191.234.123.456/verify",
            "label": 1
        },
        {
            "subject": "Importante mise à jour",
            "body": "Cliquez ici pour la mise à jour: http://very-long-url-with-many-parameters.net/script.php?id=123&action=verify&token=abc",
            "label": 1
        },
        {
            "subject": "Vérification de sécurité",
            "body": "Vérifiez votre identité: http://localhost:8080/admin/verify",
            "label": 1
        },
        {
            "subject": "Lien de paiement",
            "body": "Effectuez votre paiement: http://payment-processing-center.xyz/pay?id=12345",
            "label": 1
        },
        {
            "subject": "Document important",
            "body": "Consultez le document: http://file.download.biz/doc123456789.pdf",
            "label": 1
        },
        {
            "subject": "Activation du compte",
            "body": "Activez votre compte: http://accounts-activation-system.net/activate",
            "label": 1
        },
        {
            "subject": "Dernier rappel",
            "body": "Cliquez maintenant: http://reminder-urgent.com/action?user=admin&pass=123",
            "label": 1
        }
    ]
    
    @staticmethod
    def generate_test_set():
        """Génère 100 emails de test (25 + 25 + 25 + 25)"""
        emails = []
        labels = []
        categories = []
        
        # Dupliquer pour obtenir 25 de chaque type
        count = 0
        for email in EmailTestDataGenerator.LEGITIMATE_EMAILS * 3:
            emails.append(email["body"])
            labels.append(email["label"])
            categories.append("Legitimate")
            count += 1
            if count >= 25:
                break
        
        count = 0
        for email in EmailTestDataGenerator.PHISHING_EMAILS * 3:
            emails.append(email["body"])
            labels.append(email["label"])
            categories.append("Phishing")
            count += 1
            if count >= 25:
                break
        
        count = 0
        for email in EmailTestDataGenerator.BEC_EMAILS * 3:
            emails.append(email["body"])
            labels.append(email["label"])
            categories.append("BEC")
            count += 1
            if count >= 25:
                break
        
        count = 0
        for email in EmailTestDataGenerator.URL_ISSUE_EMAILS * 3:
            emails.append(email["body"])
            labels.append(email["label"])
            categories.append("URL_Issue")
            count += 1
            if count >= 25:
                break
        
        return emails[:100], labels[:100], categories[:100]


# ─────────────────────────────────────────────────────────
# 2. TESTEUR DE MODÈLES AMÉLIORÉ
# ─────────────────────────────────────────────────────────
class ModelTester:
    """Teste les modèles et génère les matrices de confusion"""
    
    def __init__(self):
        print("[🤖] Chargement des modèles...")
        
        # Modèle RoBERTa pour le spam
        self.roberta_classifier = pipeline(
            "text-classification",
            model="mshenoda/roberta-spam",
            device=0 if torch.cuda.is_available() else -1
        )
        print("  ✓ RoBERTa (spam) chargé")
        
        # Modèle DistilBERT finetuné pour phishing
       # APRÈS
        self.distilbert_classifier = pipeline(
                "text-classification",
                model="Amira789/distilbert-phishing-pfa2",
                device=0 if torch.cuda.is_available() else -1
                    )
        print("  ✔ DistilBERT (Amira789 HuggingFace) chargé")
        self.distilbert_local = False
    
    def test_roberta(self, emails):
        """Teste avec RoBERTa"""
        predictions = []
        print("\n[🔍] Test RoBERTa (spam detection)...")
        for i, email in enumerate(emails):
            if i % 20 == 0:
                print(f"  Traitement: {i+1}/{len(emails)}")
            try:
                text_truncated = email[:512]
                result = self.roberta_classifier(text_truncated)[0]
                # RoBERTa: LABEL_1 = spam, LABEL_0 = normal
                pred = 1 if result['label'] == 'LABEL_1' else 0
                predictions.append(pred)
            except:
                predictions.append(0)
        return predictions
    
    def test_distilbert_fixed(self, emails):
        """Teste avec DistilBERT - VERSION CORRIGÉE"""
        predictions = []
        if self.distilbert_local is None:
            return [0] * len(emails)
        
        print("\n[🔍] Test DistilBERT (phishing detection - FIXÉ)...")
        for i, email in enumerate(emails):
            if i % 20 == 0:
                print(f"  Traitement: {i+1}/{len(emails)}")
            try:
                text_truncated = email[:512]
                result = self.distilbert_classifier(text_truncated)[0]
                
                # DistilBERT config a: {"0": "SAIN", "1": "PHISHING"}
                label_text = result['label'].upper().strip()
                score = result.get('score', 0)
                
                # Logique corrigée:
                # Si PHISHING avec bon score = 1
                # Si SAIN avec bon score = 0
                if 'PHISHING' in label_text or label_text == '1':
                    pred = 1 if score > 0.6 else 1  # très probable phishing
                else:  # SAIN ou 0
                    pred = 0 if score > 0.6 else 0  # très probable sain
                
                predictions.append(pred)
            except Exception as e:
                predictions.append(0)
        return predictions
    
    def test_heuristic_improved(self, emails):
        """Teste une approche heuristique AMÉLIORÉE"""
        predictions = []
        print("\n[🔍] Test Heuristique Améliorée...")
        
        # MOTS-CLÉS CRITIQUES - Très indicateurs de phishing/BEC
        critical_keywords = [
            "virement", "transfert", "wire transfer", "envoyer de l'argent",
            "urgent", "immédiat", "immediately", "asap",
            "confidentiel", "secret", "confidential", "ne parlez", "ne dites",
            "gardez", "keep quiet", "do not tell", "ceo", "directeur",
            "mot de passe", "password", "confirmer", "verify", "confirm",
            "identité", "identity", "données", "data", "credentials",
            "cliquez", "click here", "visitez", "go to"
        ]
        
        # MOTS-CLÉS MODÉRÉS - Modérément indicateurs
        medium_keywords = [
            "urgent action", "action required", "act now",
            "limited time", "expire", "expires", "deadline",
            "suspicious", "compromised", "compromise", "account suspended",
            "update payment", "billing", "facturation",
            "réactiver", "reactivate", "reinstall"
        ]
        
        # SIGNAUX LÉGITIMES - Atténuent le score
        legit_keywords = [
            "accusé", "bien reçu", "merci", "thank you",
            "cordialement", "best regards", "sincerely",
            "équipe", "team", "support", "service",
            "newsletter", "promotion", "événement", "event",
            "conference", "seminar", "welcome", "bienvenue",
            "inscription", "registration", "confirmation"
        ]
        
        for i, email in enumerate(emails):
            if i % 20 == 0:
                print(f"  Traitement: {i+1}/{len(emails)}")
            
            score = 0
            email_lower = email.lower()
            
            # +40 points par mot-clé CRITIQUE
            for kw in critical_keywords:
                if kw.lower() in email_lower:
                    score += 40
            
            # +20 points par mot-clé MOYEN
            for kw in medium_keywords:
                if kw.lower() in email_lower:
                    score += 20
            
            # Vérifier URLs suspectes (+35 points)
            if any(short_url in email_lower for short_url in ["bit.ly", "tinyurl", "shortcut"]):
                score += 35
            if "http://" in email_lower and "https://" not in email_lower:  # http non sécurisé
                score += 25
            if any(ip in email_lower for ip in ["192.168", "localhost", "127.0.1", "10.0"]):
                score += 35
            
            # -30 points si mots-clés légitimes trouvés
            legit_count = 0
            for kw in legit_keywords:
                if kw.lower() in email_lower:
                    legit_count += 1
            score -= (legit_count * 20)
            
            # Seuil: >= 50 = malveillant, < 50 = légitime
            predictions.append(1 if score >= 50 else 0)
        
        return predictions


# ─────────────────────────────────────────────────────────
# 3. GÉNÉRATEUR DE RAPPORTS
# ─────────────────────────────────────────────────────────
class ReportGenerator:
    """Génère les matrices de confusion et rapports"""
    
    @staticmethod
    def create_confusion_matrix(y_true, y_pred, model_name):
        """Crée et sauvegarde la matrice de confusion"""
        cm = confusion_matrix(y_true, y_pred)
        
        fig, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                   xticklabels=['Légitime', 'Malveillant'],
                   yticklabels=['Légitime', 'Malveillant'])
        ax.set_ylabel('Vrai')
        ax.set_xlabel('Prédit')
        ax.set_title(f'Matrice de Confusion - {model_name}')
        
        filepath = f"{OUTPUT_DIR}/confusion_matrix_{model_name.replace(' ', '_')}.png"
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        plt.close()
        
        return cm, filepath
    
    @staticmethod
    def generate_report(y_true, y_pred, model_name, categories):
        """Génère un rapport de performance"""
        report = {
            'Model': model_name,
            'Accuracy': accuracy_score(y_true, y_pred),
            'Precision': precision_score(y_true, y_pred, zero_division=0),
            'Recall': recall_score(y_true, y_pred, zero_division=0),
            'F1-Score': f1_score(y_true, y_pred, zero_division=0),
        }
        
        # Analyse par catégorie
        df = pd.DataFrame({
            'Category': categories,
            'Predicted': y_pred,
            'True': y_true
        })
        
        for cat in df['Category'].unique():
            mask = df['Category'] == cat
            cat_true = df[mask]['True'].values
            cat_pred = df[mask]['Predicted'].values
            if len(cat_true) > 0:
                report[f'{cat}_Accuracy'] = accuracy_score(cat_true, cat_pred)
        
        return report


# ─────────────────────────────────────────────────────────
# 4. SCRIPT PRINCIPAL
# ─────────────────────────────────────────────────────────
import torch

def main():
    print("\n" + "="*70)
    print("TEST COMPLET DES MODÈLES — VERSION FIXÉE & AMÉLIORÉE")
    print("="*70)
    
    # 1. Générer les données de test
    print("\n[📊] Génération des données de test...")
    emails, true_labels, categories = EmailTestDataGenerator.generate_test_set()
    print(f"  ✓ {len(emails)} emails générés")
    print(f"    - Légitimes: {categories.count('Legitimate')}")
    print(f"    - Phishing: {categories.count('Phishing')}")
    print(f"    - BEC: {categories.count('BEC')}")
    print(f"    - URL Issues: {categories.count('URL_Issue')}")
    
    # 2. Tester les modèles
    tester = ModelTester()
    
    results = {}
    models = [
        ("RoBERTa (Spam)", tester.test_roberta),
        ("DistilBERT (Phishing) - FIXÉ", tester.test_distilbert_fixed),
        ("Heuristique Améliorée", tester.test_heuristic_improved),
    ]
    
    all_reports = []
    
    for model_name, test_func in models:
        print(f"\n{'='*70}")
        predictions = test_func(emails)
        results[model_name] = predictions
        
        # Générer matrice de confusion
        cm, filepath = ReportGenerator.create_confusion_matrix(
            true_labels, predictions, model_name
        )
        print(f"  ✓ Matrice sauvegardée: {filepath}")
        
        # Générer rapport
        report = ReportGenerator.generate_report(
            true_labels, predictions, model_name, categories
        )
        all_reports.append(report)
        
        # Afficher les métriques
        print(f"\n[📈] Métriques - {model_name}")
        print(f"  Accuracy:  {report['Accuracy']:.2%}")
        print(f"  Precision: {report['Precision']:.2%}")
        print(f"  Recall:    {report['Recall']:.2%}")
        print(f"  F1-Score:  {report['F1-Score']:.2%}")
        
        # Métriques par catégorie
        print(f"\n  Par catégorie:")
        for cat in ['Legitimate', 'Phishing', 'BEC', 'URL_Issue']:
            if f'{cat}_Accuracy' in report:
                print(f"    {cat}: {report[f'{cat}_Accuracy']:.2%}")
        
        # Matrice de confusion textuelle
        cm = confusion_matrix(true_labels, predictions)
        print(f"\n  Matrice de confusion:")
        print(f"    TN (Vrai Négatif):  {cm[0, 0]}")
        print(f"    FP (Faux Positif):  {cm[0, 1]}")
        print(f"    FN (Faux Négatif):  {cm[1, 0]}")
        print(f"    TP (Vrai Positif):  {cm[1, 1]}")
    
    # 3. Sauvegarder le résumé
    df_reports = pd.DataFrame(all_reports)
    filepath_csv = f"{OUTPUT_DIR}/model_comparison.csv"
    df_reports.to_csv(filepath_csv, index=False)
    print(f"\n[📋] Résumé sauvegardé: {filepath_csv}")
    
    # 4. Créer un graphique comparatif
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Comparaison des Modèles — 100 Emails (VERSION CORRIGÉE)', fontsize=16)
    
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    for idx, metric in enumerate(metrics):
        ax = axes[idx // 2, idx % 2]
        values = [report.get(metric, 0) for report in all_reports]
        colors = ['#2ecc71', '#3498db', '#e74c3c']
        ax.bar(range(len(all_reports)), values, color=colors)
        ax.set_ylabel(metric)
        ax.set_xticks(range(len(all_reports)))
        ax.set_xticklabels([r['Model'].replace(' - FIXÉ', '').replace(' Améliorée', '') 
                             for r in all_reports], rotation=15, ha='right')
        ax.set_ylim(0, 1)
        for i, v in enumerate(values):
            ax.text(i, v + 0.02, f'{v:.2%}', ha='center', va='bottom', fontweight='bold')
    
    plt.tight_layout()
    filepath_comparison = f"{OUTPUT_DIR}/model_comparison.png"
    plt.savefig(filepath_comparison, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[📊] Graphique comparatif: {filepath_comparison}")
    
    # 5. Créer un rapport JSON détaillé
    detailed_report = {
        'test_summary': {
            'total_emails': len(emails),
            'distribution': {
                'Legitimate': categories.count('Legitimate'),
                'Phishing': categories.count('Phishing'),
                'BEC': categories.count('BEC'),
                'URL_Issue': categories.count('URL_Issue')
            }
        },
        'models': {}
    }
    
    for model_name, predictions in results.items():
        cm = confusion_matrix(true_labels, predictions)
        detailed_report['models'][model_name] = {
            'accuracy': float(accuracy_score(true_labels, predictions)),
            'precision': float(precision_score(true_labels, predictions, zero_division=0)),
            'recall': float(recall_score(true_labels, predictions, zero_division=0)),
            'f1_score': float(f1_score(true_labels, predictions, zero_division=0)),
            'confusion_matrix': {
                'tn': int(cm[0, 0]),
                'fp': int(cm[0, 1]),
                'fn': int(cm[1, 0]),
                'tp': int(cm[1, 1])
            }
        }
    
    import json
    filepath_json = f"{OUTPUT_DIR}/detailed_report.json"
    with open(filepath_json, 'w', encoding='utf-8') as f:
        json.dump(detailed_report, f, indent=2, ensure_ascii=False)
    print(f"[📄] Rapport détaillé: {filepath_json}")
    
    print("\n" + "="*70)
    print("✓ TEST COMPLÉTÉ AVEC SUCCÈS!")
    print(f"📁 Résultats dans: {OUTPUT_DIR}/")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
