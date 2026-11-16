# generate_bec_synthetic.py
import random
import pandas as pd

random.seed(42)

AMOUNTS    = ["$12,500", "$48,500", "$73,200", "$102,000", "$28,750", "$55,000"]
BANKS      = ["First International Bank", "Global Trust Bank", "Continental Finance", "Meridian Bank"]
NAMES      = ["Sarah", "Michael", "James", "Emma", "David", "Lisa", "Robert"]
CEO_NAMES  = ["John Smith", "Mark Johnson", "Robert Chen", "Patricia Davis"]
COMPANIES  = ["TechCorp", "GlobalSoft", "InnovateCo", "DataSystems"]

BEC_TEMPLATES = [
    # Wire transfer
    lambda: f"Hi {random.choice(NAMES)}, I need you to process an urgent wire transfer of {random.choice(AMOUNTS)} to our new vendor account. This is time-sensitive and must be completed before end of business today. Please do not discuss this with anyone else in the office. Bank: {random.choice(BANKS)}, Account: {random.randint(1000,9999)}-{random.randint(1000,9999)}-{random.randint(1000,9999)}, Routing: {random.randint(100000000,999999999)}. Best regards, {random.choice(CEO_NAMES)}, CFO",
    # Gift card
    lambda: f"Hello, I need a favor. Can you purchase {random.choice([5,10,20])} x $100 {random.choice(['Google Play','Amazon','iTunes'])} gift cards and send me the codes? Keep this confidential, I will explain later. Thank you, {random.choice(CEO_NAMES)}",
    # Payment update
    lambda: f"Please be advised that our payment details have changed effective immediately. New bank: {random.choice(BANKS)}, Account: {random.randint(10000000,99999999)}, IBAN: GB{random.randint(10,99)}MIDL{random.randint(1000000000000,9999999999999)}. Please update your records and process all pending invoices to the new account. Do not use the old banking details.",
    # Credential phish
    lambda: f"Dear {random.choice(NAMES)}, Your {random.choice(COMPANIES)} account password has expired. You must verify your identity now to avoid suspension. Click the link to update your billing information. This is urgent and requires immediate action. Your account will be suspended in 24 hours.",
    # Authority pressure
    lambda: f"This is a personal request from the CEO. I need you to process this payment immediately: {random.choice(AMOUNTS)} to account {random.randint(1000000,9999999)}. This is confidential — do not loop in finance or discuss with anyone before completion. I will explain everything after. Complete before close of business.",
]

LEGIT_TEMPLATES = [
    lambda: f"Dear {random.choice(NAMES)}, Thank you for applying to our company. We have received your application and our team will review it shortly. We will be in touch within 5 business days. Best regards, The HR Team",
    lambda: f"Hi {random.choice(NAMES)}, This is a reminder about tomorrow's team meeting at 10:00 AM. Please find the agenda attached. See you there! Best, {random.choice(NAMES)}",
    lambda: f"Your order #{random.randint(10000,99999)} has been shipped. Expected delivery: {random.randint(2,5)} business days. Track your package using the link in your account. Thank you for your purchase.",
    lambda: f"Dear colleague, We are pleased to invite you to our annual conference on {random.choice(['March','April','May'])} {random.randint(10,28)}. Registration is free. Please confirm your attendance by replying to this email.",
    lambda: f"Hello {random.choice(NAMES)}, Your password was recently changed. If you did not make this change, please contact our support team. This is an automated notification. Do not reply to this email.",
]

bec_rows   = [{"text": t(), "label": 1} for t in BEC_TEMPLATES for _ in range(200)]
legit_rows = [{"text": t(), "label": 0} for t in LEGIT_TEMPLATES for _ in range(200)]

df = pd.DataFrame(bec_rows + legit_rows).sample(frac=1, random_state=42)
df.to_csv("data/bec_synthetic.csv", index=False)
print(f"BEC synthétique : {len(df)} exemples ({sum(df.label==1)} BEC, {sum(df.label==0)} legit)")