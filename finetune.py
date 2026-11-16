# finetune.py

import pandas as pd
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer
)
import numpy as np
from sklearn.metrics import accuracy_score, f1_score
import torch

# ─────────────────────────────────────────────────────────
# 1. DATASET
# ─────────────────────────────────────────────────────────
import pandas as pd

df = pd.read_csv("phishing_email.csv")
print(df.columns.tolist())
print(df.head(2))
print(f"Total : {len(df)} emails")

dataset  = Dataset.from_pandas(df)
split    = dataset.train_test_split(test_size=0.2, seed=42)
train_ds = split["train"]
test_ds  = split["test"]


# Split train/test 80-20
split    = dataset.train_test_split(test_size=0.2, seed=42)
train_ds = split["train"]
test_ds  = split["test"]

print(f"Train : {len(train_ds)} exemples")
print(f"Test  : {len(test_ds)} exemples")

# ─────────────────────────────────────────────────────────
# 2. TOKENIZER
# ─────────────────────────────────────────────────────────
MODEL_BASE = "distilbert-base-multilingual-cased"
tokenizer  = AutoTokenizer.from_pretrained(MODEL_BASE)

def tokenize(batch):
    return tokenizer(
        batch["text_combined"],
        truncation=True,
        padding="max_length",
        max_length=256
    )
train_ds = train_ds.map(tokenize, batched=True)
test_ds  = test_ds.map(tokenize,  batched=True)

train_ds.set_format("torch", columns=["input_ids", "attention_mask", "label"])
test_ds.set_format( "torch", columns=["input_ids", "attention_mask", "label"])

# ─────────────────────────────────────────────────────────
# 3. MODÈLE
# ─────────────────────────────────────────────────────────
model = AutoModelForSequenceClassification.from_pretrained(
    MODEL_BASE,
    num_labels=2,
    id2label={0: "SAIN", 1: "PHISHING"},
    label2id={"SAIN": 0, "PHISHING": 1}
)

# ─────────────────────────────────────────────────────────
# 4. MÉTRIQUES
# ─────────────────────────────────────────────────────────
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    predictions    = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, predictions),
        "f1":       f1_score(labels, predictions, average="weighted")
    }

# ─────────────────────────────────────────────────────────
# 5. ENTRAÎNEMENT
# ─────────────────────────────────────────────────────────
training_args = TrainingArguments(
    output_dir          = "./models/distilbert-phishing",
    num_train_epochs    = 5,
    per_device_train_batch_size = 8,
    per_device_eval_batch_size  = 8,
    eval_strategy       = "epoch",
    save_strategy       = "epoch",
    load_best_model_at_end = True,
    logging_steps       = 10,
    learning_rate       = 2e-5,
    weight_decay        = 0.01,
)

trainer = Trainer(
    model           = model,
    args            = training_args,
    train_dataset   = train_ds,
    eval_dataset    = test_ds,
    compute_metrics = compute_metrics,
)

print("\n[🔥] Fine-tuning en cours...")
trainer.train()

# ─────────────────────────────────────────────────────────
# 6. SAUVEGARDE
# ─────────────────────────────────────────────────────────
model.save_pretrained("./models/distilbert-phishing-finetuned")
tokenizer.save_pretrained("./models/distilbert-phishing-finetuned")
print("\n✅ Modèle sauvegardé dans ./models/distilbert-phishing-finetuned")
