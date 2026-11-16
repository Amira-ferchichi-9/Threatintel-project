# finetune_distilbert.py — v2 adapté aux 3 datasets réels
import os
import glob
import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from torch.utils.data import Dataset
from transformers import (
    DistilBertTokenizerFast,
    DistilBertForSequenceClassification,
    TrainingArguments,
    Trainer,
    EarlyStoppingCallback,
)
import evaluate

# ════════════════════════════════════════════════════════════
# CONFIG — RTX 3050 4GB
# ════════════════════════════════════════════════════════════
MODEL_NAME   = "distilbert-base-uncased"
OUTPUT_DIR   = "./distilbert-threatintel"
HF_REPO      = "Amira789/distilbert-phishing-pfa2"
MAX_LEN      = 256
BATCH_SIZE   = 8
GRAD_ACCUM   = 4        # batch effectif = 32
EPOCHS       = 4
LR           = 2e-5
MAX_SAMPLES  = 50_000   # 25k safe + 25k threat

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Device : {device}")
if device == "cuda":
    print(f"GPU    : {torch.cuda.get_device_name(0)}")
    print(f"VRAM   : {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")


# ════════════════════════════════════════════════════════════
# 1. CHARGEMENT ET MERGE
# ════════════════════════════════════════════════════════════
print("\n─── Chargement datasets ───")
dfs = []
for f in sorted(glob.glob("data/*.csv")):
    try:
        df = pd.read_csv(f, usecols=['text', 'label'])
        df = df.dropna()
        df['label'] = df['label'].astype(int)
        df['text']  = df['text'].astype(str).str.strip()
        df = df[df['text'].str.len() > 10]
        dfs.append(df)
        print(f"  {os.path.basename(f):35s} → {len(df)} lignes "
              f"(safe={sum(df.label==0)} | threat={sum(df.label==1)})")
    except Exception as e:
        print(f"  ✗ {f} : {e}")

df_all = pd.concat(dfs, ignore_index=True)
df_all = df_all.drop_duplicates(subset='text')
print(f"\n  Total brut : {len(df_all)} | "
      f"safe={sum(df_all.label==0)} | threat={sum(df_all.label==1)}")


# ════════════════════════════════════════════════════════════
# 2. ÉQUILIBRAGE — 25k safe + 25k threat
# ════════════════════════════════════════════════════════════
print("\n─── Équilibrage ───")
df_safe   = df_all[df_all.label == 0]
df_threat = df_all[df_all.label == 1]

n_target  = min(len(df_safe), len(df_threat), MAX_SAMPLES // 2)
df_safe   = df_safe.sample(n_target, random_state=42)
df_threat = df_threat.sample(n_target, random_state=42)

df_balanced = pd.concat([df_safe, df_threat]).sample(frac=1, random_state=42)
print(f"  Dataset équilibré : {len(df_balanced)} exemples "
      f"(safe={n_target} | threat={n_target})")


# ════════════════════════════════════════════════════════════
# 3. SPLIT 80 / 10 / 10
# ════════════════════════════════════════════════════════════
train_df, temp_df = train_test_split(
    df_balanced, test_size=0.2, random_state=42, stratify=df_balanced['label']
)
val_df, test_df = train_test_split(
    temp_df, test_size=0.5, random_state=42, stratify=temp_df['label']
)
print(f"\n  Train : {len(train_df)} | Val : {len(val_df)} | Test : {len(test_df)}")


# ════════════════════════════════════════════════════════════
# 4. TOKENISATION
# ════════════════════════════════════════════════════════════
print("\n─── Tokenisation (ça peut prendre 1-2 min) ───")
tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)

class EmailDataset(Dataset):
    def __init__(self, df: pd.DataFrame):
        self.encodings = tokenizer(
            df['text'].tolist(),
            truncation=True,
            padding=True,
            max_length=MAX_LEN,
            return_tensors='pt'
        )
        self.labels = torch.tensor(df['label'].tolist(), dtype=torch.long)

    def __len__(self):
        return len(self.labels)

    def __getitem__(self, idx):
        return {
            'input_ids':      self.encodings['input_ids'][idx],
            'attention_mask': self.encodings['attention_mask'][idx],
            'labels':         self.labels[idx],
        }

train_dataset = EmailDataset(train_df.reset_index(drop=True))
val_dataset   = EmailDataset(val_df.reset_index(drop=True))
test_dataset  = EmailDataset(test_df.reset_index(drop=True))
print("  ✓ Datasets tokenisés")


# ════════════════════════════════════════════════════════════
# 5. MODÈLE
# ════════════════════════════════════════════════════════════
print("\n─── Chargement modèle ───")
model = DistilBertForSequenceClassification.from_pretrained(
    MODEL_NAME,
    num_labels=2,
    id2label={0: "SAFE", 1: "PHISHING"},
    label2id={"SAFE": 0, "PHISHING": 1},
)
model.to(device)
print(f"  ✓ Modèle chargé sur {device}")


# ════════════════════════════════════════════════════════════
# 6. MÉTRIQUES
# ════════════════════════════════════════════════════════════
accuracy_metric = evaluate.load("accuracy")
f1_metric       = evaluate.load("f1")

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds  = np.argmax(logits, axis=-1)
    acc    = accuracy_metric.compute(predictions=preds, references=labels)['accuracy']
    f1     = f1_metric.compute(predictions=preds, references=labels, average='weighted')['f1']
    return {"accuracy": acc, "f1": f1}


# ════════════════════════════════════════════════════════════
# 7. TRAINING ARGS — optimisé RTX 3050
# ════════════════════════════════════════════════════════════
training_args = TrainingArguments(
    output_dir                  = OUTPUT_DIR,
    num_train_epochs            = EPOCHS,
    per_device_train_batch_size = BATCH_SIZE,
    per_device_eval_batch_size  = BATCH_SIZE,
    gradient_accumulation_steps = GRAD_ACCUM,
    warmup_ratio                = 0.1,
    weight_decay                = 0.01,
    learning_rate               = LR,
    eval_strategy               = "epoch",
    save_strategy               = "epoch",
    load_best_model_at_end      = True,
    metric_for_best_model       = "f1",
    fp16                        = True,
    dataloader_num_workers      = 0,      # obligatoire Windows
    logging_steps               = 100,
    save_total_limit            = 2,      # garde seulement les 2 meilleurs checkpoints
    report_to                   = "none",
    push_to_hub                 = False,
)

trainer = Trainer(
    model           = model,
    args            = training_args,
    train_dataset   = train_dataset,
    eval_dataset    = val_dataset,
    compute_metrics = compute_metrics,
    callbacks       = [EarlyStoppingCallback(early_stopping_patience=2)],
)


# ════════════════════════════════════════════════════════════
# 8. ENTRAÎNEMENT
# ════════════════════════════════════════════════════════════
print("\n─── Fine-tuning DistilBERT ───")
print(f"  {len(train_df)} exemples | {EPOCHS} epochs | "
      f"batch={BATCH_SIZE} x grad_accum={GRAD_ACCUM} | fp16=True | max_len={MAX_LEN}")
print("  Durée estimée sur RTX 3050 : ~25-40 min\n")

trainer.train()


# ════════════════════════════════════════════════════════════
# 9. ÉVALUATION FINALE
# ════════════════════════════════════════════════════════════
print("\n─── Évaluation finale sur test set ───")
preds_output = trainer.predict(test_dataset)
preds        = np.argmax(preds_output.predictions, axis=-1)
labels       = preds_output.label_ids

print(classification_report(labels, preds, target_names=["SAFE", "PHISHING"]))
print("Matrice de confusion :")
print(confusion_matrix(labels, preds))


# ════════════════════════════════════════════════════════════
# 10. SAUVEGARDE LOCALE
# ════════════════════════════════════════════════════════════
print(f"\n─── Sauvegarde → {OUTPUT_DIR} ───")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)
print("  ✓ Modèle sauvegardé localement")


# ════════════════════════════════════════════════════════════
# 11. PUSH HUGGINGFACE
# ════════════════════════════════════════════════════════════
push = input(f"\nPusher vers HuggingFace ({HF_REPO}) ? [o/N] : ").strip().lower()
if push == 'o':
    from huggingface_hub import HfApi
    api = HfApi()
    api.upload_folder(
        folder_path = OUTPUT_DIR,
        repo_id     = HF_REPO,
        repo_type   = "model",
    )
    print(f"  ✓ Pushé → https://huggingface.co/{HF_REPO}")
else:
    print("  Push ignoré.")