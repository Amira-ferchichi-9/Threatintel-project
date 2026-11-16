import os
from dotenv import load_dotenv
load_dotenv()
# push_model.py
from huggingface_hub import HfApi, login, create_repo

login(token=os.getenv("HF_TOKEN"))  # ← ton vrai token complet ici

api = HfApi()

# Recrée le repo s'il n'existe plus
create_repo(
    repo_id   = "Amira789/distilbert-phishing-pfa2",
    repo_type = "model",
    exist_ok  = True,
)
print("✓ Repo vérifié/créé")

api.upload_folder(
    folder_path = "./distilbert-threatintel",
    repo_id     = "Amira789/distilbert-phishing-pfa2",
    repo_type   = "model",
)
print("✓ Pushé → https://huggingface.co/Amira789/distilbert-phishing-pfa2")
