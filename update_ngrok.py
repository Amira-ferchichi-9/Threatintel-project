import os
from dotenv import load_dotenv
load_dotenv()
"""
update_ngrok.py — Demarre ngrok si necessaire, recupere l'URL et met a jour le Logic App.
Lancer depuis n'importe quel terminal :
    python update_ngrok.py
"""
import time
import json
import subprocess
import urllib.request
import os
import sys

SUBSCRIPTION  = os.getenv("AZURE_SUBSCRIPTION_ID")
RESOURCE_GROUP = "PFA_Email_Sandbox_RG"
LOGIC_APP     = "la-threatintel-gmail"
API_VERSION   = "2019-05-01"
NGROK_PORT    = 8000

# Chemin ngrok connu apres installation winget
NGROK_FALLBACK = (
    r"C:\Users\amira\AppData\Local\Microsoft\WinGet\Packages"
    r"\Ngrok.Ngrok_Microsoft.Winget.Source_8wekyb3d8bbwe\ngrok.exe"
)


def find_ngrok() -> str:
    """Retourne le chemin vers ngrok.exe (PATH ou fallback)."""
    import shutil
    found = shutil.which("ngrok")
    if found:
        return found
    if os.path.exists(NGROK_FALLBACK):
        return NGROK_FALLBACK
    raise RuntimeError(
        "ngrok introuvable. Installe-le avec : winget install ngrok.ngrok"
    )


def is_ngrok_running() -> bool:
    try:
        with urllib.request.urlopen("http://localhost:4040/api/tunnels", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def start_ngrok(ngrok_exe: str):
    print(f"  Demarrage ngrok sur le port {NGROK_PORT}...")
    subprocess.Popen(
        [ngrok_exe, "http", str(NGROK_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )
    # Attendre que l'API locale soit prete
    for i in range(15):
        time.sleep(2)
        if is_ngrok_running():
            print("  ngrok demarre.")
            return
        print(f"  Attente demarrage... ({i+1}/15)")
    raise RuntimeError("ngrok n'a pas demarre apres 30 secondes.")


def get_ngrok_url() -> str:
    with urllib.request.urlopen("http://localhost:4040/api/tunnels", timeout=5) as r:
        data = json.loads(r.read())
    for t in data.get("tunnels", []):
        if t.get("proto") == "https":
            return t["public_url"]
    raise RuntimeError("Aucun tunnel HTTPS trouve dans ngrok.")


def az(*args) -> subprocess.CompletedProcess:
    """Lance une commande az avec shell=True (necessaire sur Windows pour az.cmd)."""
    cmd = "az " + " ".join(str(a) for a in args)
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding="utf-8")


def update_logic_app(ngrok_url: str) -> str:
    show = az("logic", "workflow", "show",
              "--resource-group", RESOURCE_GROUP,
              "--name", LOGIC_APP, "-o", "json")
    if show.returncode != 0:
        raise RuntimeError(f"az logic workflow show a echoue : {show.stderr}")

    wf = json.loads(show.stdout)
    wf["parameters"]["backendApiUrl"]["value"] = ngrok_url

    put_body = {
        "location": wf["location"],
        "properties": {
            "state": "Enabled",
            "definition": wf["definition"],
            "parameters": wf["parameters"],
        }
    }

    import tempfile
    tmp = os.path.join(tempfile.gettempdir(), "la_update.json")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(put_body, f)

    uri = (
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION}"
        f"/resourceGroups/{RESOURCE_GROUP}"
        f"/providers/Microsoft.Logic/workflows/{LOGIC_APP}"
        f"?api-version={API_VERSION}"
    )
    result = az("rest", "--method", "PUT", "--uri", uri,
                "--body", f"@{tmp}",
                "--query", "properties.parameters.backendApiUrl.value", "-o", "tsv")
    if result.returncode != 0:
        raise RuntimeError(f"Mise a jour Logic App echouee : {result.stderr}")
    return result.stdout.strip()


if __name__ == "__main__":
    print("=== ThreatIntel — Demarrage ngrok + Logic App ===\n")

    ngrok_exe = find_ngrok()
    print(f"ngrok trouve : {ngrok_exe}")

    if is_ngrok_running():
        print("ngrok deja en cours d'execution.")
    else:
        start_ngrok(ngrok_exe)

    url = get_ngrok_url()
    print(f"\nURL publique : {url}")

    print("Mise a jour Logic App Azure...")
    updated = update_logic_app(url)
    print(f"Logic App -> {updated}")
    print("\nOK — Chaine complete operationnelle.")
    print(f"   Gmail -> Logic App -> {url}/analyze -> FastAPI -> Cosmos DB -> VS Code")

