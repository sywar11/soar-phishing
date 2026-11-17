"""Prépare le laboratoire : compte propriétaire n8n et configuration GoPhish de démonstration.

    python scripts/configurer_lab.py

- n8n : crée un compte de test et écrit ses identifiants dans identifiants_lab.txt (fichier ignoré par git).
- GoPhish : crée le profil d'envoi, la page, le modèle neutre [DEMO] et les groupes Equipe A / Equipe B.
Relancer le script ne change rien à ce qui existe déjà. Uniquement pour le laboratoire local.
"""
import http.cookiejar
import json
import os
import secrets
import sqlite3
import ssl
import string
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CREDS = ROOT / "identifiants_lab.txt"
N8N = "http://localhost:5680"
GOPHISH = "http://localhost:3333/api"  # admin en http, ouvert seulement sur 127.0.0.1 (docker-compose.yml)
ctx = ssl._create_unverified_context()  # utile seulement si l'admin GoPhish repasse en https auto-signé


def call(req, opener=None):
    try:
        if opener:
            with opener.open(req, timeout=30) as f:
                return f.status, f.read().decode()
        with urllib.request.urlopen(req, timeout=30, context=ctx if req.full_url.startswith("https") else None) as f:
            return f.status, f.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:300]


def n8n_owner():
    status, body = call(urllib.request.Request(f"{N8N}/rest/settings"))
    data = json.loads(body).get("data", {})
    if not data.get("userManagement", {}).get("showSetupOnFirstLoad"):
        print("n8n : le compte propriétaire existe déjà")
        return
    alphabet = string.ascii_letters + string.digits
    password = "Lab" + "".join(secrets.choice(alphabet) for _ in range(16)) + "7a"
    email = "admin@soar-lab.test"
    payload = {"email": email, "firstName": "Admin", "lastName": "Lab", "password": password}
    req = urllib.request.Request(f"{N8N}/rest/owner/setup", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    status, body = call(req)
    if status >= 400:
        print("n8n : échec", status, body)
        return
    with CREDS.open("a", encoding="utf-8") as f:
        f.write(f"n8n (http://localhost:5680)\n  e-mail : {email}\n  mot de passe : {password}\n\n")
    print("n8n : compte créé, identifiants écrits dans", CREDS.name)


def gophish_key():
    path = os.path.join(tempfile.mkdtemp(), "g.db")
    subprocess.run(["docker", "cp", "soar-gophish:/opt/gophish/data/gophish.db", path], check=True, capture_output=True)
    con = sqlite3.connect(path)
    key = con.execute("select api_key from users limit 1").fetchone()[0]
    con.close()
    return key


def gophish():
    key = gophish_key()

    def api(path, body):
        req = urllib.request.Request(GOPHISH + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        return call(req)[0]

    print("GoPhish profil :", api("/smtp/", {"name": "Mailpit", "from_address": "demo@c0rp-local.test", "host": "mailpit:1025",
                                             "ignore_cert_errors": True, "interface_type": "SMTP", "headers": []}))
    print("GoPhish page :", api("/pages/", {"name": "Demo", "html": "<html><body><h1>Exercice de sensibilisation</h1>"
                                                                    "<p>Ceci est un exercice. Aucune donnée n'est collectée.</p></body></html>"}))
    print("GoPhish modèle :", api("/templates/", {
        "name": "Demo", "subject": "[DEMO] Exercice de signalement",
        "text": "Ceci est un exercice de signalement du projet SOAR.\nLien de l'exercice : {{.URL}}\n",
        "html": "<html><body><p>Ceci est un exercice de signalement du projet SOAR.</p>"
                "<p><a href=\"{{.URL}}\">Lien de l'exercice</a></p>{{.Tracker}}</body></html>"}))
    for name, users in (("Equipe A", ["alice.martin", "bruno.bernard", "chloe.dubois", "david.thomas"]), ("Equipe B", ["hugo.durand"])):
        targets = [{"email": f"{u}@corp.local", "first_name": u.split(".")[0], "last_name": u.split(".")[1], "position": ""} for u in users]
        print(f"GoPhish {name} :", api("/groups/", {"name": name, "targets": targets}))
    print("(201 = créé, 409 = existe déjà)")


n8n_owner()
gophish()
