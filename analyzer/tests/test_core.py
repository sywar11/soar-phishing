"""Tests unitaires du moteur, sans réseau ni base de données.

    python analyzer/tests/test_core.py     (depuis le dossier du projet)

Les données sont de simples chaînes de test sur des domaines réservés (.example, .test).
"""
import base64
import hashlib
import io
import os
import sys
import tempfile
import threading
import zipfile
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("RULES_DIR", str(ROOT / "rules"))
os.environ["ENABLE_ONLINE_LOOKUPS"] = "false"
os.environ["DB_PATH"] = str(Path(tempfile.mkdtemp()) / "test.db")
os.environ["THEHIVE_URL"] = ""

from app import cluster, ioc, lookalike, parser, yara_scan  # noqa: E402

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("OK    " if ok else "ECHEC ") + name + (f"  -> {detail}" if detail and not ok else ""))


def inner_mail() -> EmailMessage:
    m = EmailMessage()
    m["From"] = "Test <a@sender.example>"
    m["To"] = "b@corp.local"
    m["Subject"] = "Sujet accentué de test"
    m["Message-ID"] = "<id1@sender.example>"
    m.set_content("Corps de test http://site.example/page?rid=abc")
    return m


# --- indicateurs
check("défanisation d'URL", ioc.defang_url("http://a.example/x") == "hxxp://a[.]example/x", ioc.defang_url("http://a.example/x"))
check("clé d'URL ignore ?rid=", ioc.url_key("http://a.example/p?rid=1") == ioc.url_key("http://a.example/p?rid=2"))
check("redirection statique déroulée", ioc.unwrap_url("http://r.example/?url=http%3A%2F%2Fb.example%2F")[-1] == "http://b.example/")
check("domaine enregistré (co.uk)", ioc.registered_domain("a.b.co.uk") == "b.co.uk")

# --- domaines similaires
for dom in ("c0rp-local.example", "paypa1.example", "microsoft-login.example"):
    check(f"similaire détecté : {dom}", lookalike.check(dom) is not None)
for dom in ("corp.local", "microsoft.com", "login.microsoftonline.com", "exemple-neutre.org", "amazonaws.com"):
    check(f"légitime non signalé : {dom}", lookalike.check(dom) is None, str(lookalike.check(dom)))

# --- robustesse : charset inexistant (cas réel rencontré dans le corpus public)
import email as _email  # noqa: E402
from email import policy as _policy  # noqa: E402

_bad = _email.message_from_bytes(
    b"From: a@sender.example\r\nSubject: x\r\nContent-Type: text/plain; charset=DEFAULT_CHARSET\r\n\r\nbonjour\r\n",
    policy=_policy.default)
check("charset inexistant : pas de plantage", "bonjour" in parser.analyze_message(_bad).get("body_text", "bonjour"))

# --- score : motifs resserrés après l'évaluation
from app import scoring  # noqa: E402

check("chemin d'URL : « author » n'est pas « auth »", scoring.CREDENTIAL_PATH.search("site.example/author/page") is None)
check("chemin d'URL : /login détecté", scoring.CREDENTIAL_PATH.search("site.example/login") is not None)
check("texte de lien : une adresse est reconnue", scoring.LINK_AS_ADDRESS.match("https://www.banque.example/acces") is not None)
check("texte de lien : une phrase ne l'est pas", scoring.LINK_AS_ADDRESS.match("Voir le site banque.example") is None)
check("action sur le compte détectée", bool(scoring._count(scoring.ACCOUNT_ACTION, "merci de confirmer votre compte")))
check("texte neutre sans action sur le compte", not scoring._count(scoring.ACCOUNT_ACTION, "le compte rendu de la réunion est prêt"))

# --- regroupement
# n8n envoie les signalements EN MÊME TEMPS : ils doivent quand même former un seul dossier
from app import pipeline, store  # noqa: E402


def _report_from(n: int) -> bytes:
    rep = EmailMessage()
    rep["From"] = f"user{n}@corp.local"
    rep["To"] = "phishing@corp.local"
    rep["Subject"] = "Signalement"
    rep.set_content("Voir la pièce jointe.")
    rep.add_attachment(inner_mail().as_bytes(), maintype="application", subtype="octet-stream", filename="suspect.eml")
    return rep.as_bytes()


_rounds_ok = True
_detail = ""
for _round in range(5):
    # Message-ID et domaine propres à chaque tour, pour que chaque tour teste la création d'un nouveau dossier
    _raws = [_report_from(i).replace(b"id1@sender.example", f"r{_round}@s{_round}.example".encode())
             .replace(b"site.example", f"s{_round}.example".encode()) for i in range(8)]
    _barrier = threading.Barrier(len(_raws))
    _ids: list[int] = []

    def _worker(raw: bytes) -> None:
        _barrier.wait()
        _ids.append(pipeline.ingest(raw)["case_id"])

    _threads = [threading.Thread(target=_worker, args=(r,)) for r in _raws]
    for _t in _threads:
        _t.start()
    for _t in _threads:
        _t.join()
    if len(set(_ids)) != 1 or len(_ids) != len(_raws):
        _rounds_ok = False
        _detail = f"tour {_round} : {len(_ids)} réponses, dossiers {sorted(set(_ids))}"
check("signalements simultanés : 1 seul dossier", _rounds_ok, _detail)

check("objet normalisé (TR:, numéros)", cluster.normalize_subject("TR: Dossier 123") == cluster.normalize_subject("Dossier 456"))

# --- extraction du message signalé, dans les 3 formats
raw = inner_mail().as_bytes()
rep1 = EmailMessage()
rep1["From"] = "r@corp.local"
rep1.set_content("signalement")
rep1.add_attachment(inner_mail(), filename="s.eml")
rep2 = EmailMessage()
rep2["From"] = "r@corp.local"
rep2.set_content("signalement")
rep2.add_attachment(raw, maintype="application", subtype="octet-stream", filename="s.eml")
rep3 = EmailMessage()
rep3["From"] = "r@corp.local"
rep3.set_content("signalement")
rep3.add_attachment(raw, maintype="message", subtype="rfc822", filename="s.eml")
for label, rep in (("rfc822", rep1), (".eml joint", rep2), ("rfc822 encodé base64", rep3)):
    msg, method = parser.extract_reported(parser.parse_bytes(rep.as_bytes()))
    check(f"extraction {label} ({method})", msg.get("Subject") == "Sujet accentué de test", str(msg.get("Subject")))

# --- analyse : URL, hash, contenu d'un ZIP
m = inner_mail()
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    z.writestr("note.txt", "contenu neutre")
m.add_attachment(buf.getvalue(), maintype="application", subtype="zip", filename="a.zip")
a = parser.analyze_message(parser.parse_bytes(m.as_bytes()))
check("URL extraite et défanisée", a["urls"][0]["defanged"].startswith("hxxp://site[.]example"))
check("hash SHA256 de la pièce jointe", a["attachments"][0]["sha256"] == hashlib.sha256(buf.getvalue()).hexdigest())
check("membre du ZIP listé", a["attachments"][0]["zip_members"][0]["filename"] == "note.txt")

# --- YARA (chaînes de test inoffensives)
try:
    import yara  # noqa: F401
    have_yara = True
except ImportError:
    have_yara = False
if have_yara:
    hit = yara_scan.scan([("t.html", b'<form action="x"><input type="password"></form>')])
    check("YARA : formulaire avec mot de passe", any(h["rule"] == "HTML_Credential_Harvesting" for h in hit), str(hit))
    hit = yara_scan.scan([("t.txt", b"Bonjour, voici un simple texte.")])
    check("YARA : texte neutre sans alerte", hit == [], str(hit))
    hit = yara_scan.scan([("t.bin", b"powershell -enc " + base64.b64encode(b"x"))])
    check("YARA : chaîne PowerShell encodée", any(h["rule"] == "Suspicious_PowerShell" for h in hit), str(hit))
else:
    print("IGNORÉ YARA : yara-python absent (lancer le test dans le conteneur analyzer)")

print(f"\n{sum(results)}/{len(results)} tests réussis")
sys.exit(0 if all(results) else 1)
