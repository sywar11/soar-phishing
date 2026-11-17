"""Télécharge les corpus publics et construit le jeu d'essai, DANS le conteneur analyzer.

    docker exec soar-analyzer python -I /dataset/preparer_corpus.py
    docker exec soar-analyzer sh -c "cd /app && python -m app.evaluate --dataset /data/corpus --as-report"
    docker cp soar-analyzer:/data/corpus/results dataset/

Les e-mails restent dans /data/corpus (volume Docker) : seuls les résultats, sans contenu d'e-mail, sont copiés sur l'hôte.
Ils sont uniquement lus par l'analyseur : aucun lien ouvert, aucune pièce jointe exécutée.

Sources :
  - Phishing : corpus de J. Nazario, phishing-2024, https://monkey.org/~jose/phishing/ (CC-BY-4.0)
  - Légitimes et spam : Apache SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/
"""
import csv
import hashlib
import mailbox
import random
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path("/data/corpus")
RAW = ROOT / "raw"
EMAILS = ROOT / "emails"
SA = "https://spamassassin.apache.org/old/publiccorpus/"
PHISH_URL = "https://monkey.org/~jose/phishing/phishing-2024"
SOURCES = [("20030228_easy_ham.tar.bz2", "legit", "easy_ham", 300),
           ("20021010_hard_ham.tar.bz2", "legit", "hard_ham", 300),
           ("20030228_spam.tar.bz2", "legit", "spam", 200)]
PHISH_MAX = 400
rng = random.Random(42)


def fetch(url: str, name: str) -> Path:
    path = RAW / name
    if not path.exists():
        print("téléchargement", name)
        req = urllib.request.Request(url, headers={"User-Agent": "soar-lab/1.0"})
        with urllib.request.urlopen(req, timeout=180) as r:  # noqa: S310 - URL fixes ci-dessus
            path.write_bytes(r.read())
    return path


for d in (RAW, EMAILS):
    d.mkdir(parents=True, exist_ok=True)
for old in EMAILS.glob("*.eml"):
    old.unlink()

seen: set[str] = set()
rows = []


def add(raw: bytes, label: str, family: str) -> bool:
    digest = hashlib.sha256(raw).hexdigest()
    if digest in seen or len(raw) < 50:
        return False
    seen.add(digest)
    # nom généré par nous : on n'utilise jamais un nom venant d'une archive
    name = f"{family}_{len([r for r in rows if r[2] == family]):04d}.eml"
    (EMAILS / name).write_bytes(raw)
    rows.append((name, label, family))
    return True


# Lecture directe des membres de l'archive, sans jamais les extraire sur le disque
for filename, label, family, limit in SOURCES:
    path = fetch(SA + filename, filename)
    items = []
    with tarfile.open(path, "r:bz2") as tar:
        for m in tar:
            if m.isfile() and not m.name.endswith("cmds"):
                items.append(tar.extractfile(m).read())
    rng.shuffle(items)
    kept = sum(add(raw, label, family) for raw in items[:limit])
    print(family, "disponibles", len(items), "gardés", kept)

mbox = mailbox.mbox(str(fetch(PHISH_URL, "phishing-2024.mbox")), create=False)
keys = list(mbox.keys())
rng.shuffle(keys)
kept = 0
for k in keys:
    if kept >= PHISH_MAX:
        break
    try:
        kept += add(mbox.get_bytes(k), "phishing", "nazario_2024")
    except Exception as exc:  # noqa: BLE001 - message mal formé dans le corpus
        print("ignoré", exc)
mbox.close()
print("nazario_2024 disponibles", len(keys), "gardés", kept)

# Séparation fixe, moitié par moitié dans chaque famille :
#   dev  = sert à régler le score ;  test = sert uniquement à la mesure finale.
split_rng = random.Random(2026)
split = {}
for family in sorted({r[2] for r in rows}):
    names = sorted(r[0] for r in rows if r[2] == family)
    split_rng.shuffle(names)
    for i, name in enumerate(names):
        split[name] = "dev" if i < len(names) // 2 else "test"

with (ROOT / "labels.csv").open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["file", "label", "family", "split"])
    w.writerows((*r, split[r[0]]) for r in rows)
print("total", len(rows), "dev", sum(v == "dev" for v in split.values()), "test", sum(v == "test" for v in split.values()))
