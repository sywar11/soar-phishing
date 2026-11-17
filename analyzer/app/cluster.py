"""Détection des doublons et des campagnes.

Un signalement rejoint un dossier existant s'il partage au moins une « clé » avec lui :
  - url:<hôte+chemin normalisé>   (les paramètres par destinataire comme ?rid= de GoPhish sont ignorés)
  - sha256:<hash d'une pièce jointe>
  - subj:<domaine expéditeur>:<sujet normalisé>   (sans RE/TR/FW, chiffres, prénoms en tête)
  - mid:<Message-ID>                            (le même e-mail signalé par plusieurs personnes)
Les domaines très courants (NEVER_BLOCK) ne servent pas de clé pour éviter de fusionner des campagnes sans rapport.
"""
from __future__ import annotations

import re
import unicodedata

from . import config, ioc

PREFIX = re.compile(r"^\s*((re|tr|fw|fwd|réf|ref|aw|wg|sv|antw)\s*(\[\d+\])?\s*:\s*)+", re.I)
GREETING = re.compile(r"^(bonjour|hello|hi|cher|chère|dear)\s+\S+[,\s]+", re.I)


def normalize_subject(subject: str) -> str:
    s = unicodedata.normalize("NFKD", subject or "").encode("ascii", "ignore").decode().lower()
    s = PREFIX.sub("", s)
    s = GREETING.sub("", s)
    s = re.sub(r"\S+@\S+", " ", s)          # adresses e-mail personnalisées
    s = re.sub(r"[#n°]*\d[\d\-/.:]*", "#", s)  # numéros de dossier, dates, montants
    s = re.sub(r"[^a-z#]+", " ", s)
    return " ".join(s.split())


def keys_for(analysis: dict) -> list[str]:
    h = analysis["headers"]
    keys: list[str] = []
    if h["message_id"]:
        keys.append(f"mid:{h['message_id'].lower()}")
    for u in analysis["urls"]:
        if u["domain"] and u["domain"] not in config.NEVER_BLOCK and u["domain"] not in config.INTERNAL_DOMAINS:
            keys.append(f"url:{u['key']}")
    for a in analysis["attachments"]:
        keys.append(f"sha256:{a['sha256']}")
        keys += [f"sha256:{m['sha256']}" for m in a["zip_members"] if m.get("sha256")]
    subj = normalize_subject(h["subject"])
    if len(subj.replace("#", "").strip()) >= 8:
        keys.append(f"subj:{ioc.registered_domain(h['from_domain'])}:{subj}")
    return sorted(set(keys))
