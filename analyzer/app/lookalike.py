"""Détection de domaines similaires (typosquatting, homoglyphes, punycode, marque dans le domaine)."""
from __future__ import annotations

from functools import lru_cache

from . import config, ioc

# Homoglyphes courants (latin/chiffres + cyrillique/grec fréquemment utilisés dans les IDN)
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a", "$": "s",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ԁ": "d",
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "ѕ": "s", "ɡ": "g",
}
MULTI_GLYPHS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("ii", "u"))


def _idna_decode(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna") if "xn--" in domain else domain
    except UnicodeError:
        return domain


def normalize(label: str) -> str:
    s = "".join(HOMOGLYPHS.get(c, c) for c in label.lower())
    for a, b in MULTI_GLYPHS:
        s = s.replace(a, b)
    return s


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _brand(domain: str) -> str:
    """'impots.gouv.fr' -> 'impots', 'paypal.com' -> 'paypal'."""
    return ioc.registered_domain(domain).split(".")[0]


LURE_WORDS = {
    "login", "logon", "signin", "secure", "security", "verify", "verification", "account", "accounts",
    "support", "update", "auth", "service", "services", "online", "portal", "mail", "help", "id",
    "connexion", "compte", "client", "clients", "espace", "web", "app", "pay", "billing", "facture",
    "remboursement", "suivi", "colis", "office", "local", "intranet", "rh", "it",
}
BRANDS = {d: _brand(d) for d in config.PROTECTED_DOMAINS}
LEGIT_REG_DOMAINS = {ioc.registered_domain(d) for d in config.PROTECTED_DOMAINS}


@lru_cache(maxsize=4096)
def check(domain: str) -> dict | None:
    """Renvoie {'brand', 'technique', 'legit'} si `domain` imite une marque protégée, sinon None."""
    domain = (domain or "").lower().strip(".")
    if not domain or ioc.is_ip(domain):
        return None
    reg = ioc.registered_domain(domain)
    if reg in LEGIT_REG_DOMAINS:
        return None
    unicode_reg = _idna_decode(reg)
    label = unicode_reg.split(".")[0]
    norm = normalize(label)
    tokens = [t for t in norm.replace("_", "-").split("-") if t]

    for legit, brand in BRANDS.items():
        if len(brand) < 4:
            continue
        if unicode_reg != reg and normalize(_idna_decode(reg).split(".")[0]) == brand:
            return {"brand": brand, "legit": legit, "technique": "punycode/homoglyphe IDN"}
        if norm == brand and label != brand:
            return {"brand": brand, "legit": legit, "technique": "homoglyphe (ex: 0→o, rn→m)"}
        if label == brand:  # même nom, autre TLD : paypal.co, microsoft.support…
            return {"brand": brand, "legit": legit, "technique": "même marque, autre TLD"}
        if brand in tokens and len(tokens) > 1:
            return {"brand": brand, "legit": legit, "technique": "marque incluse dans le domaine"}
        flat = norm.replace("-", "")
        if flat != brand and brand in flat:
            rest = flat.replace(brand, "", 1)
            if rest in LURE_WORDS or any(rest.startswith(w) or rest.endswith(w) for w in LURE_WORDS):
                return {"brand": brand, "legit": legit, "technique": "marque + mot d'appât (login, secure…)"}
        dist = levenshtein(norm, brand)
        if (len(brand) >= 5 and dist == 1) or (len(brand) >= 8 and dist == 2):
            return {"brand": brand, "legit": legit, "technique": f"typosquatting (distance {dist})"}
    # Sous-domaine trompeur : paypal.com.secure-login.xyz
    sub = domain[: -len(reg)].strip(".") if domain.endswith(reg) else ""
    for legit in LEGIT_REG_DOMAINS:
        if sub and (sub == legit or sub.endswith("." + legit) or sub.startswith(legit + ".") or legit in sub.split(".")):
            return {"brand": _brand(legit), "legit": legit, "technique": "marque en sous-domaine"}
        if sub and legit.replace(".", "-") in sub:
            return {"brand": _brand(legit), "legit": legit, "technique": "marque en sous-domaine"}
    return None
