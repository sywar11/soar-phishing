"""Outils sur les indicateurs : domaine enregistré, défanisation, normalisation d'URL."""
import ipaddress
import re
from urllib.parse import parse_qs, unquote, urlsplit

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "co.in",
    "com.tn", "gouv.fr", "asso.fr", "co.za", "com.mx", "com.tr", "co.nz", "com.cn",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly",
    "shorturl.at", "rb.gy", "tiny.cc", "buff.ly", "s.id", "t.ly",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "live", "icu", "buzz", "rest", "cam", "monster",
    "quest", "sbs", "cfd", "lat", "beauty", "hair", "online", "site", "support", "work",
}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def host_of(url: str) -> str:
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.lower().strip(".")


def registered_domain(host: str) -> str:
    host = (host or "").lower().strip(".").split(":")[0]
    if not host or is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def email_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower().strip(">").strip() if addr and "@" in addr else ""


def tld(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def defang_url(url: str) -> str:
    out = re.sub(r"^http", "hxxp", url, flags=re.I)
    out = re.sub(r"^ftp", "fxp", out, flags=re.I)
    host = host_of(url)
    if host:
        out = out.replace(host, host.replace(".", "[.]"), 1)
    return out


def defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def defang_email(addr: str) -> str:
    return addr.replace("@", "[@]").replace(".", "[.]")


_TOKEN = re.compile(r"(?<![a-z])[0-9a-f]{8,}(?![a-z])|\d+", re.I)


def url_key(url: str) -> str:
    """Clé de regroupement : hôte + chemin sans paramètres ni identifiants.

    GoPhish ajoute ?rid=<id_destinataire> à chaque lien : deux destinataires d'une même campagne
    obtiennent donc la même clé alors que l'URL brute diffère.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    path = _TOKEN.sub("#", unquote(parts.path or "/")).rstrip("/") or "/"
    return f"{(parts.hostname or '').lower()}{path}"


REDIRECT_PARAMS = ("url", "u", "q", "target", "redirect", "redirect_uri", "dest", "destination", "goto", "link", "r")


def unwrap_url(url: str) -> list[str]:
    """Déroule les redirections « statiques » (SafeLinks, google.com/url, ?url=…) sans requête réseau.

    Renvoie la chaîne [url, url_intermédiaire, …, url_finale].
    """
    chain = [url]
    current = url
    for _ in range(5):
        try:
            qs = parse_qs(urlsplit(current).query)
        except ValueError:
            break
        nxt = None
        for p in REDIRECT_PARAMS:
            for v in qs.get(p, []):
                v = unquote(v)
                if re.match(r"^https?://", v, re.I):
                    nxt = v
                    break
            if nxt:
                break
        if not nxt or nxt in chain:
            break
        chain.append(nxt)
        current = nxt
    return chain
