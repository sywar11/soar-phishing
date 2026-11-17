"""Requêtes de réputation : renseignement interne (campagnes déjà confirmées), URLhaus, VirusTotal, OTX, CIRCL hashlookup.

Chaque source renvoie une liste de verdicts :
    {"source", "indicator", "type", "verdict": malicious|suspicious|clean|known_good|unknown|error, "detail"}
Les sources sans clé API sont ignorées ; les résultats sont mis en cache (24 h) pour respecter les quotas.
"""
from __future__ import annotations

import base64
import logging
import time
from typing import Callable

import requests

from . import config

log = logging.getLogger(__name__)
_cache: dict[tuple[str, str], tuple[float, dict]] = {}
CACHE_TTL = 24 * 3600
UA = {"User-Agent": "soar-phishing-lab/1.0"}


def _cached(source: str, indicator: str, fn: Callable[[], dict]) -> dict:
    key = (source, indicator)
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return {**hit[1], "cached": True}
    try:
        res = fn()
    except requests.RequestException as exc:
        res = {"verdict": "error", "detail": f"{type(exc).__name__}"}
    res = {"source": source, "indicator": indicator, **res}
    if res.get("verdict") != "error":
        _cache[key] = (time.time(), res)
    return res


# --------------------------------------------------------------------------- URLhaus (abuse.ch)
def urlhaus_url(url: str) -> dict:
    def call():
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                          headers={**UA, "Auth-Key": config.URLHAUS_AUTH_KEY}, timeout=config.HTTP_TIMEOUT)
        j = r.json()
        if j.get("query_status") == "ok":
            return {"verdict": "malicious", "detail": f"listé URLhaus ({j.get('threat')}, statut {j.get('url_status')})"}
        return {"verdict": "unknown", "detail": j.get("query_status", "")}
    return _cached("urlhaus", url, call)


def urlhaus_host(host: str) -> dict:
    def call():
        r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": host},
                          headers={**UA, "Auth-Key": config.URLHAUS_AUTH_KEY}, timeout=config.HTTP_TIMEOUT)
        j = r.json()
        if j.get("query_status") == "ok" and int(j.get("url_count") or 0) > 0:
            return {"verdict": "malicious", "detail": f"hôte avec {j.get('url_count')} URL malveillantes (URLhaus)"}
        return {"verdict": "unknown", "detail": j.get("query_status", "")}
    return _cached("urlhaus", host, call)


def urlhaus_hash(sha256: str) -> dict:
    def call():
        r = requests.post("https://urlhaus-api.abuse.ch/v1/payload/", data={"sha256_hash": sha256},
                          headers={**UA, "Auth-Key": config.URLHAUS_AUTH_KEY}, timeout=config.HTTP_TIMEOUT)
        j = r.json()
        if j.get("query_status") == "ok":
            return {"verdict": "malicious", "detail": f"charge connue URLhaus ({j.get('signature') or j.get('file_type')})"}
        return {"verdict": "unknown", "detail": j.get("query_status", "")}
    return _cached("urlhaus", sha256, call)


# --------------------------------------------------------------------------- VirusTotal v3
def _vt(path: str, indicator: str) -> dict:
    def call():
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}",
                         headers={**UA, "x-apikey": config.VT_API_KEY}, timeout=config.HTTP_TIMEOUT)
        if r.status_code == 404:
            return {"verdict": "unknown", "detail": "inconnu de VirusTotal"}
        if r.status_code == 429:
            return {"verdict": "error", "detail": "quota VirusTotal atteint"}
        r.raise_for_status()
        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        detail = f"{mal} moteurs malveillant / {sus} suspect"
        if mal >= 3:
            return {"verdict": "malicious", "detail": detail}
        if mal >= 1 or sus >= 2:
            return {"verdict": "suspicious", "detail": detail}
        return {"verdict": "clean", "detail": detail}
    return _cached("virustotal", indicator, call)


def vt_url(url: str) -> dict:
    uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return _vt(f"urls/{uid}", url)


def vt_file(sha256: str) -> dict:
    return _vt(f"files/{sha256}", sha256)


def vt_domain(domain: str) -> dict:
    return _vt(f"domains/{domain}", domain)


# --------------------------------------------------------------------------- AlienVault OTX
def otx_domain(domain: str) -> dict:
    def call():
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                         headers={**UA, "X-OTX-API-KEY": config.OTX_API_KEY}, timeout=config.HTTP_TIMEOUT)
        if r.status_code in (400, 404):
            return {"verdict": "unknown", "detail": "inconnu d'OTX"}
        r.raise_for_status()
        pulses = int(r.json().get("pulse_info", {}).get("count", 0))
        if pulses >= 3:
            return {"verdict": "malicious", "detail": f"cité dans {pulses} pulses OTX"}
        if pulses >= 1:
            return {"verdict": "suspicious", "detail": f"cité dans {pulses} pulse(s) OTX"}
        return {"verdict": "unknown", "detail": "aucun pulse OTX"}
    return _cached("otx", domain, call)


# --------------------------------------------------------------------------- CIRCL hashlookup (fichiers connus légitimes, NSRL)
def circl_hash(sha256: str) -> dict:
    def call():
        r = requests.get(f"https://hashlookup.circl.lu/lookup/sha256/{sha256}", headers=UA, timeout=config.HTTP_TIMEOUT)
        if r.status_code == 200:
            j = r.json()
            return {"verdict": "known_good", "detail": f"fichier connu ({j.get('FileName') or j.get('source', 'NSRL')})"}
        return {"verdict": "unknown", "detail": "hash inconnu de CIRCL"}
    return _cached("circl", sha256, call)


# --------------------------------------------------------------------------- suivi de redirections HTTP (optionnel)
def follow_redirects(url: str, max_hops: int = 5) -> list[str]:
    """Requête HEAD sans contenu ; à n'activer qu'en environnement isolé (FOLLOW_REDIRECTS=true)."""
    chain = [url]
    current = url
    for _ in range(max_hops):
        try:
            r = requests.head(current, allow_redirects=False, timeout=5, headers=UA)
        except requests.RequestException:
            break
        loc = r.headers.get("Location")
        if r.status_code not in (301, 302, 303, 307, 308) or not loc:
            break
        current = requests.compat.urljoin(current, loc)
        if current in chain:
            break
        chain.append(current)
    return chain


# --------------------------------------------------------------------------- orchestration
def enrich(analysis: dict, local_lookup: Callable[[str], dict | None], online: bool | None = None) -> list[dict]:
    online = config.ENABLE_ONLINE_LOOKUPS if online is None else online
    results: list[dict] = []
    urls = analysis["urls"]
    domains = sorted({u["domain"] for u in urls if u["domain"] and u["domain"] not in config.NEVER_BLOCK})
    sender_dom = analysis["headers"]["from_domain"]
    hashes = [a["sha256"] for a in analysis["attachments"]]
    hashes += [m["sha256"] for a in analysis["attachments"] for m in a["zip_members"] if m.get("sha256")]

    # 1) renseignement interne : IOC des campagnes déjà confirmées par un analyste
    for ind, typ in ([(u["key"], "url") for u in urls] + [(d, "domain") for d in domains]
                     + [(h, "sha256") for h in hashes] + ([(sender_dom, "domain")] if sender_dom else [])):
        hit = local_lookup(ind)
        if hit:
            results.append({"source": "intel_interne", "indicator": ind, "type": typ, "verdict": "malicious",
                            "detail": f"IOC du dossier confirmé #{hit['case_id']}"})

    if not online:
        return results

    vt_budget = config.VT_MAX_LOOKUPS
    for h in hashes[:10]:
        results.append({**circl_hash(h), "type": "sha256"})
        if config.URLHAUS_AUTH_KEY:
            results.append({**urlhaus_hash(h), "type": "sha256"})
        if config.VT_API_KEY and vt_budget > 0:
            results.append({**vt_file(h), "type": "sha256"})
            vt_budget -= 1
    for u in [u for u in urls if u["domain"] not in config.NEVER_BLOCK][:15]:
        if config.URLHAUS_AUTH_KEY:
            results.append({**urlhaus_url(u["final_url"]), "type": "url"})
        if config.VT_API_KEY and vt_budget > 0:
            results.append({**vt_url(u["final_url"]), "type": "url"})
            vt_budget -= 1
    for d in domains[:10]:
        if config.OTX_API_KEY:
            results.append({**otx_domain(d), "type": "domain"})
        if config.URLHAUS_AUTH_KEY:
            results.append({**urlhaus_host(d), "type": "domain"})
    return results
