"""Intégration optionnelle TheHive 5 : création d'une alerte par dossier (campagne) avec ses observables."""
from __future__ import annotations

import logging

import requests

from . import config

log = logging.getLogger(__name__)


def enabled() -> bool:
    return bool(config.THEHIVE_URL and config.THEHIVE_API_KEY)


def _h() -> dict:
    return {"Authorization": f"Bearer {config.THEHIVE_API_KEY}", "Content-Type": "application/json"}


def create_alert(case: dict, scoring: dict, report_count: int) -> str | None:
    if not enabled():
        return None
    iocs = case["iocs"] or {}
    observables = (
        [{"dataType": "url", "data": u} for u in iocs.get("urls", [])[:50]]
        + [{"dataType": "domain", "data": d} for d in iocs.get("domains", [])[:50]]
        + [{"dataType": "hash", "data": h} for h in iocs.get("hashes", [])[:50]]
        + [{"dataType": "mail", "data": s} for s in iocs.get("senders", [])[:10]]
    )
    body = {
        "type": "phishing-report",
        "source": "soar-phishing",
        "sourceRef": f"case-{case['id']}",
        "title": case["title"],
        "description": "Score {}/100\n\n".format(scoring["score"]) + "\n".join(
            f"- {h['label']} ({h['points']:+d}) : {h['evidence']}" for h in scoring["hits"]),
        "severity": 3 if scoring["decision"] == "malicious" else 2,
        "tags": ["phishing", scoring["decision"], f"reports:{report_count}"],
        "observables": observables,
    }
    try:
        r = requests.post(f"{config.THEHIVE_URL}/api/v1/alert", json=body, headers=_h(), timeout=15)
        r.raise_for_status()
        return r.json().get("_id")
    except requests.RequestException as exc:
        log.warning("TheHive indisponible : %s", exc)
        return None
