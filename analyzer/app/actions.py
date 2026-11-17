"""Actions de réponse : lecture Mailpit, recherche + purge chez les autres destinataires, blocage DNS, e-mails de retour.

En production, Mailpit serait remplacé par l'API de la messagerie :
  Microsoft 365 -> Graph / Purview « Search-Compliance + Purge » ; Google Workspace -> Gmail API ; Exchange -> Search-Mailbox.
"""
from __future__ import annotations

import logging
import smtplib
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

import requests

from . import cluster, config, ioc, parser, scoring

log = logging.getLogger(__name__)
FREEMAIL = scoring.FREEMAIL


# --------------------------------------------------------------------------- Mailpit
def mailpit_get_raw(mailpit_id: str) -> bytes:
    r = requests.get(f"{config.MAILPIT_URL}/api/v1/message/{mailpit_id}/raw", timeout=15)
    r.raise_for_status()
    return r.content


def mailpit_search(query: str, limit: int = 500) -> list[dict]:
    r = requests.get(f"{config.MAILPIT_URL}/api/v1/search", params={"query": query, "limit": limit}, timeout=15)
    r.raise_for_status()
    return r.json().get("messages", []) or []


def mailpit_mark_read(ids: list[str]) -> None:
    if ids:
        requests.put(f"{config.MAILPIT_URL}/api/v1/messages", json={"IDs": ids, "Read": True}, timeout=15)


def mailpit_delete(ids: list[str]) -> None:
    if ids:
        r = requests.delete(f"{config.MAILPIT_URL}/api/v1/messages", json={"IDs": ids}, timeout=15)
        r.raise_for_status()


def _addresses(field) -> list[str]:
    return [(x.get("Address") or "").lower() for x in (field or []) if x.get("Address")]


# --------------------------------------------------------------------------- recherche + purge
def find_copies(case: dict, case_keys: set[str]) -> list[dict]:
    """Recherche le message dans toutes les boîtes (hors boîte de signalement) et vérifie la correspondance par clés."""
    iocs = case["iocs"] or {}
    queries = set()
    for mid in iocs.get("message_ids", [])[:20]:
        queries.add(f'message-id:"{mid.strip("<>")}"')
    for s in iocs.get("senders", [])[:5]:
        queries.add(f'from:"{s}"')
    for d in iocs.get("domains", [])[:5]:
        queries.add(f'"{d}"')
    candidates: dict[str, dict] = {}
    for q in queries:
        try:
            for m in mailpit_search(q):
                candidates[m["ID"]] = m
        except requests.RequestException as exc:
            log.warning("recherche Mailpit '%s' : %s", q, exc)

    matches = []
    for mid, m in candidates.items():
        rcpts = _addresses(m.get("To")) + _addresses(m.get("Cc")) + _addresses(m.get("Bcc"))
        if config.REPORT_MAILBOX in rcpts:
            continue  # on ne purge pas les preuves dans la boîte de signalement
        try:
            msg = parser.parse_bytes(mailpit_get_raw(mid))
        except requests.RequestException:
            continue
        keys = set(cluster.keys_for(parser.analyze_message(msg)))
        common = keys & case_keys
        if common:
            matches.append({"mailpit_id": mid, "recipients": rcpts, "subject": m.get("Subject", ""),
                            "matched_on": sorted(common)[:3]})
    return matches


def purge(case: dict, case_keys: set[str]) -> list[dict]:
    copies = find_copies(case, case_keys)
    mailpit_delete([c["mailpit_id"] for c in copies])
    for c in copies:
        c["purged_at"] = time.time()
    return copies


# --------------------------------------------------------------------------- blocage DNS
def domains_to_block(case: dict) -> list[str]:
    iocs = case["iocs"] or {}
    out = set()
    for host in iocs.get("hosts", []) + iocs.get("domains", []) + iocs.get("sender_domains", []):
        host = host.lower()
        reg = ioc.registered_domain(host)
        if (not host or ioc.is_ip(host) or reg in config.NEVER_BLOCK or reg in FREEMAIL
                or reg in config.INTERNAL_DOMAINS or reg in ioc.URL_SHORTENERS):
            continue
        out.add(host)
        out.add(reg)
    return sorted(out)


def dns_block(domains: list[str]) -> list[str]:
    path = Path(config.BLOCKLIST_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else "# Domaines bloqués par le SOAR\n"
    present = {line.split()[1] for line in existing.splitlines() if line and not line.startswith("#") and len(line.split()) > 1}
    added = []
    lines = []
    for d in domains:
        for name in (d, f"www.{d}") if d.count(".") == 1 else (d,):
            if name not in present:
                lines.append(f"0.0.0.0 {name}")
                present.add(name)
                added.append(name)
    if lines:
        with path.open("a", encoding="utf-8") as f:
            if not existing.endswith("\n"):
                f.write("\n")
            f.write("\n".join(lines) + "\n")
    return added


def dns_unblock(domains: list[str]) -> None:
    path = Path(config.BLOCKLIST_PATH)
    if not path.exists():
        return
    drop = set(domains) | {f"www.{d}" for d in domains}
    kept = [l for l in path.read_text(encoding="utf-8").splitlines()
            if l.startswith("#") or len(l.split()) < 2 or l.split()[1] not in drop]
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- e-mails
def send_mail(to: str, subject: str, body: str, html: str | None = None) -> None:
    m = EmailMessage()
    m["From"] = f"Centre de sécurité <{config.SOC_SENDER}>"
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = formatdate(localtime=True)
    m["Message-ID"] = make_msgid(domain=ioc.email_domain(config.SOC_SENDER) or "soc.local")
    m["X-SOAR"] = "phishing-response"
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
        s.send_message(m)


def _signature() -> str:
    return "\n\n-- \nCentre de sécurité (SOC)\nMerci de votre vigilance : chaque signalement protège vos collègues."


TEMPLATES = {
    "received": (
        "[Signalement #{case_id}] Reçu - analyse en cours",
        "Bonjour,\n\nNous avons bien reçu votre signalement de l'e-mail « {subject} ».\n"
        "L'analyse automatique le classe comme {verdict_fr} (score {score}/100). Un analyste va le valider.\n"
        "Ne cliquez sur aucun lien et n'ouvrez pas les pièces jointes en attendant.\n"
        "{campaign}",
    ),
    "benign": (
        "[Signalement #{case_id}] E-mail jugé légitime",
        "Bonjour,\n\nMerci pour votre signalement de l'e-mail « {subject} ».\n"
        "Après analyse automatique (score {score}/100), il ne présente pas de caractère malveillant : "
        "{reasons}\nSi vous avez un doute (expéditeur inattendu, demande inhabituelle), contactez le support.",
    ),
    "confirmed": (
        "[Signalement #{case_id}] Phishing confirmé - merci !",
        "Bonjour,\n\nL'e-mail « {subject} » que vous avez signalé est bien une tentative de phishing.\n"
        "Actions réalisées : {actions}.\n\n"
        "Si vous avez cliqué sur un lien ou saisi votre mot de passe, changez-le immédiatement et prévenez le support.",
    ),
    "false_positive": (
        "[Signalement #{case_id}] E-mail légitime après vérification",
        "Bonjour,\n\nAprès vérification par un analyste, l'e-mail « {subject} » que vous avez signalé est légitime.\n"
        "Vous pouvez le traiter normalement. Merci pour votre vigilance.",
    ),
    "recipient_alert": (
        "Un e-mail frauduleux a été retiré de votre boîte",
        "Bonjour,\n\nL'e-mail « {subject} » (expéditeur : {sender}) que vous avez reçu a été identifié comme "
        "une tentative de phishing et retiré automatiquement de votre boîte.\n"
        "Si vous l'aviez déjà ouvert et cliqué sur un lien ou saisi vos identifiants, changez votre mot de passe "
        "et contactez le support.",
    ),
}
VERDICT_FR = {"benign": "probablement légitime", "suspicious": "suspect", "malicious": "malveillant"}


def notify(template: str, to: str, **ctx) -> dict:
    subject_t, body_t = TEMPLATES[template]
    ctx = {"campaign": "", "reasons": "", "actions": "", **ctx}
    ctx.setdefault("verdict_fr", VERDICT_FR.get(ctx.get("verdict", ""), ctx.get("verdict", "")))
    subject = subject_t.format(**ctx)
    body = body_t.format(**ctx) + _signature()
    send_mail(to, subject, body)
    return {"to": to, "template": template, "subject": subject}
