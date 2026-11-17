"""Réponse sur un dossier : confirmation, purge, blocage DNS, notifications, faux positif."""
from __future__ import annotations

from . import actions, ioc, store


def _ctx(case: dict) -> dict:
    return {"case_id": case["id"], "subject": case["subject"], "sender": ioc.defang_email(case["sender"] or "")}


def _case_keys(case_id: int) -> set[str]:
    with store.db() as c:
        return {r["key"] for r in c.execute("SELECT key FROM case_keys WHERE case_id=?", (case_id,))}


def confirm(case_id: int, analyst: str = "analyste") -> dict:
    case = store.get_case(case_id)
    iocs = case["iocs"] or {}
    intel = ([(k, "url") for k in iocs.get("url_keys", [])] + [(d, "domain") for d in actions.domains_to_block(case)]
             + [(h, "sha256") for h in iocs.get("hashes", [])])
    store.add_intel(intel, case_id)
    store.update_case(case_id, status="confirmed", verdict="malicious")
    store.log_action(case_id, "confirmed", {"analyst": analyst, "intel_added": len(intel)})
    return {"case_id": case_id, "status": "confirmed", "intel_added": len(intel)}


def purge(case_id: int) -> dict:
    case = store.get_case(case_id)
    copies = actions.purge(case, _case_keys(case_id))
    all_purged = (case["purged"] or []) + copies
    store.update_case(case_id, purged=all_purged)
    store.log_action(case_id, "purge", {"count": len(copies), "messages": copies})
    return {"case_id": case_id, "purged": len(copies),
            "recipients": sorted({r for c in copies for r in c["recipients"]})}


def block_dns(case_id: int) -> dict:
    case = store.get_case(case_id)
    domains = actions.domains_to_block(case)
    added = actions.dns_block(domains)
    store.update_case(case_id, blocked=sorted(set(case["blocked"] or []) | set(domains)))
    store.log_action(case_id, "dns_block", {"domains": domains, "new_entries": added})
    return {"case_id": case_id, "blocked": domains, "new_entries": added}


def notify_confirmed(case_id: int, only_new: bool = False) -> dict:
    """Prévient les rapporteurs (merci + consignes) et les autres destinataires (e-mail retiré)."""
    case = store.get_case(case_id)
    ctx = _ctx(case)
    sent_before = {(a["detail"].get("to"), a["detail"].get("template")) for a in store.actions_for_case(case_id)
                   if a["action"] == "notify" and isinstance(a["detail"], dict)}
    reporters = sorted({r["reporter"] for r in store.reports_for_case(case_id) if r["reporter"]})
    acts = []
    if case["purged"]:
        acts.append(f"{len(case['purged'])} copie(s) retirée(s) des boîtes")
    if case["blocked"]:
        acts.append("domaine(s) bloqué(s) : " + ", ".join(ioc.defang_domain(d) for d in case["blocked"][:5]))
    sent = []
    for r in reporters:
        if only_new and (r, "confirmed") in sent_before:
            continue
        sent.append(actions.notify("confirmed", r, actions=" ; ".join(acts) or "dossier clôturé", **ctx))
    for rcpt in sorted({x for p in (case["purged"] or []) for x in p["recipients"]} - set(reporters)):
        if (rcpt, "recipient_alert") in sent_before:
            continue
        sent.append(actions.notify("recipient_alert", rcpt, **ctx))
    for s in sent:
        store.log_action(case_id, "notify", s)
    return {"case_id": case_id, "notified": len(sent), "messages": sent}


def respond(case_id: int, analyst: str = "automatique") -> dict:
    """Réponse complète (utilisée pour une campagne déjà confirmée ou en mode sans n8n)."""
    case = store.get_case(case_id)
    out = {}
    if case["status"] != "confirmed":
        out["confirm"] = confirm(case_id, analyst)
    out["purge"] = purge(case_id)
    out["dns"] = block_dns(case_id)
    out["notify"] = notify_confirmed(case_id, only_new=True)
    return out


def false_positive(case_id: int, analyst: str = "analyste") -> dict:
    case = store.get_case(case_id)
    store.remove_intel(case_id)
    if case["blocked"]:
        actions.dns_unblock(case["blocked"])
    store.update_case(case_id, status="false_positive", verdict="benign", blocked=[])
    ctx = _ctx(case)
    sent = [actions.notify("false_positive", r, **ctx)
            for r in sorted({r["reporter"] for r in store.reports_for_case(case_id) if r["reporter"]})]
    store.log_action(case_id, "false_positive", {"analyst": analyst, "notified": len(sent)})
    for s in sent:
        store.log_action(case_id, "notify", s)
    return {"case_id": case_id, "status": "false_positive", "notified": len(sent)}


def reply_report(report_id: int, template: str) -> dict:
    rep = store.get_report(report_id)
    case = store.get_case(rep["case_id"])
    s = rep["analysis"]["scoring"]
    reasons = "; ".join(f"{h['label'].lower()}" for h in s["hits"] if h["points"] < 0) or "aucun indicateur de fraude détecté"
    n = len({r["reporter"] for r in store.reports_for_case(case["id"])})
    campaign = f"\n{n} collègues ont signalé le même message : il est traité comme une seule campagne.\n" if n > 1 else ""
    msg = actions.notify(template, rep["reporter"], score=rep["score"], verdict=rep["decision"], reasons=reasons + ".",
                         campaign=campaign, case_id=case["id"], subject=rep["subject"],
                         sender=ioc.defang_email(rep["sender"] or ""))
    store.log_action(case["id"], "notify", msg)
    return msg
