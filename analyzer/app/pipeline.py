"""Chaîne de traitement d'un signalement : extraction -> analyse -> YARA -> réputation -> score -> regroupement."""
from __future__ import annotations

import logging
import threading
import time
from email.utils import parseaddr

from . import actions, cluster, config, enrich, ioc, parser, scoring, store, thehive, yara_scan

log = logging.getLogger(__name__)


def _local_intel(indicator: str):
    return store.lookup_intel(indicator)


def analyze_raw(raw: bytes, *, is_report: bool = True, online: bool | None = None, use_local_intel: bool = True) -> dict:
    report = parser.parse_bytes(raw)
    _, reporter = parseaddr(str(report.get("From", "") or ""))
    original, method = parser.extract_reported(report) if is_report else (report, "direct")
    a = parser.analyze_message(original)

    online_eff = config.ENABLE_ONLINE_LOOKUPS if online is None else online
    if config.FOLLOW_REDIRECTS and online_eff:
        for u in a["urls"][:10]:
            chain = enrich.follow_redirects(u["final_url"])
            if len(chain) > 1:
                u["redirect_chain"] += chain[1:]
                u["final_url"] = chain[-1]
                u["host"] = ioc.host_of(chain[-1])
                u["domain"] = ioc.registered_domain(u["host"])
                u["defanged"] = ioc.defang_url(chain[-1])
                u["key"] = ioc.url_key(chain[-1])

    yara_hits = yara_scan.scan(a["_blobs"])
    intel = enrich.enrich(a, _local_intel if use_local_intel else (lambda _i: None), online=online_eff)
    result = scoring.score(a, yara_hits, intel)
    public = {k: v for k, v in a.items() if not k.startswith("_")}
    return {
        "reporter": reporter.lower(),
        "extraction": method,
        "analysis": public,
        "yara": yara_hits,
        "intel": intel,
        "scoring": result,
        "keys": cluster.keys_for(a),
        "iocs": iocs_of(a),
    }


def iocs_of(a: dict) -> dict:
    h = a["headers"]
    sender_domains = []
    if h["from_domain"] and ioc.registered_domain(h["from_domain"]) not in config.INTERNAL_DOMAINS:
        sender_domains.append(h["from_domain"])
    if h["reply_to"]:
        sender_domains.append(ioc.email_domain(h["reply_to"]))
    return {
        "urls": sorted({u["final_url"] for u in a["urls"]}),
        "url_keys": sorted({u["key"] for u in a["urls"] if u["domain"] not in config.NEVER_BLOCK}),
        "hosts": sorted({u["host"] for u in a["urls"] if u["host"]}),
        "domains": sorted({u["domain"] for u in a["urls"] if u["domain"] and u["domain"] not in config.NEVER_BLOCK}),
        "hashes": sorted({x["sha256"] for x in a["attachments"]}
                         | {m["sha256"] for x in a["attachments"] for m in x["zip_members"] if m.get("sha256")}),
        "senders": [h["from"]] if h["from"] else [],
        "sender_domains": sorted(set(sender_domains)),
        "message_ids": [h["message_id"]] if h["message_id"] else [],
        "subjects": [h["subject"]] if h["subject"] else [],
    }


def _merge_iocs(old: dict, new: dict) -> dict:
    out = dict(old or {})
    for k, v in new.items():
        out[k] = sorted(set(out.get(k, [])) | set(v))
    return out


RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
_ingest_lock = threading.Lock()


def ingest(raw: bytes, mailpit_id: str | None = None) -> dict:
    """Traite un signalement et le rattache à un dossier. Renvoie la « route » à suivre pour le SOAR."""
    if mailpit_id:
        prev = store.report_by_mailpit_id(mailpit_id)
        if prev:
            return {"report_id": prev["id"], "case_id": prev["case_id"], "route": "already_processed",
                    "score": prev["score"], "decision": prev["decision"]}

    res = analyze_raw(raw)
    s = res["scoring"]
    h = res["analysis"]["headers"]
    reporter = res["reporter"]

    # n8n envoie les signalements en parallèle : « chercher le dossier puis le créer » doit être atomique,
    # sinon chaque requête crée son propre dossier. L'analyse, parfois lente, reste hors du verrou.
    # Un verrou de processus suffit : l'analyzer tourne avec un seul worker (voir le Dockerfile).
    with _ingest_lock:
        if mailpit_id:
            prev = store.report_by_mailpit_id(mailpit_id)
            if prev:
                return {"report_id": prev["id"], "case_id": prev["case_id"], "route": "already_processed",
                        "score": prev["score"], "decision": prev["decision"]}
        duplicate = store.same_message_reported(h["message_id"], reporter) is not None

        since = time.time() - config.CAMPAIGN_WINDOW_DAYS * 86400
        match = store.find_case_by_keys(res["keys"], since)
        new_case = match is None
        if new_case:
            case_id = store.create_case(s["decision"], s["score"], h["from"], h["subject"], res["iocs"])
            matched_on: list[str] = []
        else:
            case_id, matched_on = match
            case = store.get_case(case_id)
            fields = {"iocs": _merge_iocs(case["iocs"], res["iocs"])}
            if s["score"] > (case["max_score"] or 0):
                fields["max_score"] = s["score"]
            if RANK[s["decision"]] > RANK.get(case["verdict"], 0):
                fields["verdict"] = s["decision"]
                fields["title"] = f"[{s['decision']}] {case['subject'][:120]}"
                if case["status"] == "closed_benign":
                    fields["status"] = "awaiting_validation"
            store.update_case(case_id, **fields)

        report_id = store.add_report(case_id, reporter, mailpit_id, h["message_id"], h["subject"], h["from"],
                                     s["score"], s["decision"], duplicate, res)
        store.add_keys(case_id, res["keys"])
        case = store.get_case(case_id)
        reports = store.reports_for_case(case_id)
        store.log_action(case_id, "report_received", {"report_id": report_id, "reporter": reporter, "score": s["score"],
                                                      "decision": s["decision"], "new_case": new_case,
                                                      "matched_on": matched_on, "duplicate": duplicate})

    if mailpit_id:
        try:
            actions.mailpit_mark_read([mailpit_id])
        except Exception:  # noqa: BLE001
            pass

    if duplicate:
        route = "duplicate"
    elif case["status"] == "confirmed":
        route = "known_campaign"           # campagne déjà validée : réponse automatique
    elif case["status"] == "false_positive":
        route = "known_false_positive"
    elif case["status"] == "closed_benign":
        route = "benign"
    else:
        route = "pending_validation"

    if new_case and case["status"] == "awaiting_validation" and thehive.enabled():
        alert = thehive.create_alert(case, s, len(reports))
        if alert:
            store.update_case(case_id, thehive_id=alert)

    return {
        "report_id": report_id,
        "case_id": case_id,
        "new_case": new_case,
        "matched_on": matched_on,
        "route": route,
        "score": s["score"],
        "decision": s["decision"],
        "case_status": case["status"],
        "campaign_reports": len(reports),
        "campaign_reporters": len({r["reporter"] for r in reports}),
        "reporter": reporter,
        "subject": h["subject"],
        "top_reasons": [f"{x['label']} ({x['points']:+d})" for x in s["hits"][:5]],
        "case_url": f"{config.PUBLIC_ANALYZER_URL}/cases/{case_id}",
    }
