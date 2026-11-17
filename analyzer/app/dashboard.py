"""Tableau de bord analyste (HTML rendu côté serveur, sans dépendance externe)."""
from __future__ import annotations

import datetime as dt
from html import escape as e

from . import config, ioc

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--ink:#1c2230;--muted:#5f6b7d;--line:#e3e6eb;--accent:#2f5bea;
--red:#c62828;--red-bg:#fdecec;--amber:#a15c00;--amber-bg:#fff3e0;--green:#1b7a3d;--green-bg:#e7f5ec;--grey-bg:#eef0f3}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--panel:#1a1f27;--ink:#e6e9ef;--muted:#9aa4b2;--line:#2a313c;
--accent:#7c9cff;--red:#ff8a80;--red-bg:#3a1d1d;--amber:#ffb74d;--amber-bg:#3a2c16;--green:#81c995;--green-bg:#17301f;--grey-bg:#232a34}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:var(--panel);border-bottom:1px solid var(--line);padding:12px 24px;display:flex;gap:24px;align-items:center}
header b{font-size:16px}header a{color:var(--muted);text-decoration:none}header a:hover{color:var(--accent)}
main{max-width:1200px;margin:0 auto;padding:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin-bottom:16px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:0 0 12px}
table{width:100%;border-collapse:collapse}td{overflow-wrap:anywhere}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
tr:last-child td{border-bottom:0}td a{color:var(--accent);text-decoration:none}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.malicious,.confirmed{background:var(--red-bg);color:var(--red)}.suspicious,.awaiting_validation{background:var(--amber-bg);color:var(--amber)}
.benign,.closed_benign,.false_positive{background:var(--green-bg);color:var(--green)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px}.kpi div{font-size:24px;font-weight:700}
.kpi span{color:var(--muted);font-size:12px}
.score{font-size:40px;font-weight:800}.muted{color:var(--muted)}code{font-size:12px;word-break:break-all}
.bar{height:8px;border-radius:4px;background:var(--grey-bg);overflow:hidden;min-width:80px}.bar i{display:block;height:100%}
.grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:16px}@media(max-width:860px){.grid{grid-template-columns:1fr}}
button{font:inherit;padding:8px 16px;border-radius:8px;border:1px solid var(--line);cursor:pointer;background:var(--panel);color:var(--ink)}
button.danger{background:var(--red);border-color:var(--red);color:#fff}button:hover{filter:brightness(1.05)}
.flash{padding:10px 14px;border-radius:8px;background:var(--green-bg);color:var(--green);margin-bottom:16px}
.pos{color:var(--red);font-weight:700}.neg{color:var(--green);font-weight:700}
input[type=file]{margin:8px 0}
"""

STATUS_FR = {"awaiting_validation": "à valider", "confirmed": "phishing confirmé", "false_positive": "faux positif",
             "closed_benign": "classé légitime"}
VERDICT_FR = {"benign": "légitime", "suspicious": "suspect", "malicious": "malveillant"}


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang=fr><head><meta charset=utf-8><meta name=viewport content='width=device-width,"
            f"initial-scale=1'><title>{e(title)}</title><style>{CSS}</style></head><body><header><b>SOAR Phishing</b>"
            f"<a href='/'>Dossiers</a><a href='/analyze'>Analyser un .eml</a><a href='http://localhost:8025' target=_blank>"
            f"Mailpit</a><a href='http://localhost:5680' target=_blank>n8n</a></header><main>{body}</main></body></html>")


def _ts(t) -> str:
    return dt.datetime.fromtimestamp(t).strftime("%d/%m %H:%M:%S") if t else ""


def _pill(cls: str, label: str) -> str:
    return f"<span class='pill {e(cls)}'>{e(label)}</span>"


def _bar(score: int) -> str:
    color = "var(--red)" if score >= config.THRESHOLD_MALICIOUS else "var(--amber)" if score >= config.THRESHOLD_SUSPICIOUS else "var(--green)"
    return f"<div class=bar><i style='width:{max(2, score)}%;background:{color}'></i></div>"


def index(cases: list[dict], stats: dict) -> str:
    by = stats["cases_by_status"]
    kpis = "".join(f"<div class=kpi><div>{v}</div><span>{e(k)}</span></div>" for k, v in [
        ("Signalements reçus", stats["reports"]),
        ("Dossiers à valider", by.get("awaiting_validation", 0)),
        ("Phishing confirmés", by.get("confirmed", 0)),
        ("Classés légitimes", by.get("closed_benign", 0) + by.get("false_positive", 0)),
        ("IOC en renseignement interne", stats["intel_indicators"]),
    ])
    rows = "".join(
        f"<tr><td><a href='/cases/{c['id']}'>#{c['id']}</a></td><td><a href='/cases/{c['id']}'>{e(c['subject'] or '(sans objet)')}</a>"
        f"<div class=muted>{e(ioc.defang_email(c['sender'] or ''))}</div></td>"
        f"<td>{_pill(c['verdict'], VERDICT_FR.get(c['verdict'], c['verdict']))}</td>"
        f"<td><b>{c['max_score']}</b>{_bar(c['max_score'] or 0)}</td>"
        f"<td>{c['report_count']} <span class=muted>({c['reporter_count']} pers.)</span></td>"
        f"<td>{_pill(c['status'], STATUS_FR.get(c['status'], c['status']))}</td><td class=muted>{_ts(c['updated'])}</td></tr>"
        for c in cases) or "<tr><td colspan=7 class=muted>Aucun signalement pour l'instant.</td></tr>"
    return _page("Dossiers phishing", f"<div class=kpis>{kpis}</div><div class=card><h2>Dossiers (1 dossier = 1 campagne)</h2>"
                 f"<table><tr><th>#</th><th>Objet / expéditeur</th><th>Verdict</th><th>Score max</th><th>Signalements</th>"
                 f"<th>Statut</th><th>Mise à jour</th></tr>{rows}</table></div>")


def _hits_table(hits: list[dict]) -> str:
    rows = "".join(
        f"<tr><td class={'pos' if h['points'] > 0 else 'neg'}>{h['points']:+d}</td><td>{e(h['label'])}</td>"
        f"<td><code>{e(h['evidence'])}</code></td></tr>" for h in hits)
    return f"<table><tr><th>Points</th><th>Règle</th><th>Preuve</th></tr>{rows or '<tr><td colspan=3 class=muted>Aucune règle déclenchée</td></tr>'}</table>"


def _analysis_blocks(res: dict) -> str:
    a = res["analysis"]
    h = a["headers"]
    auth = h["auth"]
    head = "".join(f"<tr><th>{k}</th><td><code>{e(str(v))}</code></td></tr>" for k, v in [
        ("From", f"{h['from_name']} <{ioc.defang_email(h['from'])}>"), ("Reply-To", ioc.defang_email(h["reply_to"])),
        ("Return-Path", ioc.defang_email(h["return_path"])), ("Objet", h["subject"]), ("Message-ID", h["message_id"]),
        ("SPF / DKIM / DMARC", f"{auth['spf']} / {auth['dkim']} / {auth['dmarc']}"),
        ("Relais (Received)", " ← ".join(h["received"][:4])), ("Extraction", res.get("extraction", "")),
        ("Encodages", ", ".join(a["body"]["transfer_encodings"]) + (" ; objet encodé RFC 2047" if h["subject_was_encoded"] else "")),
    ])
    urls = "".join(
        f"<tr><td><code>{e(u['defanged'])}</code>"
        + (f"<div class=muted>chaîne : {e(' → '.join(ioc.defang_url(x) for x in u['redirect_chain']))}</div>" if len(u['redirect_chain']) > 1 else "")
        + f"</td><td>{e(', '.join(u['texts'])[:80])}</td><td class=muted>{e(', '.join(u['sources']))}</td></tr>"
        for u in a["urls"][:40]) or "<tr><td colspan=3 class=muted>Aucune URL</td></tr>"
    atts = "".join(
        f"<tr><td>{e(x['filename'])}<div class=muted>{e(x['content_type'])} · {x['size']} o</div></td><td><code>{x['sha256']}</code>"
        + "".join(f"<div class=muted>↳ {e(m['filename'])}</div>" for m in x["zip_members"][:10]) + "</td></tr>"
        for x in a["attachments"]) or "<tr><td colspan=2 class=muted>Aucune pièce jointe</td></tr>"
    yara = "".join(f"<tr><td>{e(y['rule'])}</td><td>{e(y['file'])}</td><td>{e(y['description'])}</td></tr>" for y in res["yara"]) \
        or "<tr><td colspan=3 class=muted>Aucune correspondance</td></tr>"
    intel = "".join(f"<tr><td>{e(i['source'])}</td><td><code>{e(ioc.defang_url(i['indicator']) if '://' in i['indicator'] else i['indicator'])}</code></td>"
                    f"<td>{_pill('malicious' if i['verdict'] == 'malicious' else 'suspicious' if i['verdict'] == 'suspicious' else 'benign', i['verdict'])}</td>"
                    f"<td class=muted>{e(i.get('detail', ''))}</td></tr>" for i in res["intel"]) \
        or "<tr><td colspan=4 class=muted>Aucune source interrogée (clés API absentes ou mode hors ligne)</td></tr>"
    return (f"<div class=card><h2>En-têtes</h2><table>{head}</table></div>"
            f"<div class=card><h2>URL (défanisées)</h2><table><tr><th>URL</th><th>Texte affiché</th><th>Source</th></tr>{urls}</table></div>"
            f"<div class=card><h2>Pièces jointes</h2><table>{atts}</table></div>"
            f"<div class=card><h2>YARA</h2><table><tr><th>Règle</th><th>Fichier</th><th>Description</th></tr>{yara}</table></div>"
            f"<div class=card><h2>Réputation</h2><table><tr><th>Source</th><th>Indicateur</th><th>Verdict</th><th>Détail</th></tr>{intel}</table></div>")


def case_page(case: dict, reports: list[dict], actions: list[dict], msg: str) -> str:
    best = max(reports, key=lambda r: r["score"]) if reports else None
    flash = f"<div class=flash>Décision enregistrée : {e(msg)}</div>" if msg else ""
    buttons = ""
    if case["status"] in ("awaiting_validation", "closed_benign"):
        buttons = (f"<form method=post action='/cases/{case['id']}/decision' style='display:flex;gap:8px;flex-wrap:wrap;margin-top:12px'>"
                   f"<input type=hidden name=analyst value='analyste'>"
                   f"<button class=danger name=decision value=confirm>Confirmer le phishing : purger et bloquer</button>"
                   f"<button name=decision value=false_positive>Faux positif : légitime</button></form>")
    elif case["status"] == "confirmed":
        buttons = (f"<form method=post action='/cases/{case['id']}/decision' style='margin-top:12px'>"
                   f"<button name=decision value=false_positive>Annuler : faux positif</button></form>")
    iocs = case["iocs"] or {}
    ioc_rows = "".join(f"<tr><th>{k}</th><td>{'<br>'.join('<code>' + e(x) + '</code>' for x in v[:15]) or '<span class=muted>-</span>'}</td></tr>"
                       for k, v in [("Domaines", [ioc.defang_domain(d) for d in iocs.get("domains", [])]),
                                    ("URL", [ioc.defang_url(u) for u in iocs.get("urls", [])]),
                                    ("Hash SHA256", iocs.get("hashes", [])),
                                    ("Expéditeurs", [ioc.defang_email(s) for s in iocs.get("senders", [])]),
                                    ("Domaines bloqués", [ioc.defang_domain(d) for d in case["blocked"] or []])])
    rep_rows = "".join(f"<tr><td>#{r['id']}</td><td>{e(r['reporter'])}{' <span class=muted>(doublon)</span>' if r['duplicate'] else ''}</td>"
                       f"<td>{e(r['subject'])}</td><td><b>{r['score']}</b></td><td>{_pill(r['decision'], VERDICT_FR.get(r['decision'], ''))}</td>"
                       f"<td class=muted>{_ts(r['created'])}</td></tr>" for r in reports)
    purged = "".join(f"<tr><td>{e(', '.join(p['recipients']))}</td><td>{e(p['subject'])}</td><td class=muted>{e(', '.join(p['matched_on']))[:90]}</td></tr>"
                     for p in case["purged"] or []) or "<tr><td colspan=3 class=muted>Aucune purge</td></tr>"
    act_rows = "".join(f"<tr><td class=muted>{_ts(a['created'])}</td><td>{e(a['action'])}</td><td><code>{e(str(a['detail']))[:220]}</code></td></tr>"
                       for a in actions)
    summary = (f"<div class=card><div style='display:flex;gap:24px;align-items:center;flex-wrap:wrap'><div class=score>{case['max_score']}</div>"
               f"<div><h1>Dossier #{case['id']} · {e(case['subject'] or '')}</h1><div class=muted>{e(ioc.defang_email(case['sender'] or ''))} · "
               f"{len(reports)} signalement(s) par {len({r['reporter'] for r in reports})} personne(s)</div>"
               f"<div style='margin-top:6px'>{_pill(case['verdict'], VERDICT_FR.get(case['verdict'], ''))} "
               f"{_pill(case['status'], STATUS_FR.get(case['status'], ''))}</div></div></div>{buttons}</div>")
    detail = ""
    if best:
        res = best["analysis"]
        detail = (f"<div class=card><h2>Pourquoi ce score ? (signalement #{best['id']})</h2>{_hits_table(res['scoring']['hits'])}"
                  f"<p class=muted>Seuils : suspect ≥ {res['scoring']['thresholds']['suspicious']}, malveillant ≥ {res['scoring']['thresholds']['malicious']}</p></div>"
                  + _analysis_blocks(res))
    side = (f"<div class=card><h2>Indicateurs (IOC)</h2><table>{ioc_rows}</table></div>"
            f"<div class=card><h2>Copies purgées</h2><table><tr><th>Destinataires</th><th>Objet</th><th>Correspondance</th></tr>{purged}</table></div>")
    bottom = (f"<div class=card><h2>Signalements de la campagne</h2><table><tr><th>#</th><th>Rapporteur</th><th>Objet</th><th>Score</th>"
              f"<th>Décision</th><th>Reçu</th></tr>{rep_rows}</table></div>"
              f"<div class=card><h2>Journal des actions</h2><table>{act_rows}</table></div>")
    return _page(f"Dossier {case['id']}", f"{flash}{summary}<div class=grid><div>{detail}</div><div>{side}</div></div>{bottom}")


def analyze_page(res: dict | None, filename: str | None = None) -> str:
    form = ("<div class=card><h2>Analyser un fichier .eml (sans enregistrement)</h2><form method=post enctype=multipart/form-data>"
            "<input type=file name=file accept='.eml,message/rfc822' required><br><label><input type=checkbox name=is_report value=true> "
            "C'est un signalement (l'e-mail suspect est en pièce jointe)</label><br><br><button>Analyser</button></form></div>")
    if not res:
        return _page("Analyser un e-mail", form)
    s = res["scoring"]
    top = (f"<div class=card><div style='display:flex;gap:24px;align-items:center'><div class=score>{s['score']}</div><div><h1>{e(filename or '')}</h1>"
           f"{_pill(s['decision'], VERDICT_FR.get(s['decision'], ''))}</div></div></div>"
           f"<div class=card><h2>Pourquoi ce score ?</h2>{_hits_table(s['hits'])}</div>")
    return _page("Résultat d'analyse", form + top + _analysis_blocks(res))
