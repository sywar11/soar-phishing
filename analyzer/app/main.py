"""API de l'analyzer, appelée par le SOAR (n8n), et tableau de bord analyste."""
from __future__ import annotations

import logging

import requests
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from . import actions, config, dashboard, pipeline, response, store, yara_scan

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("analyzer")
app = FastAPI(title="SOAR Phishing - Analyzer", version="1.0")


@app.on_event("startup")
def _startup() -> None:
    yara_scan.load_rules()
    store.stats()  # crée le schéma


def _case_or_404(case_id: int) -> dict:
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(404, "dossier inconnu")
    return case


# --------------------------------------------------------------------------- santé / stats
@app.get("/health")
def health():
    return {"status": "ok", "online_lookups": config.ENABLE_ONLINE_LOOKUPS,
            "sources": {"virustotal": bool(config.VT_API_KEY), "otx": bool(config.OTX_API_KEY),
                        "urlhaus": bool(config.URLHAUS_AUTH_KEY), "circl": config.ENABLE_ONLINE_LOOKUPS}}


@app.get("/api/stats")
def stats():
    return store.stats()


# --------------------------------------------------------------------------- analyse
@app.post("/api/analyze")
async def analyze(request: Request, is_report: bool = True, online: bool | None = None):
    """Analyse sans enregistrement d'un e-mail brut (corps de la requête = .eml)."""
    raw = await request.body()
    if not raw:
        raise HTTPException(400, "corps vide : envoyer le contenu .eml")
    return pipeline.analyze_raw(raw, is_report=is_report, online=online)


@app.post("/api/reports/mailpit/{mailpit_id}")
def ingest_mailpit(mailpit_id: str):
    """Point d'entrée du workflow n8n : traite le signalement `mailpit_id` de la boîte de signalement."""
    try:
        raw = actions.mailpit_get_raw(mailpit_id)
    except requests.RequestException as exc:
        raise HTTPException(502, f"Mailpit : {exc}") from exc
    return pipeline.ingest(raw, mailpit_id=mailpit_id)


@app.post("/api/reports/raw")
async def ingest_raw(request: Request):
    raw = await request.body()
    if not raw:
        raise HTTPException(400, "corps vide")
    return pipeline.ingest(raw)


@app.post("/api/reports/{report_id}/reply")
def reply(report_id: int, template: str = "received"):
    if template not in actions.TEMPLATES:
        raise HTTPException(400, f"modèle inconnu, choix : {list(actions.TEMPLATES)}")
    if not store.get_report(report_id):
        raise HTTPException(404, "signalement inconnu")
    return response.reply_report(report_id, template)


# --------------------------------------------------------------------------- dossiers
@app.get("/api/cases")
def cases():
    return store.list_cases()


@app.get("/api/cases/{case_id}")
def case(case_id: int):
    c = _case_or_404(case_id)
    c["reports"] = [{k: v for k, v in r.items() if k != "analysis"} for r in store.reports_for_case(case_id)]
    c["actions"] = store.actions_for_case(case_id)
    return c


@app.post("/api/cases/{case_id}/confirm")
def confirm(case_id: int, analyst: str = "analyste"):
    _case_or_404(case_id)
    return response.confirm(case_id, analyst)


@app.post("/api/cases/{case_id}/purge")
def purge(case_id: int):
    _case_or_404(case_id)
    return response.purge(case_id)


@app.post("/api/cases/{case_id}/block-dns")
def block(case_id: int):
    _case_or_404(case_id)
    return response.block_dns(case_id)


@app.post("/api/cases/{case_id}/notify-confirmed")
def notify_confirmed(case_id: int, only_new: bool = False):
    _case_or_404(case_id)
    return response.notify_confirmed(case_id, only_new=only_new)


@app.post("/api/cases/{case_id}/respond")
def respond(case_id: int, analyst: str = "automatique"):
    _case_or_404(case_id)
    return response.respond(case_id, analyst)


@app.post("/api/cases/{case_id}/false-positive")
def false_positive(case_id: int, analyst: str = "analyste"):
    _case_or_404(case_id)
    return response.false_positive(case_id, analyst)


# --------------------------------------------------------------------------- tableau de bord
@app.get("/", response_class=HTMLResponse)
def ui_index():
    return dashboard.index(store.list_cases(), store.stats())


@app.get("/cases/{case_id}", response_class=HTMLResponse)
def ui_case(case_id: int, msg: str = ""):
    c = _case_or_404(case_id)
    return dashboard.case_page(c, store.reports_for_case(case_id), store.actions_for_case(case_id), msg)


@app.post("/cases/{case_id}/decision")
def ui_decision(case_id: int, decision: str = Form(...), analyst: str = Form("analyste")):
    """Bouton analyste. La décision est transmise au workflow n8n de réponse ; à défaut, exécutée directement."""
    _case_or_404(case_id)
    if decision not in ("confirm", "false_positive"):
        raise HTTPException(400, "décision invalide")
    via = "direct"
    if config.N8N_DECISION_WEBHOOK:
        try:
            r = requests.post(config.N8N_DECISION_WEBHOOK, json={"case_id": case_id, "decision": decision,
                                                                 "analyst": analyst}, timeout=120)
            r.raise_for_status()
            via = "n8n"
        except requests.RequestException as exc:
            log.warning("webhook n8n indisponible (%s) : exécution directe", exc)
    if via == "direct":
        if decision == "confirm":
            response.respond(case_id, analyst)
        else:
            response.false_positive(case_id, analyst)
    store.log_action(case_id, "analyst_decision", {"decision": decision, "analyst": analyst, "via": via})
    return RedirectResponse(f"/cases/{case_id}?msg={decision}:{via}", status_code=303)


@app.get("/analyze", response_class=HTMLResponse)
def ui_analyze_form():
    return dashboard.analyze_page(None)


@app.post("/analyze", response_class=HTMLResponse)
async def ui_analyze(file: UploadFile = File(...), is_report: bool = Form(False)):
    raw = await file.read()
    return dashboard.analyze_page(pipeline.analyze_raw(raw, is_report=is_report), file.filename)
