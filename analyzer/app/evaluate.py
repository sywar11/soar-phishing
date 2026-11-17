"""Évaluation du score sur un jeu d'essai étiqueté -> matrice de confusion.

Format attendu (monté dans le conteneur sur /dataset) :
    /dataset/labels.csv   colonnes : file,label[,family]
                          label = phishing | legit   (spam, newsletter… => legit : ce n'est pas du phishing)
    /dataset/emails/<file>   e-mails .eml ORIGINAUX (pas les signalements)

Usage :
    docker compose exec analyzer python -m app.evaluate                 # hors ligne, reproductible
    docker compose exec analyzer python -m app.evaluate --online        # avec les API de réputation
    docker compose exec analyzer python -m app.evaluate --as-report     # emballe chaque e-mail dans un signalement

Sorties : /dataset/results/{confusion_matrix.md, results.csv, metrics.json}
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

from . import config, pipeline

POSITIVE = {"phishing", "phish", "malicious", "1", "true"}


def wrap_as_report(raw: bytes, n: int) -> bytes:
    """Simule un employé qui transfère l'e-mail « en pièce jointe » (alterne message/rfc822 et .eml octet-stream)."""
    rep = EmailMessage()
    rep["From"] = f"user{n:03d}@corp.local"
    rep["To"] = config.REPORT_MAILBOX
    rep["Subject"] = "Signalement : e-mail suspect"
    rep.set_content("E-mail suspect transféré en pièce jointe.")
    if n % 2:
        rep.add_attachment(raw, maintype="application", subtype="octet-stream", filename="suspect.eml")
    else:
        rep.add_attachment(raw, maintype="message", subtype="rfc822", filename="suspect.eml")
    return rep.as_bytes()


def confusion(rows: list[dict], threshold: int) -> dict:
    tp = sum(1 for r in rows if r["truth"] and r["score"] >= threshold)
    fn = sum(1 for r in rows if r["truth"] and r["score"] < threshold)
    fp = sum(1 for r in rows if not r["truth"] and r["score"] >= threshold)
    tn = sum(1 for r in rows if not r["truth"] and r["score"] < threshold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    acc = (tp + tn) / len(rows) if rows else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"threshold": threshold, "tp": tp, "fn": fn, "fp": fp, "tn": tn, "precision": round(precision, 3),
            "recall": round(recall, 3), "f1": round(f1, 3), "accuracy": round(acc, 3), "fpr": round(fpr, 3)}


AUTH_RULES = {"spf_fail", "spf_softfail", "dkim_fail", "dmarc_fail", "auth_all_pass", "newsletter"}


def score_without_auth(rules: str) -> int:
    total = 0
    for part in filter(None, rules.split(";")):
        name, points = part.rstrip(")").split("(")
        if name not in AUTH_RULES:
            total += int(points)
    return max(0, min(100, total))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="/dataset")
    ap.add_argument("--online", action="store_true", help="interroger les API de réputation")
    ap.add_argument("--as-report", action="store_true", help="passer par l'extraction d'un signalement")
    ap.add_argument("--split", help="n'évaluer que cette partie du jeu (colonne split de labels.csv : dev ou test)")
    ap.add_argument("--out", default="results", help="dossier de sortie, relatif au jeu d'essai")
    args = ap.parse_args(argv)

    root = Path(args.dataset)
    labels = root / "labels.csv"
    if not labels.exists():
        print(f"Fichier {labels} introuvable (colonnes : file,label[,family]).", file=sys.stderr)
        return 2
    with labels.open(encoding="utf-8-sig") as f:
        entries = list(csv.DictReader(f))
    if args.split:
        entries = [e for e in entries if e.get("split") == args.split]

    rows = []
    for i, ent in enumerate(entries):
        path = root / "emails" / ent["file"]
        if not path.exists():
            print(f"absent : {path}", file=sys.stderr)
            continue
        raw = path.read_bytes()
        if args.as_report:
            raw = wrap_as_report(raw, i)
        res = pipeline.analyze_raw(raw, is_report=args.as_report, online=args.online, use_local_intel=False)
        s = res["scoring"]
        rows.append({
            "file": ent["file"], "family": ent.get("family", ""), "label": ent["label"],
            "truth": ent["label"].strip().lower() in POSITIVE, "score": s["score"], "decision": s["decision"],
            "extraction": res["extraction"], "rules": ";".join(f"{h['rule']}({h['points']:+d})" for h in s["hits"]),
        })
    if not rows:
        print("Aucun e-mail évalué.", file=sys.stderr)
        return 2

    main_cm = confusion(rows, config.THRESHOLD_SUSPICIOUS)
    strict_cm = confusion(rows, config.THRESHOLD_MALICIOUS)
    sweep = [confusion(rows, t) for t in range(10, 100, 10)]
    # Robustesse : mêmes e-mails, sans les règles d'authentification. Les en-têtes SPF/DKIM/DMARC et les autres
    # marqueurs d'époque peuvent séparer artificiellement un corpus légitime ancien d'un corpus de phishing récent.
    no_auth = [{**r, "score": score_without_auth(r["rules"])} for r in rows]
    no_auth_cm = confusion(no_auth, config.THRESHOLD_SUSPICIOUS)
    by_family = {}
    for fam in sorted({r["family"] for r in rows}):
        sub = [r for r in rows if r["family"] == fam]
        by_family[fam] = {"n": len(sub), "au_seuil_suspect": sum(r["score"] >= config.THRESHOLD_SUSPICIOUS for r in sub),
                          "au_seuil_malveillant": sum(r["score"] >= config.THRESHOLD_MALICIOUS for r in sub)}
    rule_freq = {"phishing": Counter(), "legit": Counter()}
    for r in rows:
        for part in filter(None, r["rules"].split(";")):
            rule_freq["phishing" if r["truth"] else "legit"][part.split("(")[0]] += 1

    out = root / args.out
    out.mkdir(parents=True, exist_ok=True)
    with (out / "results.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    (out / "metrics.json").write_text(json.dumps({"main": main_cm, "strict": strict_cm, "sweep": sweep,
                                                  "no_auth": no_auth_cm, "by_family": by_family,
                                                  "rule_frequency": rule_freq, "n": len(rows), "split": args.split,
                                                  "online": args.online, "as_report": args.as_report},
                                                 indent=2, ensure_ascii=False), encoding="utf-8")

    def table(cm: dict) -> str:
        return (f"| | Prédit phishing | Prédit légitime |\n|---|---|---|\n"
                f"| **Phishing réel** | VP = {cm['tp']} | FN = {cm['fn']} |\n"
                f"| **Légitime réel** | FP = {cm['fp']} | VN = {cm['tn']} |\n\n"
                f"Précision {cm['precision']} · Rappel {cm['recall']} · F1 {cm['f1']} · "
                f"Exactitude {cm['accuracy']} · Taux de faux positifs {cm['fpr']}\n")

    errors = [r for r in rows if (r["truth"] and r["score"] < config.THRESHOLD_SUSPICIOUS)
              or (not r["truth"] and r["score"] >= config.THRESHOLD_SUSPICIOUS)]
    md = [f"# Matrice de confusion du score\n",
          f"Jeu d'essai : {len(rows)} e-mails ({sum(r['truth'] for r in rows)} phishing, "
          f"{sum(not r['truth'] for r in rows)} légitimes). Réputation en ligne : {'oui' if args.online else 'non'}. "
          f"Passage par un signalement : {'oui' if args.as_report else 'non'}.\n",
          f"## Seuil « suspect » (score ≥ {config.THRESHOLD_SUSPICIOUS}) : envoi en validation\n", table(main_cm),
          f"## Seuil « malveillant » (score ≥ {config.THRESHOLD_MALICIOUS})\n", table(strict_cm),
          "## Balayage des seuils\n", "| Seuil | VP | FN | FP | VN | Précision | Rappel | F1 |", "|---|---|---|---|---|---|---|---|"]
    md += [f"| {c['threshold']} | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} | {c['precision']} | {c['recall']} | {c['f1']} |"
           for c in sweep]
    md += ["\n## Erreurs au seuil principal\n", "| Fichier | Famille | Vérité | Score | Règles |", "|---|---|---|---|---|"]
    md += [f"| {r['file']} | {r['family']} | {r['label']} | {r['score']} | {r['rules'] or '-'} |" for r in errors] or ["| - | | | | |"]
    (out / "confusion_matrix.md").write_text("\n".join(md) + "\n", encoding="utf-8")

    print("\n".join(md[:7]))
    print(f"\nRésultats écrits dans {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
