"""Simule des employés qui signalent un e-mail (bouton « Signaler » = transfert en pièce jointe .eml).

Exemples (depuis l'hôte, bibliothèque standard uniquement) :
    python scripts/report_email.py --query 'subject:"Mise à jour"' --count 3
    python scripts/report_email.py --id <ID_Mailpit>
    python scripts/report_email.py --file mon_email.eml --reporter alice@corp.local

Chaque message trouvé est transféré à la boîte de signalement par SON destinataire.
"""
from __future__ import annotations

import argparse
import json
import smtplib
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--mailpit", default="http://localhost:8025")
ap.add_argument("--smtp", default="localhost:1025")
ap.add_argument("--report-mailbox", default="phishing@corp.local")
g = ap.add_mutually_exclusive_group(required=True)
g.add_argument("--id", action="append", help="ID Mailpit du message à signaler (répétable)")
g.add_argument("--query", help="recherche Mailpit, ex: 'subject:\"Facture\"'")
g.add_argument("--file", help="fichier .eml local à signaler")
ap.add_argument("--count", type=int, default=1, help="nombre de destinataires qui signalent (avec --query)")
ap.add_argument("--reporter", help="adresse du rapporteur (défaut : destinataire du message)")
ap.add_argument("--format", choices=["rfc822", "eml"], default="rfc822",
                help="rfc822 = pièce jointe message/rfc822 (Outlook/Thunderbird), eml = fichier .eml octet-stream")
args = ap.parse_args()


def api(path: str) -> bytes:
    with urllib.request.urlopen(f"{args.mailpit}{path}", timeout=15) as r:  # noqa: S310 - URL locale
        return r.read()


def send_report(raw: bytes, reporter: str, subject: str) -> None:
    rep = EmailMessage()
    rep["From"] = reporter
    rep["To"] = args.report_mailbox
    rep["Subject"] = f"Signalement : {subject}"
    rep.set_content("Bonjour,\n\nJe vous signale l'e-mail ci-joint qui me semble suspect.\n")
    if args.format == "rfc822":
        from email import policy
        from email.parser import BytesParser
        inner = BytesParser(policy=policy.default).parsebytes(raw)
        rep.add_attachment(inner, filename="suspect.eml")  # message/rfc822 conforme (7bit/8bit)
    else:
        rep.add_attachment(raw, maintype="application", subtype="octet-stream", filename="suspect.eml")
    host, port = args.smtp.split(":")
    with smtplib.SMTP(host, int(port), timeout=15) as s:
        s.send_message(rep)
    print(f"signalé par {reporter} : {subject}")


if args.file:
    raw = Path(args.file).read_bytes()
    send_report(raw, args.reporter or "user@corp.local", Path(args.file).name)
else:
    if args.id:
        msgs = [json.loads(api(f"/api/v1/message/{i}")) for i in args.id]
    else:
        q = urllib.parse.urlencode({"query": args.query, "limit": 200})
        msgs = json.loads(api(f"/api/v1/search?{q}")).get("messages", [])
        msgs = [m for m in msgs if args.report_mailbox not in [t["Address"].lower() for t in m.get("To", [])]]
        msgs = msgs[: args.count]
    if not msgs:
        raise SystemExit("aucun message trouvé")
    for m in msgs:
        raw = api(f"/api/v1/message/{m['ID']}/raw")
        reporter = args.reporter or (m.get("To") or [{"Address": "user@corp.local"}])[0]["Address"]
        send_report(raw, reporter, m.get("Subject", ""))
