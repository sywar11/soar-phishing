"""Score explicable 0-100.

Chaque règle qui se déclenche ajoute (ou retire) des points et laisse une preuve lisible.
Le score final est la somme bornée à [0, 100] ; la décision dépend de deux seuils :
    score <  THRESHOLD_SUSPICIOUS  -> "benign"     (classement automatique, réponse au rapporteur)
    score <  THRESHOLD_MALICIOUS   -> "suspicious" (dossier, validation analyste)
    score >= THRESHOLD_MALICIOUS   -> "malicious"  (dossier prioritaire, validation avant purge)
Les poids sont documentés dans WEIGHTS et justifiés dans docs/score.md.
"""
from __future__ import annotations

import re
import unicodedata

from . import config, ioc, lookalike

# id: (points, libellé)
WEIGHTS: dict[str, tuple[int, str]] = {
    # --- Authentification de l'expéditeur
    "spf_fail": (15, "SPF en échec"),
    "spf_softfail": (8, "SPF softfail"),
    "dkim_fail": (10, "Signature DKIM invalide"),
    "dmarc_fail": (15, "DMARC en échec"),
    # 0 point : un attaquant authentifie facilement son propre domaine ; la preuve reste affichée à l'analyste
    "auth_all_pass": (0, "SPF, DKIM et DMARC valides"),
    # --- Expéditeur
    "sender_lookalike": (30, "Domaine expéditeur imitant une marque protégée"),
    "display_name_spoof": (20, "Nom affiché usurpant une marque/un service interne"),
    "external_claims_internal": (15, "Expéditeur externe se présentant comme interne"),
    "reply_to_mismatch": (15, "Reply-To vers un autre domaine que l'expéditeur"),
    "freemail_reply_to": (10, "Réponses redirigées vers une messagerie gratuite"),
    "internal_authenticated": (-15, "Expéditeur interne authentifié"),
    # --- URL
    "url_lookalike": (30, "Lien vers un domaine imitant une marque protégée"),
    "link_text_mismatch": (20, "Le texte du lien affiche un autre domaine que la cible réelle"),
    "url_ip": (10, "Lien vers une adresse IP"),
    "url_shortener": (10, "Lien raccourci (cible masquée)"),
    "url_redirect_wrapper": (5, "Lien redirigé vers un domaine externe"),
    "url_suspicious_tld": (5, "Extension de domaine souvent abusée"),
    "url_credential_path": (10, "Lien vers une page de connexion/vérification hors domaine légitime"),
    "html_form": (5, "Formulaire HTML dans le corps de l'e-mail"),
    "html_password_field": (25, "Champ de mot de passe dans le corps de l'e-mail"),
    # --- Contenu
    "urgency": (10, "Ton d'urgence / menace"),
    "urgency_strong": (5, "Nombreuses formules d'urgence"),
    "credential_request": (10, "Demande d'identifiants / de mot de passe"),
    "account_action": (20, "Demande d'action sur le compte ou la messagerie"),
    "generic_greeting": (5, "Formule d'appel générique"),
    "payment_change": (15, "Demande de virement / changement de coordonnées bancaires"),
    # --- Pièces jointes
    "dangerous_extension": (25, "Pièce jointe à extension dangereuse"),
    "double_extension": (20, "Double extension trompeuse (ex: facture.pdf.exe)"),
    "html_attachment": (10, "Pièce jointe HTML"),
    "encrypted_archive": (10, "Archive chiffrée (contourne l'antivirus)"),
    "yara": (0, "Règle YARA"),  # points = méta « score » de la règle (max 40)
    "known_good_files": (-10, "Toutes les pièces jointes sont des fichiers connus légitimes (CIRCL)"),
    # --- Réputation
    "intel_malicious": (50, "Indicateur malveillant selon le renseignement"),
    "intel_suspicious": (20, "Indicateur suspect selon le renseignement"),
    # --- Signaux de légitimité
    "newsletter": (-10, "Envoi en masse légitime (List-Unsubscribe + authentifié)"),
}

DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "lnk", "iso",
    "img", "vhd", "msi", "jar", "docm", "xlsm", "pptm", "dotm", "xlam", "one", "cpl", "reg", "chm",
}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip", "rar", "html"}
FREEMAIL = {
    "gmail.com", "yahoo.com", "yahoo.fr", "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr", "live.com",
    "live.fr", "aol.com", "gmx.com", "gmx.fr", "proton.me", "protonmail.com", "mail.ru", "yandex.ru", "laposte.net",
    "orange.fr", "free.fr", "icloud.com",
}
INTERNAL_SERVICE_NAMES = (
    "service it", "support it", "helpdesk", "help desk", "service informatique", "support informatique",
    "administrateur", "admin", "ressources humaines", "rh ", "direction", "comptabilit", "paie", "it support",
    "security team", "équipe sécurité", "equipe securite", "webmaster", "messagerie",
)

URGENCY = [
    r"urgent", r"imm[ée]diat", r"sous 24 ?h", r"within 24 hours", r"dans les 24", r"derni(er|ère) (avis|rappel)",
    r"final (notice|warning)", r"suspendu", r"suspended", r"bloqu[ée]", r"locked", r"d[ée]sactiv", r"deactivat",
    r"expir", r"action requise", r"action required", r"sans r[ée]ponse", r"failure to", r"faute de",
    r"supprim[ée]", r"will be deleted", r"avant ce soir", r"aujourd'hui", r"today", r"asap", r"au plus vite",
    r"inhabituel", r"unusual (sign|activity)", r"tentative de connexion", r"poursuites", r"amende",
]
CREDENTIALS = [
    r"mot de passe", r"password", r"identifiants?", r"credentials", r"v[ée]rifi(er|ez|cation) (votre|your) (compte|account|identit)",
    r"verify your (account|identity)", r"confirm(er|ez)? (votre|your) (compte|account|identit|informations)",
    r"reconnect", r"se reconnecter", r"reconnectez", r"sign in", r"connectez-vous", r"log ?in", r"mettre à jour vos informations",
    r"update your (payment|billing|account)", r"code (de )?v[ée]rification", r"quota de (votre )?(bo[iî]te|messagerie)",
    r"mailbox (is )?full", r"bo[iî]te (aux lettres|mail) (est )?pleine",
]
PAYMENT = [
    r"\biban\b", r"\brib\b", r"coordonn[ée]es bancaires", r"bank (details|account)", r"virement", r"wire transfer",
    r"changement de (compte|banque)", r"new (bank|account) details", r"carte cadeau", r"gift card", r"paiement en attente",
]
ACCOUNT_ACTION = [
    r"(verify|validate|confirm|re-?activate|update).{0,30}(account|e-?mail|identity|mailbox|details|information)",
    r"(v[ée]rifi|valid|confirm|r[ée]activ|mett).{0,30}(compte|identit|messagerie|bo[iî]te|informations)",
    r"password.{0,40}(expir|reset|chang|updat)", r"mot de passe.{0,40}(expir|r[ée]initialis|chang)",
    r"(mailbox|e-?mail|storage|quota).{0,40}(full|limit|exceed|upgrade)",
    r"(messagerie|bo[iî]te|quota).{0,40}(pleine|limite|d[ée]pass)",
    r"(pending|undelivered|incoming|held|blocked) (e-?)?(mail|message)s?", r"messages? (en attente|bloqu|non distribu)",
    r"your (e-?mail )?account", r"votre compte",
]
GENERIC_GREETING = [r"dear (customer|user|client|member|valued)", r"cher (client|utilisateur|membre)", r"ch[èe]re? (cliente|utilisatrice)"]
# mot entier : « auth » ne doit pas correspondre à « author », ni « update » à une simple mise à jour logicielle
CREDENTIAL_PATH = re.compile(r"(?<![a-z0-9])(login|log-in|signin|sign-in|logon|verify|verification|accounts?|secure|auth|oauth|"
                             r"password|webmail|owa|confirm|connexion|wp-admin|validate)(?![a-z0-9])", re.I)
# le texte du lien doit être lui-même une adresse : citer un domaine dans une phrase n'est pas une tromperie
LINK_AS_ADDRESS = re.compile(r"(?i)^\s*(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]\S*)?\s*$")
FILE_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".htm", ".html", ".txt", ".php", ".asp")


def _norm(s: str) -> str:
    return unicodedata.normalize("NFKC", s or "").lower()


def _count(patterns: list[str], text: str) -> list[str]:
    found = []
    for p in patterns:
        m = re.search(p, text, re.I)
        if m:
            found.append(m.group(0))
    return found


def _add(hits: list[dict], rule: str, evidence: str, points: int | None = None) -> None:
    pts, label = WEIGHTS[rule]
    hits.append({"rule": rule, "label": label, "points": pts if points is None else points, "evidence": evidence})


def score(analysis: dict, yara_hits: list[dict], intel: list[dict]) -> dict:
    h = analysis["headers"]
    hits: list[dict] = []
    from_dom = ioc.registered_domain(h["from_domain"])
    internal = {ioc.registered_domain(d) for d in config.INTERNAL_DOMAINS}
    is_internal_sender = from_dom in internal
    auth = h["auth"]

    # ---------------- authentification
    if auth["spf"] in ("fail", "permerror"):
        _add(hits, "spf_fail", f"spf={auth['spf']}")
    elif auth["spf"] == "softfail":
        _add(hits, "spf_softfail", "spf=softfail")
    if auth["dkim"] in ("fail", "permerror"):
        _add(hits, "dkim_fail", f"dkim={auth['dkim']}")
    if auth["dmarc"] in ("fail", "permerror"):
        _add(hits, "dmarc_fail", f"dmarc={auth['dmarc']}")
    all_pass = auth["spf"] == "pass" and auth["dkim"] == "pass" and auth["dmarc"] == "pass"
    if all_pass:
        _add(hits, "auth_all_pass", "spf=pass dkim=pass dmarc=pass")

    # ---------------- expéditeur
    la = lookalike.check(h["from_domain"])
    if la:
        _add(hits, "sender_lookalike", f"{ioc.defang_domain(h['from_domain'])} imite {la['legit']} ({la['technique']})")
    name = _norm(h["from_name"])
    if name and not is_internal_sender:
        name_words = set(re.findall(r"[a-z0-9]+", lookalike.normalize(name)))
        brand_in_name = next((b for b in lookalike.BRANDS.values() if len(b) >= 4 and b in name_words), None)
        if brand_in_name and ioc.registered_domain(h["from_domain"]) not in lookalike.LEGIT_REG_DOMAINS:
            _add(hits, "display_name_spoof", f"« {h['from_name']} » <{ioc.defang_email(h['from'])}>")
        elif any(s in name + " " for s in INTERNAL_SERVICE_NAMES):
            _add(hits, "external_claims_internal", f"« {h['from_name']} » envoyé depuis {ioc.defang_domain(from_dom)}")
    if h["reply_to"]:
        rt_dom = ioc.registered_domain(ioc.email_domain(h["reply_to"]))
        if rt_dom and rt_dom != from_dom:
            _add(hits, "reply_to_mismatch", f"From {from_dom} → Reply-To {ioc.defang_email(h['reply_to'])}")
            if rt_dom in FREEMAIL:
                _add(hits, "freemail_reply_to", ioc.defang_email(h["reply_to"]))
    if is_internal_sender and (all_pass or (auth["spf"] is None and auth["dkim"] is None and h["received"] == [])):
        # interne : soit authentifié, soit déposé directement sur le serveur interne (aucun relais externe)
        if not any(r["rule"] in ("spf_fail", "dkim_fail", "dmarc_fail") for r in hits):
            _add(hits, "internal_authenticated", h["from"])

    # ---------------- URL
    seen_rules: set[str] = set()
    sender_and_brands = {from_dom} | lookalike.LEGIT_REG_DOMAINS | internal
    for u in analysis["urls"]:
        host, dom = u["host"], u["domain"]
        dfg = u["defanged"]
        if "url_lookalike" not in seen_rules:
            lu = lookalike.check(host)
            if lu:
                _add(hits, "url_lookalike", f"{dfg} imite {lu['legit']} ({lu['technique']})")
                seen_rules.add("url_lookalike")
        if "link_text_mismatch" not in seen_rules:
            for t in u["texts"]:
                m = LINK_AS_ADDRESS.match(t)
                if m:
                    shown = ioc.registered_domain(m.group(1).lower())
                    if shown and shown != dom and not shown.endswith(FILE_SUFFIXES) and shown.split(".")[-1].isalpha():
                        _add(hits, "link_text_mismatch", f"texte « {t[:60]} » → {dfg}")
                        seen_rules.add("link_text_mismatch")
                        break
        if ioc.is_ip(host) and "url_ip" not in seen_rules:
            _add(hits, "url_ip", dfg)
            seen_rules.add("url_ip")
        if ioc.host_of(u["url"]) in ioc.URL_SHORTENERS and "url_shortener" not in seen_rules:
            _add(hits, "url_shortener", ioc.defang_url(u["url"]))
            seen_rules.add("url_shortener")
        if len(u["redirect_chain"]) > 1 and dom not in sender_and_brands and "url_redirect_wrapper" not in seen_rules:
            _add(hits, "url_redirect_wrapper", " → ".join(ioc.defang_url(x) for x in u["redirect_chain"]))
            seen_rules.add("url_redirect_wrapper")
        if ioc.tld(host) in ioc.SUSPICIOUS_TLDS and "url_suspicious_tld" not in seen_rules:
            _add(hits, "url_suspicious_tld", dfg)
            seen_rules.add("url_suspicious_tld")
        if (dom not in sender_and_brands and "url_credential_path" not in seen_rules
                and CREDENTIAL_PATH.search(u["final_url"].split("?", 1)[0].split("//", 1)[-1])):
            _add(hits, "url_credential_path", dfg)
            seen_rules.add("url_credential_path")
    if analysis["body"]["html_password_inputs"]:
        _add(hits, "html_password_field", f"{analysis['body']['html_password_inputs']} champ(s) mot de passe")
    elif analysis["body"]["html_forms"]:
        _add(hits, "html_form", f"{len(analysis['body']['html_forms'])} formulaire(s)")

    # ---------------- contenu
    # mots-clés cherchés dans le texte lisible uniquement (les URL sont évaluées à part)
    text = _norm(h["subject"] + "\n" + re.sub(r"(?i)\b(?:https?|ftp)://\S+", " ", analysis["body"]["text"]))
    urg = _count(URGENCY, text)
    if len(urg) >= 2:
        _add(hits, "urgency", ", ".join(urg[:4]))
    if len(urg) >= 4:
        _add(hits, "urgency_strong", f"{len(urg)} formules")
    cred = _count(CREDENTIALS, text)
    if cred:
        _add(hits, "credential_request", ", ".join(cred[:4]))
    action = _count(ACCOUNT_ACTION, text)
    if action:
        _add(hits, "account_action", ", ".join(a[:60] for a in action[:3]))
    greeting = _count(GENERIC_GREETING, text)
    if greeting:
        _add(hits, "generic_greeting", greeting[0])
    pay = _count(PAYMENT, text)
    if pay:
        _add(hits, "payment_change", ", ".join(pay[:4]))

    # ---------------- pièces jointes
    names = [a["filename"] for a in analysis["attachments"]]
    names += [m["filename"] for a in analysis["attachments"] for m in a["zip_members"]]
    for n in names:
        parts = n.lower().rsplit("/", 1)[-1].split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in DANGEROUS_EXT and "dangerous_extension" not in seen_rules:
            _add(hits, "dangerous_extension", n)
            seen_rules.add("dangerous_extension")
        if len(parts) >= 3 and parts[-2] in DOC_EXT and ext in DANGEROUS_EXT | {"html", "htm"} and "double_extension" not in seen_rules:
            _add(hits, "double_extension", n)
            seen_rules.add("double_extension")
        if ext in ("htm", "html", "shtml", "svg") and "html_attachment" not in seen_rules:
            _add(hits, "html_attachment", n)
            seen_rules.add("html_attachment")
    if any(m["sha256"] is None for a in analysis["attachments"] for m in a["zip_members"]):
        _add(hits, "encrypted_archive", "membre chiffré dans une archive")
    for y in sorted(yara_hits, key=lambda x: -x["score"])[:3]:
        _add(hits, "yara", f"{y['rule']} sur {y['file']} — {y['description']}", points=min(40, y["score"]))

    # ---------------- réputation
    mal = [i for i in intel if i.get("verdict") == "malicious"]
    sus = [i for i in intel if i.get("verdict") == "suspicious"]
    if mal:
        _add(hits, "intel_malicious", "; ".join(f"{i['source']}: {i['detail']}" for i in mal[:3]))
    elif sus:
        _add(hits, "intel_suspicious", "; ".join(f"{i['source']}: {i['detail']}" for i in sus[:3]))
    att_hashes = [a["sha256"] for a in analysis["attachments"]]
    good = {i["indicator"] for i in intel if i.get("verdict") == "known_good"}
    if att_hashes and all(x in good for x in att_hashes) and not yara_hits:
        _add(hits, "known_good_files", f"{len(att_hashes)} fichier(s)")

    # ---------------- légitimité
    if h["list_unsubscribe"] and all_pass:
        _add(hits, "newsletter", "List-Unsubscribe présent")

    total = max(0, min(100, sum(x["points"] for x in hits)))
    if total >= config.THRESHOLD_MALICIOUS:
        decision = "malicious"
    elif total >= config.THRESHOLD_SUSPICIOUS:
        decision = "suspicious"
    else:
        decision = "benign"
    hits.sort(key=lambda x: -x["points"])
    return {"score": total, "decision": decision, "hits": hits,
            "thresholds": {"suspicious": config.THRESHOLD_SUSPICIOUS, "malicious": config.THRESHOLD_MALICIOUS}}
