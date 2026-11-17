"""Analyse des formats réels d'e-mail.

- Extraction du message signalé : pièce jointe message/rfc822, fichier .eml joint (application/octet-stream),
  ou transfert « en ligne » (fallback).
- Décodage des en-têtes encodés (RFC 2047 : =?UTF-8?B?...?=), des corps base64 / quoted-printable et des charsets.
- Extraction des URL (texte, href, form action, src), du texte des liens, des pièces jointes (hash) et des archives ZIP.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import quopri
import re
import zipfile
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

from . import ioc

URL_RE = re.compile(r"""(?i)\b((?:https?|ftp)://[^\s<>"'\])}]+)""")
MAX_ATTACHMENT_SCAN = 15 * 1024 * 1024
MAX_ZIP_MEMBERS = 50


def parse_bytes(raw: bytes) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw)


# --------------------------------------------------------------------------- extraction du message signalé
def extract_reported(report: EmailMessage) -> tuple[EmailMessage, str]:
    """Renvoie (message_original, méthode). Le rapporteur transfère l'e-mail « en pièce jointe »."""
    for part in report.walk():
        if part is report:
            continue
        ctype = part.get_content_type()
        if ctype == "message/rfc822":
            cte = str(part.get("Content-Transfer-Encoding", "") or "").strip().lower()
            if cte in ("base64", "quoted-printable"):
                # Non conforme RFC 2046 mais fréquent (certains clients/passerelles) : on décode nous-mêmes
                payload = part.get_payload()
                body = payload[0].as_string() if isinstance(payload, list) and payload else str(payload)
                body = body.split("\n\n", 1)[-1] if ":" in body.split("\n", 1)[0] else body
                try:
                    if cte == "base64":
                        data = base64.b64decode(re.sub(r"[^A-Za-z0-9+/=]", "", body) + "==", validate=False)
                    else:
                        data = quopri.decodestring(body.encode())
                    return parse_bytes(data), f"rfc822_{cte}"
                except (binascii.Error, ValueError):
                    pass
            try:
                inner = part.get_content()
            except Exception:  # noqa: BLE001
                payload = part.get_payload()
                inner = payload[0] if isinstance(payload, list) and payload else None
            if isinstance(inner, EmailMessage):
                return parse_bytes(inner.as_bytes()), "rfc822"
        filename = (part.get_filename() or "").lower()
        if filename.endswith(".eml"):
            data = part.get_payload(decode=True)
            if data:
                return parse_bytes(data), "eml_attachment"
    return report, "inline"


# --------------------------------------------------------------------------- HTML
class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self.forms: list[str] = []
        self.password_inputs = 0
        self.scripts = 0
        self._href: str | None = None
        self._text: list[str] = []
        self.text_chunks: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self._href = a["href"].strip()
            self._text = []
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.password_inputs += 1
        elif tag == "script":
            self.scripts += 1
        for attr in ("src", "action"):
            if a.get(attr, "").lower().startswith(("http://", "https://")) and tag != "a":
                self.links.append({"url": a[attr].strip(), "text": "", "source": f"html_{tag}_{attr}"})

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append({"url": self._href, "text": " ".join("".join(self._text).split()), "source": "html_href"})
            self._href = None

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)
        self.text_chunks.append(data)


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # noqa: BLE001 - charset inconnu, encodage cassé…
        data = part.get_payload(decode=True) or b""
        try:
            return data.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:  # charset déclaré inexistant : un e-mail hostile ne doit pas faire planter l'analyse
            return data.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- en-têtes
def _auth_results(msg: EmailMessage) -> dict:
    res = {"spf": None, "dkim": None, "dmarc": None}
    raw = " ".join(str(v) for v in msg.get_all("Authentication-Results", []) or [])
    raw += " " + " ".join(str(v) for v in msg.get_all("ARC-Authentication-Results", []) or [])
    for mech in res:
        m = re.search(rf"\b{mech}\s*=\s*([a-z]+)", raw, re.I)
        if m:
            res[mech] = m.group(1).lower()
    if res["spf"] is None:
        spf = str(msg.get("Received-SPF", "") or "")
        m = re.match(r"\s*([a-z]+)", spf, re.I)
        if m:
            res["spf"] = m.group(1).lower()
    return res


def _addr(value) -> tuple[str, str]:
    name, addr = parseaddr(str(value or ""))
    return name.strip(), addr.strip().lower()


def _hops(msg: EmailMessage) -> list[str]:
    hops = []
    for r in msg.get_all("Received", []) or []:
        r = " ".join(str(r).split())
        m = re.search(r"from\s+(\S+)(?:\s+\(([^)]*)\))?", r, re.I)
        hops.append(m.group(0)[:160] if m else r[:160])
    return hops


# --------------------------------------------------------------------------- pièces jointes
def _attachment(part, filename: str, data: bytes) -> dict:
    info = {
        "filename": filename,
        "content_type": part.get_content_type() if part is not None else "application/octet-stream",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - indicateur, pas un usage cryptographique
        "zip_members": [],
    }
    return info


def _zip_members(data: bytes) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for zi in zf.infolist()[:MAX_ZIP_MEMBERS]:
                if zi.is_dir() or zi.file_size > MAX_ATTACHMENT_SCAN:
                    continue
                if zi.flag_bits & 0x1:  # archive chiffrée : on note juste le nom
                    out.append((zi.filename, b""))
                    continue
                out.append((zi.filename, zf.read(zi)))
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError, EOFError):
        pass
    return out


# --------------------------------------------------------------------------- analyse principale
def analyze_message(msg: EmailMessage) -> dict:
    from_name, from_addr = _addr(msg.get("From"))
    _, reply_to = _addr(msg.get("Reply-To"))
    _, return_path = _addr(msg.get("Return-Path"))
    _, sender_hdr = _addr(msg.get("Sender"))
    to = [a.lower() for _, a in getaddresses([str(v) for v in (msg.get_all("To", []) or [])]) if a]
    cc = [a.lower() for _, a in getaddresses([str(v) for v in (msg.get_all("Cc", []) or [])]) if a]

    raw_subject_hdr = ""
    for k, v in msg.raw_items():
        if k.lower() == "subject":
            raw_subject_hdr = str(v)
            break

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    blobs: list[tuple[str, bytes]] = []  # (nom, contenu) pour YARA
    encodings: set[str] = set()

    for part in msg.walk():
        if part.is_multipart():
            continue
        cte = str(part.get("Content-Transfer-Encoding", "") or "").lower()
        if cte:
            encodings.add(cte)
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        filename = part.get_filename()
        if ctype in ("text/plain", "text/html") and disp != "attachment" and not filename:
            (html_parts if ctype == "text/html" else text_parts).append(_part_text(part))
            continue
        if ctype == "message/rfc822":
            # e-mail imbriqué dans l'e-mail suspect : on l'expose comme pièce jointe
            data = part.as_bytes()
            filename = filename or "embedded.eml"
        else:
            data = part.get_payload(decode=True) or b""
        if not data:
            continue
        att = _attachment(part, filename or f"unnamed.{ctype.split('/')[-1]}", data)
        blobs.append((att["filename"], data[:MAX_ATTACHMENT_SCAN]))
        if data[:4] == b"PK\x03\x04":
            for name, member in _zip_members(data):
                att["zip_members"].append({
                    "filename": name,
                    "size": len(member),
                    "sha256": hashlib.sha256(member).hexdigest() if member else None,
                })
                if member:
                    blobs.append((f"{att['filename']}!{name}", member))
        attachments.append(att)

    text = "\n".join(text_parts)
    html_body = "\n".join(html_parts)

    links: list[dict] = []
    lp = _LinkParser()
    if html_body:
        try:
            lp.feed(html_body)
        except Exception:  # noqa: BLE001
            pass
        links.extend(lp.links)
    for m in URL_RE.finditer(text):
        links.append({"url": m.group(1).rstrip(".,;:!?)"), "text": "", "source": "text"})
    # HTML joint (page de phishing en pièce jointe)
    for name, data in blobs:
        if name.lower().endswith((".htm", ".html", ".shtml", ".svg")):
            sub = _LinkParser()
            try:
                sub.feed(data.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            for l in sub.links:
                links.append({**l, "source": f"attachment:{name}"})
            for action in sub.forms:
                if action.lower().startswith("http"):
                    links.append({"url": action, "text": "", "source": f"attachment_form:{name}"})

    urls: dict[str, dict] = {}
    for l in links:
        u = l["url"]
        if not u.lower().startswith(("http://", "https://", "ftp://")):
            continue
        entry = urls.setdefault(u, {"url": u, "texts": set(), "sources": set()})
        if l["text"]:
            entry["texts"].add(l["text"][:200])
        entry["sources"].add(l["source"])
    url_list = []
    for u, e in urls.items():
        chain = ioc.unwrap_url(u)
        final = chain[-1]
        host = ioc.host_of(final)
        url_list.append({
            "url": u,
            "final_url": final,
            "redirect_chain": chain,
            "host": host,
            "domain": ioc.registered_domain(host),
            "defanged": ioc.defang_url(final),
            "texts": sorted(e["texts"]),
            "sources": sorted(e["sources"]),
            "key": ioc.url_key(final),
        })

    visible_text = text
    if not visible_text and lp.text_chunks:
        visible_text = " ".join(" ".join(lp.text_chunks).split())

    return {
        "headers": {
            "from_name": from_name,
            "from": from_addr,
            "from_domain": ioc.email_domain(from_addr),
            "reply_to": reply_to,
            "return_path": return_path,
            "sender": sender_hdr,
            "to": to,
            "cc": cc,
            "subject": str(msg.get("Subject", "") or ""),
            "subject_was_encoded": "=?" in raw_subject_hdr,
            "date": str(msg.get("Date", "") or ""),
            "message_id": str(msg.get("Message-ID", "") or "").strip(),
            "x_mailer": str(msg.get("X-Mailer", "") or ""),
            "list_unsubscribe": bool(msg.get("List-Unsubscribe")),
            "auth": _auth_results(msg),
            "received": _hops(msg),
        },
        "body": {
            "text": visible_text[:20000],
            "has_html": bool(html_body),
            "html_forms": lp.forms,
            "html_password_inputs": lp.password_inputs,
            "html_scripts": lp.scripts,
            "transfer_encodings": sorted(encodings),
        },
        "urls": url_list,
        "attachments": attachments,
        "_blobs": blobs,
        "_html": html_body[:MAX_ATTACHMENT_SCAN],
    }
