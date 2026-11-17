"""Scan YARA des pièces jointes (et membres d'archives ZIP/OOXML)."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from . import config

log = logging.getLogger(__name__)
_rules = None


def load_rules():
    global _rules
    try:
        import yara  # noqa: PLC0415
    except ImportError:  # exécution hors conteneur sans yara-python
        log.warning("yara-python indisponible : scan YARA désactivé")
        return None
    files = {p.stem: str(p) for p in Path(config.RULES_DIR).glob("*.yar")} if os.path.isdir(config.RULES_DIR) else {}
    if not files:
        log.warning("aucune règle YARA trouvée dans %s", config.RULES_DIR)
        return None
    _rules = yara.compile(filepaths=files)
    return _rules


def scan(blobs: list[tuple[str, bytes]]) -> list[dict]:
    rules = _rules or load_rules()
    if rules is None:
        return []
    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for name, data in blobs:
        if not data:
            continue
        try:
            matches = rules.match(data=data, timeout=10)
        except Exception as exc:  # noqa: BLE001
            log.warning("échec YARA sur %s : %s", name, exc)
            continue
        for m in matches:
            key = (m.rule, name)
            if key in seen:
                continue
            seen.add(key)
            hits.append({
                "rule": m.rule,
                "file": name,
                "description": m.meta.get("description", ""),
                "score": int(m.meta.get("score", 20)),
            })
    return hits
