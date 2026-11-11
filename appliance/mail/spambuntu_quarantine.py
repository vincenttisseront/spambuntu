#!/usr/bin/env python3
"""Gestion de la quarantaine (file « hold » de Postfix) pour la console web.

  spambuntu-quarantine list [--limit N]
  spambuntu-quarantine release IDENTIFIANT [--actor NOM]
  spambuntu-quarantine delete  IDENTIFIANT [--actor NOM]

Exécuté en root via sudo par la console : tout argument est donc validé strictement ici (identifiant
de file Postfix, nom d'acteur), et une action ne vise que des messages réellement en quarantaine.
Sortie : JSON sur la sortie standard. Chaque action est journalisée.
"""
from __future__ import annotations

import argparse
import email.header
import json
import re
import subprocess
import sys
import time
from pathlib import Path

LOG_FILE = Path("/var/log/spambuntu/quarantine.log")
QUEUE_ID_RE = re.compile(r"[0-9A-Za-z]{6,25}")
ACTOR_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
MAX_LIST = 500
HEADER_BYTES = 8192


class QuarantineError(Exception):
    pass


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=False, timeout=60, check=False)


def decode_header(value: str, limit: int = 200) -> str:
    """Décode un en-tête MIME (RFC 2047) en texte brut inoffensif et borné."""
    try:
        parts = email.header.decode_header(value)
        text = "".join(p.decode(enc or "utf-8", "replace") if isinstance(p, bytes) else p for p, enc in parts)
    except (ValueError, LookupError):
        text = value
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()
    return text[:limit]


def headers_of(raw: bytes) -> dict:
    """Extrait quelques en-têtes d'une sortie `postcat -qh` (déjà tronquée à HEADER_BYTES)."""
    text = raw[:HEADER_BYTES].decode("utf-8", "replace")
    found, current = {}, None
    for line in text.splitlines():
        if line[:1] in " \t" and current:
            found[current] += " " + line.strip()
        elif ":" in line:
            name, _, value = line.partition(":")
            current = name.strip().lower()
            if current in ("subject", "x-spamd-result", "from", "x-rspamd-action") and current not in found:
                found[current] = value.strip()
            else:
                current = None
    return found


def score_of(spamd_result: str):
    m = re.search(r"\[(-?\d+(?:\.\d+)?) / (\d+(?:\.\d+)?)\]", spamd_result or "")
    return float(m.group(1)) if m else None


def symbols_of(spamd_result: str, limit: int = 12) -> list:
    return re.findall(r"([A-Z][A-Z0-9_]{2,})\(", spamd_result or "")[:limit]


def held(run=_run, limit: int = MAX_LIST) -> list:
    res = run(["postqueue", "-j"])
    if res.returncode != 0:
        raise QuarantineError("Lecture de la file Postfix impossible")
    items = []
    for line in res.stdout.decode("utf-8", "replace").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if d.get("queue_name") != "hold" or not QUEUE_ID_RE.fullmatch(str(d.get("queue_id", ""))):
            continue
        items.append(d)
    items.sort(key=lambda d: d.get("arrival_time", 0), reverse=True)
    return items[:limit]


def listing(run=_run, limit: int = MAX_LIST) -> list:
    out = []
    for d in held(run, limit):
        head = run(["postcat", "-qh", d["queue_id"]])
        h = headers_of(head.stdout[:HEADER_BYTES]) if head.returncode == 0 else {}
        out.append({
            "id": d["queue_id"],
            "sender": str(d.get("sender", ""))[:200],
            "recipients": [str(r.get("address", ""))[:200] for r in d.get("recipients", [])][:20],
            "size": int(d.get("message_size", 0)),
            "arrived": int(d.get("arrival_time", 0)),
            "subject": decode_header(h.get("subject", "")),
            "from": decode_header(h.get("from", "")),
            "score": score_of(h.get("x-spamd-result", "")),
            "symbols": symbols_of(h.get("x-spamd-result", "")),
        })
    return out


def audit(actor: str, action: str, queue_id: str, ok: bool, log_file: Path = LOG_FILE) -> None:
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {actor} {action} {queue_id} {'ok' if ok else 'échec'}\n")
    except OSError:
        pass


def act(action: str, queue_id: str, actor: str = "console", run=_run, log_file: Path = LOG_FILE) -> str:
    if not QUEUE_ID_RE.fullmatch(queue_id):
        raise QuarantineError("Identifiant de message invalide")
    if not ACTOR_RE.fullmatch(actor):
        raise QuarantineError("Nom d'acteur invalide")
    if queue_id not in {d["queue_id"] for d in held(run)}:
        audit(actor, action, queue_id, False, log_file)
        raise QuarantineError("Ce message n'est plus en quarantaine")
    if action == "release":
        res = run(["postsuper", "-H", queue_id])
        if res.returncode == 0:
            res = run(["postqueue", "-i", queue_id])
        message = "Message libéré et remis en livraison"
    elif action == "delete":
        res = run(["postsuper", "-d", queue_id, "hold"])
        message = "Message supprimé"
    else:
        raise QuarantineError("Action inconnue")
    ok = res.returncode == 0
    audit(actor, action, queue_id, ok, log_file)
    if not ok:
        raise QuarantineError("L'opération a échoué (voir les journaux de Postfix)")
    return message


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-quarantine", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--limit", type=int, default=200)
    for name in ("release", "delete"):
        p = sub.add_parser(name)
        p.add_argument("queue_id")
        p.add_argument("--actor", default="console")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            print(json.dumps({"ok": True, "messages": listing(limit=max(1, min(args.limit, MAX_LIST)))}, ensure_ascii=False))
        else:
            print(json.dumps({"ok": True, "message": act(args.cmd, args.queue_id, args.actor)}, ensure_ascii=False))
    except QuarantineError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
