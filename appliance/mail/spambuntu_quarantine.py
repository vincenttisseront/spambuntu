#!/usr/bin/env python3
"""Gestion de la quarantaine (file « hold » de Postfix) pour la console web.

  spambuntu-quarantine list [--limit N] [--recipient ADRESSE]
  spambuntu-quarantine release IDENTIFIANT [--actor NOM] [--learn] [--recipient ADRESSE] [--max-score N] [--confirm-danger]
  spambuntu-quarantine delete  IDENTIFIANT [--actor NOM] [--learn] [--recipient ADRESSE]

Deux classes de messages retenus : « user » (courrier indésirable ordinaire, gérable par son destinataire) et
« admin » (programme malveillant, hameçonnage, fraude, usurpation, score très élevé, analyse impossible :
examinable par l'administrateur seulement). Avec --recipient, l'action est celle d'un utilisateur : elle est
refusée pour la classe « admin ». Un administrateur doit confirmer (--confirm-danger) la libération d'un message
de la classe « admin ». En cas de doute (en-têtes illisibles, pas de score), le message est classé « admin ».

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
FEEDBACK_FILE = Path("/var/lib/spambuntu/mail/feedback.jsonl")
RCPT_RE = re.compile(r"[^\s<>\"',;()\[\]\\]{1,64}@[A-Za-z0-9.-]{1,255}")
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


def ai_explanation(spamd_result: str) -> str:
    """Explication de l'analyse IA, si elle a contribué (option de la règle SPAMBUNTU_AI)."""
    m = re.search(r"SPAMBUNTU_AI\((-?\d+(?:\.\d+)?)\)\[([^\]]*)\]", spamd_result or "")
    return re.sub(r"\s+", " ", m.group(2)).strip()[:200] if m else ""


DANGER_SCORE = 12.0
AI_DANGER = {  # drapeaux de l'analyse IA qui rendent un message « admin », avec leur libellé
    "phishing": "Hameçonnage", "bec": "Fraude au président ou à la facture", "malware_lure": "Leurre de logiciel malveillant",
    "scam": "Escroquerie", "impersonation": "Usurpation d'identité", "credentials": "Demande d'identifiants",
    "payment": "Demande de paiement", "gift_cards": "Demande de cartes cadeaux", "invoice_change": "Changement de coordonnées bancaires",
    "prompt_injection": "Tentative de manipulation de l'IA",
}
DANGER_SYMBOLS = (  # (motif de règle Rspamd, libellé)
    (re.compile(r"VIRUS|MALWARE|TROJAN|RANSOM|EXPLOIT"), "Programme malveillant"),
    (re.compile(r"PHISH"), "Hameçonnage"),
    (re.compile(r"MACRO|EXECUTABLE|BAD_EXTENSION|ARCHIVE_IN_ARCHIVE|ENCRYPTED"), "Pièce jointe dangereuse"),
    (re.compile(r"DMARC_POLICY_REJECT"), "Usurpation de domaine"),
)


def classify(symbols: list, ai_flags: list, score) -> tuple:
    """(classe, motifs) : « admin » dès qu'un signal de danger est présent ou que l'analyse est incomplète."""
    reasons = [AI_DANGER[f] for f in ai_flags if f in AI_DANGER]
    for pattern, label in DANGER_SYMBOLS:
        if any(pattern.search(sym) for sym in symbols):
            reasons.append(label)
    if score is None:
        reasons.append("Analyse impossible")
    elif score >= DANGER_SCORE:
        reasons.append("Score très élevé")
    reasons = list(dict.fromkeys(reasons))
    return ("admin" if reasons else "user"), reasons


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
        every = symbols_of(h.get("x-spamd-result", ""), 200)
        flags = [x[len("SPAMBUNTU_AI_"):].lower() for x in every if x.startswith("SPAMBUNTU_AI_")]
        cls, reasons = classify(every, flags, score_of(h.get("x-spamd-result", "")))
        out.append({
            "class": cls, "danger": reasons,
            "id": d["queue_id"],
            "sender": str(d.get("sender", ""))[:200],
            "recipients": [str(r.get("address", ""))[:200] for r in d.get("recipients", [])][:20],
            "size": int(d.get("message_size", 0)),
            "arrived": int(d.get("arrival_time", 0)),
            "subject": decode_header(h.get("subject", "")),
            "from": decode_header(h.get("from", "")),
            "score": score_of(h.get("x-spamd-result", "")),
            "symbols": [s for s in symbols_of(h.get("x-spamd-result", "")) if not s.startswith("SPAMBUNTU_AI")],
            "ai": ai_explanation(h.get("x-spamd-result", "")),
            "ai_flags": flags,
        })
    return out


def listing_for_user(recipient: str, run=_run, limit: int = MAX_LIST, max_score=None) -> dict:
    """Vue d'un destinataire : uniquement ses messages de classe « user », sans détail technique ; les autres
    sont seulement comptés (l'utilisateur sait qu'un message a été bloqué, pas ce qu'il contient)."""
    if not RCPT_RE.fullmatch(recipient):
        raise QuarantineError("Destinataire invalide")
    wanted = recipient.lower()
    messages, blocked = [], 0
    for m in listing(run, limit):
        if wanted not in {r.lower() for r in m["recipients"]}:
            continue
        if m["class"] != "user" or (max_score is not None and (m["score"] is None or m["score"] > max_score)):
            blocked += 1
            continue
        messages.append({"id": m["id"], "from": m["from"] or m["sender"], "subject": m["subject"], "arrived": m["arrived"],
                         "size": m["size"], "single": len(m["recipients"]) == 1})
    return {"messages": messages, "blocked": blocked}


def audit(actor: str, action: str, queue_id: str, ok: bool, log_file: Path = LOG_FILE) -> None:
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')} {actor} {action} {queue_id} {'ok' if ok else 'échec'}\n")
    except OSError:
        pass


def _feed_rspamd(label: str, message: bytes) -> bool:
    try:
        res = subprocess.run(["rspamc", "-h", "127.0.0.1:11334", "learn_ham" if label == "ham" else "learn_spam"],
                             input=message, capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0


def learn(label: str, queue_id: str, run, feedback_file: Path, score, symbols, feed=_feed_rspamd) -> bool:
    """Apprentissage : le retour de l'utilisateur entraîne le filtre bayésien de Rspamd et alimente le corpus de référence."""
    head, body = run(["postcat", "-qh", queue_id]), run(["postcat", "-qb", queue_id])
    ok = head.returncode == 0 and body.returncode == 0 and feed(label, head.stdout + b"\n" + body.stdout)
    try:
        feedback_file.parent.mkdir(parents=True, exist_ok=True)
        with open(feedback_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": int(time.time()), "label": label, "score": score, "symbols": symbols[:15], "learned": ok}) + "\n")
    except OSError:
        pass
    return ok


def act(action: str, queue_id: str, actor: str = "console", run=_run, log_file: Path = LOG_FILE, *, do_learn: bool = False,
        recipient: str = "", max_score=None, feedback_file: Path = FEEDBACK_FILE, feed=_feed_rspamd,
        confirm_danger: bool = False) -> str:
    if not QUEUE_ID_RE.fullmatch(queue_id):
        raise QuarantineError("Identifiant de message invalide")
    if not ACTOR_RE.fullmatch(actor):
        raise QuarantineError("Nom d'acteur invalide")
    if recipient and not RCPT_RE.fullmatch(recipient):
        raise QuarantineError("Destinataire invalide")
    item = next((d for d in held(run) if d["queue_id"] == queue_id), None)
    if item is None:
        audit(actor, action, queue_id, False, log_file)
        raise QuarantineError("Ce message n'est plus en quarantaine")
    head = run(["postcat", "-qh", queue_id])
    fields = headers_of(head.stdout[:HEADER_BYTES]) if head.returncode == 0 else {}
    score = score_of(fields.get("x-spamd-result", ""))
    every = symbols_of(fields.get("x-spamd-result", ""), 200)
    cls, _ = classify(every, [x[len("SPAMBUNTU_AI_"):].lower() for x in every if x.startswith("SPAMBUNTU_AI_")], score)
    if recipient:
        recipients = {str(r.get("address", "")).lower() for r in item.get("recipients", [])}
        if recipient.lower() not in recipients:
            audit(actor, action, queue_id, False, log_file)
            raise QuarantineError("Ce message n'est pas destiné à cette adresse")
        if cls != "user":
            audit(actor + f" ({recipient})", action, queue_id, False, log_file)
            raise QuarantineError("Ce message est examiné par l'administrateur : il ne peut pas être géré depuis votre espace")
        if action == "delete" and len(recipients) != 1:
            raise QuarantineError("Ce message est destiné à plusieurs personnes : il sera purgé automatiquement")
        do_learn = False                      # l'apprentissage est réservé à l'administrateur
    elif cls == "admin" and action == "release" and not confirm_danger:
        raise QuarantineError("Message à risque : confirmez la libération après analyse")
    if max_score is not None and (score is None or score > max_score):
        audit(actor, action, queue_id, False, log_file)
        raise QuarantineError("Ce message est trop suspect pour être libéré depuis le résumé : contactez l'administrateur")
    if do_learn:
        learn("ham" if action == "release" else "spam", queue_id, run, feedback_file, score,
              symbols_of(fields.get("x-spamd-result", "")), feed)
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
    audit(actor + (f" ({recipient})" if recipient else ""), action, queue_id, ok, log_file)
    if not ok:
        raise QuarantineError("L'opération a échoué (voir les journaux de Postfix)")
    return message


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-quarantine", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--limit", type=int, default=200)
    ls.add_argument("--recipient", default="")
    ls.add_argument("--max-score", type=float, default=None)
    for name in ("release", "delete"):
        p = sub.add_parser(name)
        p.add_argument("queue_id")
        p.add_argument("--actor", default="console")
        p.add_argument("--learn", action="store_true")
        p.add_argument("--recipient", default="")
        if name == "release":
            p.add_argument("--max-score", type=float, default=None)
            p.add_argument("--confirm-danger", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            limit = max(1, min(args.limit, MAX_LIST))
            data = listing_for_user(args.recipient, limit=limit, max_score=args.max_score) if args.recipient else {"messages": listing(limit=limit)}
            print(json.dumps({"ok": True, **data}, ensure_ascii=False))
        else:
            message = act(args.cmd, args.queue_id, args.actor, do_learn=args.learn,
                          recipient=args.recipient, max_score=getattr(args, "max_score", None),
                          confirm_danger=getattr(args, "confirm_danger", False))
            print(json.dumps({"ok": True, "message": message}, ensure_ascii=False))
    except QuarantineError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
