#!/usr/bin/env python3
"""Résumé quotidien de quarantaine : un message par destinataire, avec liens de libération signés (facultatifs).

  spambuntu-digest run [--dry-run]

Exécuté en root par une minuterie systemd. Chaque destinataire ne voit que ses propres messages. Les liens
contiennent un jeton signé (HMAC-SHA256, clé dérivée de la clé secrète de la console) qui désigne un message et
un destinataire et expire au bout de 3 jours ; la console vérifie le jeton et demande une confirmation avant
de libérer, et le programme de quarantaine refuse les messages trop suspects. Le courrier du résumé est
déposé via `sendmail` local (il passe par la table de transport, donc vers le serveur du destinataire).
"""
from __future__ import annotations

import argparse
import base64
import email.message
import email.utils
import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # exécuté avec python3 -I
import spambuntu_mail as mailcfg  # noqa: E402
import spambuntu_quarantine as quarantine  # noqa: E402

WEBUI_CONF = Path("/etc/spambuntu/webui.json")
STATE_FILE = Path("/var/lib/spambuntu/mail/digest-state.json")
TOKEN_TTL = 3 * 86400
WINDOW = 36 * 3600                 # un résumé manqué est rattrapé le lendemain ; l'état évite les doublons
MAX_PER_DIGEST = 50
MAX_RECIPIENTS = 500
SENDMAIL = "/usr/sbin/sendmail"


class DigestError(Exception):
    pass


# ----------------------------------------------------------------------------- jetons

def _key(secret: str) -> bytes:
    return hmac.new(secret.encode(), b"spambuntu-digest-v1", hashlib.sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def make_token(secret: str, queue_id: str, recipient: str, now: float | None = None, scope: str = "r") -> str:
    """scope « r » : libérer un message ; « l » : consulter la liste de ses messages (queue_id = « - »)."""
    payload = _b64(f"{scope}|{queue_id}|{recipient}|{int((now or time.time()) + TOKEN_TTL)}".encode())
    return payload + "." + _b64(hmac.new(_key(secret), payload.encode(), hashlib.sha256).digest()[:16])


def verify_token(secret: str, token: str, now: float | None = None, scope: str = "r") -> tuple:
    """Retourne (identifiant de file, destinataire) ou lève DigestError. Le jeton doit être de la portée demandée."""
    try:
        payload, sig = token.split(".")
        good = _b64(hmac.new(_key(secret), payload.encode(), hashlib.sha256).digest()[:16])
        if not hmac.compare_digest(sig, good):
            raise ValueError
        token_scope, queue_id, recipient, expires = _unb64(payload).decode().split("|")
        if token_scope != scope:
            raise ValueError
        if int(expires) < (now or time.time()):
            raise DigestError("Ce lien a expiré")
    except DigestError:
        raise
    except (ValueError, UnicodeError):
        raise DigestError("Lien invalide") from None
    if not quarantine.RCPT_RE.fullmatch(recipient) or not (queue_id == "-" if scope == "l" else quarantine.QUEUE_ID_RE.fullmatch(queue_id)):
        raise DigestError("Lien invalide")
    return queue_id, recipient


# ----------------------------------------------------------------------------- composition

def clean(text: str, limit: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f‪-‮⁦-⁩]+", " ", str(text)).strip()[:limit]


def reason_of(item: dict) -> str:
    if item.get("ai"):
        return "Analyse : " + clean(item["ai"], 160)
    if item.get("symbols"):
        return "Règles : " + ", ".join(item["symbols"][:4])
    return "Score élevé"


def releasable(item: dict, cfg: dict) -> bool:
    """Message gérable par son destinataire : classe « user » et score connu sous le plafond de libération."""
    return item.get("class") == "user" and item.get("score") is not None and item["score"] <= cfg["digest_release_max_score"]


def group_by_recipient(items: list, domains: set, sent: dict, now: float, cfg: dict) -> dict:
    groups: dict = {}
    for item in items:
        if now - item["arrived"] > WINDOW or item["id"] in sent or not releasable(item, cfg):
            continue          # les messages à risque ne sont jamais détaillés aux utilisateurs
        for rcpt in item["recipients"]:
            rcpt = rcpt.lower()
            if rcpt.rsplit("@", 1)[-1] in domains and quarantine.RCPT_RE.fullmatch(rcpt):
                groups.setdefault(rcpt, []).append(item)
    return groups


def compose(rcpt: str, items: list, cfg: dict, secret: str, hostname: str, now: float | None = None,
            blocked: int = 0) -> email.message.EmailMessage:
    now = now or time.time()
    sender = cfg["digest_from"] or f"quarantaine@{cfg['hostname'] or hostname}"
    msg = email.message.EmailMessage()
    msg["From"] = sender
    msg["To"] = rcpt
    msg["Subject"] = f"{len(items)} message(s) en quarantaine"
    msg["Date"] = email.utils.formatdate(now, localtime=False)
    msg["Message-ID"] = email.utils.make_msgid(domain=sender.rsplit("@", 1)[-1])
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    lines = ["Bonjour,", "",
             f"{len(items)} message(s) qui vous étaient destinés ont été retenus par le filtre anti-spam et ne vous ont pas été remis :", ""]
    for item in sorted(items, key=lambda i: -i["arrived"])[:MAX_PER_DIGEST]:
        when = time.strftime("%d/%m %H:%M", time.localtime(item["arrived"]))
        lines += [f"- {when}  De : {clean(item['sender'] or item['from'], 80)}",
                  f"  Objet : {clean(item['subject'] or '(sans objet)', 90)}",
                  f"  {reason_of(item)}"]
        if cfg["digest_base_url"]:
            lines.append(f"  Libérer : {cfg['digest_base_url']}/digest/{make_token(secret, item['id'], rcpt, now)}")
        lines.append("")
    if len(items) > MAX_PER_DIGEST:
        lines += [f"… et {len(items) - MAX_PER_DIGEST} autre(s).", ""]
    if cfg["digest_base_url"]:
        lines += [f"Voir et gérer tous mes messages : {cfg['digest_base_url']}/mes-messages/{make_token(secret, '-', rcpt, now, 'l')}", ""]
    if blocked:
        lines += [f"{blocked} autre(s) message(s) ont été bloqués par mesure de sécurité : ils sont examinés par l'administrateur.", ""]
    lines += ["Seuls les messages de courrier indésirable ordinaire peuvent être libérés ici.",
              "Ne transférez pas ce message : les liens vous sont personnels.", "",
              "Message automatique de la passerelle Spambuntu."]
    msg.set_content("\n".join(lines))
    return msg


# ----------------------------------------------------------------------------- exécution

def load_secret(path: Path = WEBUI_CONF) -> str:
    try:
        return str(json.loads(path.read_text(encoding="utf-8"))["secret_key"])
    except (OSError, ValueError, KeyError):
        raise DigestError("Clé de la console illisible") from None


def send(msg: email.message.EmailMessage) -> bool:
    try:
        res = subprocess.run([SENDMAIL, "-i", "-f", msg["From"], "--", str(msg["To"])], input=msg.as_bytes(),
                             capture_output=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0


def run_digest(cfg: dict, items: list, secret: str, state_file: Path = STATE_FILE, sender=send, dry_run: bool = False,
               now: float | None = None, hostname: str | None = None) -> dict:
    now = now or time.time()
    hostname = hostname or socket.getfqdn()
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
        sent = {k: v for k, v in state.get("sent", {}).items() if now - v < 7 * 86400}
    except (OSError, ValueError, AttributeError):
        sent = {}
    domains = {d["name"] for d in cfg["domains"]}
    groups = group_by_recipient(items, domains, sent, now, cfg)
    blocked: dict = {}
    for item in items:
        if not releasable(item, cfg) and now - item["arrived"] <= WINDOW:
            for r in item["recipients"]:
                blocked[r.lower()] = blocked.get(r.lower(), 0) + 1
    report = {"recipients": 0, "messages": 0, "failed": 0}
    for rcpt in sorted(groups)[:MAX_RECIPIENTS]:
        msg = compose(rcpt, groups[rcpt], cfg, secret, hostname, now, blocked.get(rcpt, 0))
        if dry_run:
            print(msg.as_string())
            continue
        if sender(msg):
            report["recipients"] += 1
            report["messages"] += len(groups[rcpt])
            for item in groups[rcpt]:
                sent[item["id"]] = now
        else:
            report["failed"] += 1
    if not dry_run:
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"sent": sent}), encoding="utf-8")
            os.replace(tmp, state_file)
        except OSError:
            pass
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-digest", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--dry-run", action="store_true", help="affiche les messages sans les envoyer")
    args = ap.parse_args(argv)
    try:
        cfg = mailcfg.load_config(mailcfg.CONF_PATH)
        if not cfg["digest_enabled"]:
            print("Résumé quotidien désactivé")
            return 0
        report = run_digest(cfg, quarantine.listing(), load_secret(), dry_run=args.dry_run)
    except (mailcfg.MailError, quarantine.QuarantineError, DigestError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
