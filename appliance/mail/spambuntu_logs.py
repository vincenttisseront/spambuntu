#!/usr/bin/env python3
"""Statistiques et recherche de messages à partir du journal de Rspamd (une ligne par message analysé).

  spambuntu-mailstats summary [--hours N]
  spambuntu-mailstats search [--q TEXTE] [--action A] [--hours N] [--limit N] [--sender S] [--rcpt R] [--ip IP]
                             [--symbol RÈGLE] [--min-score N] [--max-score N]
  spambuntu-mailstats trace IDENTIFIANT [--hours N]

Exécuté en root via sudo par la console (le journal n'est pas lisible par l'utilisateur de la console) :
tous les arguments sont validés ici. Seules des métadonnées sont exposées (expéditeur, destinataires, score,
règles) : ni objet ni contenu. La profondeur disponible est celle de la rotation du journal (≈ 5 jours).
"""
from __future__ import annotations

import argparse
import collections
import datetime
import gzip
import json
import re
import sys
import time
from pathlib import Path

LOG_FILE = Path("/var/log/rspamd/rspamd.log")
MAIL_LOG = Path("/var/log/mail.log")
MAX_HOURS = 24 * 14
MAX_LIMIT = 500
QUERY_RE = re.compile(r"[\w@.+\-:\[\] ]{1,100}")
IDENT_RE = re.compile(r"[\w.@+\-=%$#/!*]{3,200}")             # identifiant de file Postfix ou Message-ID (sans chevrons)
QID_RE = re.compile(r"[0-9A-Za-z]{6,25}")

ACTIONS = {                     # action de Rspamd -> catégorie affichée
    "no action": "delivered",
    "add header": "tagged",
    "rewrite subject": "tagged",
    "quarantine": "quarantined",
    "reject": "rejected",
    "soft reject": "deferred",
    "greylist": "deferred",
    "discard": "rejected",
}
CATEGORIES = ("delivered", "tagged", "quarantined", "rejected", "deferred")

LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) .*?rspamd_task_write_log: (.*)$")
FIELD_RES = {
    "qid": re.compile(r"\bqid: <([^>]*)>"),
    "ip": re.compile(r"\bip: ([0-9a-fA-F:.]+),"),
    "user": re.compile(r"\buser: ([^,\s]+),"),
    "sender": re.compile(r"\bfrom: <([^>]*)>"),
    "rcpts": re.compile(r"\brcpts: <([^\n]*?)>(?:, mime_rcpts|, file:|, forced:|, settings_id:|$)"),
    "size": re.compile(r"\blen: (\d+)"),
    "mid": re.compile(r"\bid: <([^>]*)>"),
    "time_ms": re.compile(r"\btime: ([\d.]+)ms"),
}
VERDICT_RE = re.compile(r"\(default: ([TF]) \(([a-z ]+)\): \[(-?[\d.]+)/([\d.]+)\] \[(.*?)\]\),")
SYMBOL_RE = re.compile(r"([A-Z][A-Z0-9_]+)\((-?[\d.]+)\)(?:\{([^}]*)\})?")


def parse_line(line: str):
    """Une ligne du journal -> enregistrement, ou None si ce n'est pas un bilan d'analyse."""
    m = LINE_RE.match(line.rstrip("\n"))
    if not m:
        return None
    stamp, rest = m.groups()
    verdict = VERDICT_RE.search(rest)
    if not verdict:
        return None
    _, action, score, limit, symbols = verdict.groups()
    try:
        ts = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        return None
    record = {"ts": int(ts), "action": action, "category": ACTIONS.get(action, "delivered"),
              "score": float(score), "limit": float(limit)}
    for name, regex in FIELD_RES.items():
        found = regex.search(rest)
        record[name] = found.group(1) if found else ""
    record["rcpts"] = [r.strip() for r in re.split(r">,\s*<|,\s*", record["rcpts"]) if r.strip()][:20] if record["rcpts"] else []
    record["size"] = int(record["size"] or 0)
    found = SYMBOL_RE.findall(symbols)
    record["symbols"] = [name for name, weight, _ in found if abs(float(weight)) >= 1.0][:10]
    record["sym_all"] = [{"name": n, "score": float(w), "options": o[:120]} for n, w, o in found][:80]
    record["time_ms"] = float(record["time_ms"] or 0)
    return record


def _open(path: Path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.suffix == ".gz" else \
        open(path, encoding="utf-8", errors="replace")


def log_files(log_file: Path = LOG_FILE, since: float = 0):
    """Journal courant et fichiers tournés, du plus ancien au plus récent, dont le contenu peut être dans la fenêtre."""
    files = [p for p in log_file.parent.glob(log_file.name + "*") if p.is_file()]
    return sorted((p for p in files if p.stat().st_mtime >= since), key=lambda p: p.stat().st_mtime)


def read_records(hours: int, now: float | None = None, log_file: Path = LOG_FILE):
    now = now or time.time()
    since = now - hours * 3600
    records = []
    for path in log_files(log_file, since):
        try:
            with _open(path) as fh:
                for line in fh:
                    if "rspamd_task_write_log" not in line:
                        continue
                    rec = parse_line(line)
                    if rec and since <= rec["ts"] <= now + 60:
                        records.append(rec)
        except OSError:
            continue
    records.sort(key=lambda r: r["ts"])
    return records


def summarize(records: list, hours: int, now: float | None = None) -> dict:
    now = int(now or time.time())
    counts = collections.Counter(r["category"] for r in records)
    step = 3600 if hours <= 48 else 86400
    first = (now - hours * 3600) // step * step
    buckets = [{"start": first + i * step, **{c: 0 for c in CATEGORIES}} for i in range((now - first) // step + 1)]
    for r in records:
        index = (r["ts"] - first) // step
        if 0 <= index < len(buckets):
            buckets[index][r["category"]] += 1
    blocked = [r for r in records if r["category"] in ("quarantined", "rejected", "tagged")]
    senders = collections.Counter(r["sender"].rsplit("@", 1)[-1].lower() for r in blocked if "@" in r["sender"])
    ips = collections.Counter(r["ip"] for r in blocked if r["ip"])
    symbols = collections.Counter(s for r in blocked for s in r["symbols"])
    top = lambda counter, n=8: [{"name": k, "count": v} for k, v in counter.most_common(n)]  # noqa: E731
    return {
        "hours": hours, "total": len(records), "counts": {c: counts.get(c, 0) for c in CATEGORIES},
        "step": step, "timeline": buckets,
        "top_sender_domains": top(senders), "top_ips": top(ips), "top_symbols": top(symbols),
        "oldest": records[0]["ts"] if records else None,
    }


def public(record: dict) -> dict:
    """Enregistrement pour les listes : sans le détail des règles (réservé à la vue de trace)."""
    return {k: v for k, v in record.items() if k not in ("sym_all", "limit", "time_ms")}


def search(records: list, query: str = "", action: str = "", limit: int = 100, *, sender: str = "", rcpt: str = "", ip: str = "",
           symbol: str = "", min_score=None, max_score=None) -> list:
    needle, sender, rcpt, ip, symbol = (x.strip().lower() for x in (query, sender, rcpt, ip, symbol))
    out = []
    for r in reversed(records):                                  # plus récents d'abord
        if action and r["category"] != action:
            continue
        if needle and not any(needle in str(v).lower() for v in (r["sender"], r["qid"], r["mid"], r["ip"], *r["rcpts"])):
            continue
        if sender and sender not in r["sender"].lower():
            continue
        if rcpt and not any(rcpt in x.lower() for x in r["rcpts"]):
            continue
        if ip and ip not in r["ip"].lower():
            continue
        if symbol and not any(symbol in s["name"].lower() for s in r["sym_all"]):
            continue
        if min_score is not None and r["score"] < min_score:
            continue
        if max_score is not None and r["score"] > max_score:
            continue
        out.append(public(r))
        if len(out) >= limit:
            break
    return out


POSTFIX_RE = re.compile(r"^(?P<when>\S+(?:\s+\d+\s+[\d:]+)?)\s+\S+\s+postfix/(?P<comp>[a-z/]+)\[\d+\]: (?P<qid>[0-9A-Za-z]+): (?P<rest>.*)$")


def _when(text: str) -> int:
    """Horodatage d'une ligne de Postfix : « Nov 11 14:41:02 » (syslog classique) ou ISO 8601 (Ubuntu récent)."""
    try:
        year = time.localtime().tm_year
        t = time.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
        return int(time.mktime((*t[:6], 0, 0, -1)))
    except ValueError:
        pass
    try:
        return int(datetime.datetime.fromisoformat(text).timestamp())
    except ValueError:
        return 0


def read_delivery(qid: str, hours: int, now: float | None = None, mail_log: Path = MAIL_LOG) -> list:
    """Étapes de Postfix (réception, livraison, report) d'un message, à partir de son identifiant de file."""
    if not QID_RE.fullmatch(qid or ""):
        return []
    now = now or time.time()
    out = []
    for path in log_files(mail_log, now - hours * 3600):
        try:
            with _open(path) as fh:
                for line in fh:
                    if qid not in line:
                        continue
                    m = POSTFIX_RE.match(line.rstrip("\n"))
                    if not m or m["qid"] != qid:
                        continue
                    fields = dict(re.findall(r"(\w+)=(<[^>]*>|\[[^\]]*\][^,\s]*|[^,\s]*)", m["rest"]))
                    status = re.search(r"status=(\w+)(?: \((.*)\))?", m["rest"])
                    out.append({"ts": _when(m["when"]), "component": m["comp"], "to": fields.get("to", "").strip("<>")[:200],
                                "relay": fields.get("relay", "")[:200], "dsn": fields.get("dsn", "")[:20], "delay": fields.get("delay", "")[:20],
                                "status": status.group(1) if status else "", "detail": re.sub(r"[\x00-\x1f]+", " ", (status.group(2) if status and status.group(2) else ""))[:300],
                                "from": fields.get("from", "").strip("<>")[:200]})
        except OSError:
            continue
    out.sort(key=lambda x: x["ts"])
    return out[:60]


def trace(records: list, ident: str, hours: int, now: float | None = None, mail_log: Path = MAIL_LOG) -> dict:
    """Parcours d'un message : verdict(s) de Rspamd avec toutes les règles, puis étapes de Postfix."""
    matches = [r for r in records if ident in (r["qid"], r["mid"])]
    qids = [r["qid"] for r in matches if QID_RE.fullmatch(r["qid"] or "")] or ([ident] if QID_RE.fullmatch(ident) else [])
    for r in matches:
        r["sym_all"] = sorted(r["sym_all"], key=lambda x: (-abs(x["score"]), x["name"]))
    return {"verdicts": list(reversed(matches))[:10], "delivery": read_delivery(qids[0], hours, now, mail_log) if qids else []}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-mailstats", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("summary")
    s.add_argument("--hours", type=int, default=24)
    q = sub.add_parser("search")
    q.add_argument("--q", default="")
    q.add_argument("--action", default="", choices=("",) + CATEGORIES)
    q.add_argument("--hours", type=int, default=24)
    q.add_argument("--limit", type=int, default=100)
    for name in ("sender", "rcpt", "ip", "symbol"):
        q.add_argument(f"--{name}", default="")
    q.add_argument("--min-score", type=float, default=None)
    q.add_argument("--max-score", type=float, default=None)
    t = sub.add_parser("trace")
    t.add_argument("ident")
    t.add_argument("--hours", type=int, default=MAX_HOURS)
    args = ap.parse_args(argv)
    hours = max(1, min(args.hours, MAX_HOURS))
    try:
        if args.cmd == "summary":
            result = {"ok": True, **summarize(read_records(hours), hours)}
        elif args.cmd == "trace":
            if not IDENT_RE.fullmatch(args.ident):
                raise ValueError("Identifiant invalide")
            result = {"ok": True, **trace(read_records(hours), args.ident, hours)}
        else:
            for value in (args.q, args.sender, args.rcpt, args.ip, args.symbol):
                if value and not QUERY_RE.fullmatch(value):
                    raise ValueError("Recherche invalide (lettres, chiffres et @ . + - : seulement)")
            result = {"ok": True, "records": search(read_records(hours), args.q, args.action, max(1, min(args.limit, MAX_LIMIT)),
                                                    sender=args.sender, rcpt=args.rcpt, ip=args.ip, symbol=args.symbol,
                                                    min_score=args.min_score, max_score=args.max_score)}
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
