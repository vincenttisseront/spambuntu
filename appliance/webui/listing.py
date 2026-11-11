"""Filtres, tri et pagination des listes de la console (en mémoire : les listes sont courtes et déjà bornées en amont)."""
from __future__ import annotations

import time

PER_PAGE = 50
PERIODS = {"24h": 86400, "7j": 7 * 86400, "30j": 30 * 86400, "tout": None}
PERIOD_NAMES = (("tout", "Toute la période"), ("24h", "24 heures"), ("7j", "7 jours"), ("30j", "30 jours"))
QUARANTINE_VIEWS = ("risque", "ordinaire", "tout")
QUARANTINE_SORTS = (("risque", "Risque puis date"), ("date", "Date"), ("score", "Score"))


def text_arg(args, name: str, limit: int = 100) -> str:
    return "".join(ch for ch in (args.get(name) or "").strip() if ch.isprintable())[:limit]


def number_arg(args, name: str):
    raw = (args.get(name) or "").strip().replace(",", ".")
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def page_arg(args) -> int:
    try:
        return max(1, min(int(args.get("page", "1")), 10000))
    except ValueError:
        return 1


def quarantine_filters(args) -> dict:
    """Paramètres de la liste d'administration, nettoyés (valeurs inconnues ramenées au défaut)."""
    view = args.get("vue", "risque")
    period = args.get("periode", "tout")
    sort = args.get("tri", "")
    return {
        "vue": view if view in QUARANTINE_VIEWS else "risque",
        "q": text_arg(args, "q"), "dest": text_arg(args, "dest"), "exp": text_arg(args, "exp"),
        "motif": text_arg(args, "motif", 80), "regle": text_arg(args, "regle", 60).upper(),
        "smin": number_arg(args, "smin"), "smax": number_arg(args, "smax"),
        "periode": period if period in PERIODS else "tout",
        "tri": sort if sort in dict(QUARANTINE_SORTS) else "",
        "page": page_arg(args),
    }


def url_params(filters: dict, **over) -> dict:
    """Paramètres d'adresse : uniquement les filtres renseignés (pas de valeurs par défaut ni de valeurs vides)."""
    merged = {**filters, **over}
    defaults = {"vue": "risque", "periode": "tout", "page": 1, "tri": ""}
    return {k: v for k, v in merged.items() if v not in (None, "") and defaults.get(k) != v}


def filter_quarantine(messages: list, f: dict, now: float | None = None) -> list:
    now = now or time.time()
    needle, dest, exp, motif, regle = (f[k].lower() for k in ("q", "dest", "exp", "motif", "regle"))
    horizon = PERIODS.get(f["periode"])
    out = []
    for m in messages:
        risky = m.get("class") != "user"
        if f["vue"] == "risque" and not risky or f["vue"] == "ordinaire" and risky:
            continue
        if needle and not any(needle in str(v).lower() for v in (m.get("from"), m.get("sender"), m.get("subject"), m.get("id"), *m.get("recipients", []))):
            continue
        if dest and not any(dest in r.lower() for r in m.get("recipients", [])):
            continue
        if exp and exp not in (str(m.get("sender", "")) + " " + str(m.get("from", ""))).lower():
            continue
        if motif and motif not in [d.lower() for d in m.get("danger", [])]:
            continue
        if regle and not any(regle.lower() in s.lower() for s in m.get("symbols", [])):
            continue
        score = m.get("score")
        if f["smin"] is not None and (score is None or score < f["smin"]):
            continue
        if f["smax"] is not None and (score is None or score > f["smax"]):
            continue
        if horizon and int(m.get("arrived", 0)) < now - horizon:
            continue
        out.append(m)
    sort = f["tri"] or ("risque" if f["vue"] == "tout" else "date")
    if sort == "score":
        out.sort(key=lambda m: -(m.get("score") if m.get("score") is not None else 1e9))
    elif sort == "risque":
        out.sort(key=lambda m: (m.get("class") == "user", -int(m.get("arrived", 0))))
    else:
        out.sort(key=lambda m: -int(m.get("arrived", 0)))
    return out


def paginate(items: list, page: int, per_page: int = PER_PAGE) -> tuple:
    """(éléments de la page, {page, pages, total, first, last})."""
    total = len(items)
    pages = max(1, -(-total // per_page))
    page = min(page, pages)
    start = (page - 1) * per_page
    chunk = items[start:start + per_page]
    return chunk, {"page": page, "pages": pages, "total": total, "first": start + 1 if total else 0, "last": start + len(chunk)}


def gauge(score, thresholds: dict, width: float = 100.0) -> dict:
    """Géométrie d'une jauge de score (SVG généré côté serveur : la CSP interdit les styles en ligne)."""
    scale = max(float(thresholds["reject"]) * 1.25, (score or 0) * 1.05, 1.0)
    pos = lambda v: round(min(max(v, 0.0), scale) / scale * width, 2)  # noqa: E731
    return {"width": width, "tag": pos(thresholds["tag"]), "quarantine": pos(thresholds["quarantine"]), "reject": pos(thresholds["reject"]),
            "score": pos(score) if score is not None else None}
