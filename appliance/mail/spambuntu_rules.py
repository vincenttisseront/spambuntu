"""Règles de filtrage de Spambuntu : liste ordonnée de règles (conditions -> actions), à la manière d'un
« Spam Rules » de passerelle professionnelle. Source de vérité du modèle ; le moteur qui les applique au courrier
est écrit en Lua pour Rspamd (rspamd/rules_lib.lua) et doit rester équivalent à `evaluate` ci-dessous
(tests de parité sur tests/data/rules_golden.json).

Principe
  1. Rspamd note le message (SPF, DKIM, DMARC, réputation, contenu, identité, IA...).
  2. Le moteur calcule des scores par classe, de 0 à 100 : spam, malware, phish, impostor, bulk.
  3. Les règles actives sont évaluées dans l'ordre. La première dont les conditions sont satisfaites s'applique :
     « livrer », « marquer », « quarantaine », « rejeter » arrêtent l'évaluation ; « continuer » ajoute
     seulement ses en-têtes. La dernière règle (inbound_notspam) est toujours satisfaite.
  4. Un message mis en quarantaine garde le nom de la règle et de son dossier. Un dossier peut être accessible à
     l'utilisateur ou réservé à l'administrateur ; les signaux de danger (programme malveillant, hameçonnage...)
     rendent un message réservé à l'administrateur quel que soit le dossier (voir spambuntu_quarantine).

Tout ce que ce module accepte est validé ici, à nouveau, par le programme root qui installe la configuration.
"""
from __future__ import annotations

import copy
import ipaddress
import re
import unicodedata

MAX_RULES = 60
MAX_CONDITIONS = 6
MAX_HEADERS = 3
MAX_LIST = 1000

CLASSES = (
    ("spam", "Spam"),
    ("malware", "Logiciel malveillant"),
    ("phish", "Hameçonnage"),
    ("impostor", "Usurpation et fraude"),
    ("bulk", "Courrier en masse"),
)
CLASS_LABELS = dict(CLASSES)

# Signaux des classes (hors « spam », calculé à partir du score Rspamd) : (type de correspondance, nom, points).
# Les points d'une classe s'additionnent, plafonnés à 100. « contains » = le nom de la règle contient le texte.
SIGNALS = {
    "malware": (
        ("contains", "VIRUS", 100), ("contains", "MALWARE", 100), ("contains", "TROJAN", 100),
        ("contains", "RANSOM", 100), ("contains", "EXPLOIT", 100),
        ("exact", "MIME_DOUBLE_BAD_EXTENSION", 60), ("exact", "MIME_BAD_EXTENSION", 40),
        ("exact", "MIME_ARCHIVE_IN_ARCHIVE", 40), ("exact", "MIME_ENCRYPTED_ARCHIVE", 40),
        ("exact", "MIME_OBFUSCATED_ARCHIVE", 40), ("exact", "SPAMBUNTU_AI_MALWARE_LURE", 60),
    ),
    "phish": (
        ("contains", "PHISH", 100), ("exact", "SPAMBUNTU_AI_PHISHING", 85), ("exact", "SPAMBUNTU_AI_CREDENTIALS", 60),
        ("exact", "SEM_URIBL_FRESH15", 30), ("exact", "HTML_META_REFRESH_URL", 20),
    ),
    "impostor": (
        ("exact", "SPAMBUNTU_VIP_SPOOF", 100), ("exact", "SPAMBUNTU_LOOKALIKE", 90), ("exact", "SPAMBUNTU_IDN_HOMOGLYPH", 90),
        ("exact", "SPAMBUNTU_BRAND_IN_DOMAIN", 40), ("exact", "SPOOF_DISPLAY_NAME", 60), ("exact", "DMARC_POLICY_REJECT", 60),
        ("exact", "SPOOF_REPLYTO", 50), ("exact", "FORGED_SENDER", 30), ("exact", "FROM_NEQ_DISPLAY_NAME", 30),
        ("exact", "SPAMBUNTU_AI_IMPERSONATION", 80), ("exact", "SPAMBUNTU_AI_BEC", 90), ("exact", "SPAMBUNTU_AI_INVOICE_CHANGE", 70),
        ("exact", "SPAMBUNTU_AI_GIFT_CARDS", 70), ("exact", "SPAMBUNTU_AI_SCAM", 60), ("exact", "SPAMBUNTU_AI_PAYMENT", 40),
    ),
    "bulk": (
        ("exact", "MAILLIST", 60), ("exact", "PRECEDENCE_BULK", 60), ("exact", "BULK_HEADER", 60), ("exact", "HAS_LIST_UNSUB", 40),
    ),
}

FIELDS = {
    "spam": {"label": "Score de spam", "type": "number", "min": 0, "max": 100},
    "malware": {"label": "Score de logiciel malveillant", "type": "number", "min": 0, "max": 100},
    "phish": {"label": "Score d'hameçonnage", "type": "number", "min": 0, "max": 100},
    "impostor": {"label": "Score d'usurpation et de fraude", "type": "number", "min": 0, "max": 100},
    "bulk": {"label": "Score de courrier en masse", "type": "number", "min": 0, "max": 100},
    "score": {"label": "Score Rspamd brut", "type": "number", "min": -100, "max": 1000},
    "blocklist": {"label": "L'expéditeur est sur la liste de blocage", "label_no": "L'expéditeur n'est pas sur la liste de blocage", "type": "bool"},
    "safelist": {"label": "L'expéditeur est sur la liste sûre (authentifié)", "label_no": "L'expéditeur n'est pas sur la liste sûre", "type": "bool"},
    "dmarc_reject": {"label": "Échec DMARC avec politique « reject »", "label_no": "Pas d'échec DMARC avec politique « reject »", "type": "bool"},
    "symbol": {"label": "Règle Rspamd déclenchée", "type": "symbol"},
    "sender": {"label": "Adresse de l'expéditeur", "type": "text"},
    "recipient": {"label": "Adresse d'un destinataire", "type": "text"},
}
FIELD_SHORT = {   # libellés courts pour les listes déroulantes du formulaire
    "spam": "Score de spam", "malware": "Score de logiciel malveillant", "phish": "Score d'hameçonnage",
    "impostor": "Score d'usurpation et de fraude", "bulk": "Score de courrier en masse", "score": "Score Rspamd brut",
    "blocklist": "Expéditeur sur la liste de blocage", "safelist": "Expéditeur sur la liste sûre (authentifié)",
    "dmarc_reject": "Échec DMARC (politique « reject »)", "symbol": "Règle Rspamd déclenchée",
    "sender": "Adresse de l'expéditeur", "recipient": "Adresse d'un destinataire",
}
OPS = {"number": (">=", "<="), "bool": ("is",), "symbol": ("present", "absent"), "text": ("contains", "equals", "ends_with")}
OP_LABELS = {">=": "≥", "<=": "≤", "present": "est déclenchée", "absent": "n'est pas déclenchée",
             "contains": "contient", "equals": "est égale à", "ends_with": "se termine par"}

DISPOSITIONS = {
    "deliver": "Livrer le message et arrêter l'évaluation",
    "tag": "Livrer en marquant le message comme indésirable (X-Spam: Yes)",
    "quarantine": "Mettre en quarantaine",
    "reject": "Rejeter le message (refus SMTP définitif, l'expéditeur est prévenu)",
    "continue": "Poursuivre avec la règle suivante",
}

RULE_ID_RE = re.compile(r"[a-z][a-z0-9_]{2,39}")
FOLDER_RE = re.compile(r"[^\W_][\w .'-]{0,39}")           # lettres (accents compris), chiffres, espace . ' - _
SYMBOL_RE = re.compile(r"[A-Z][A-Z0-9_]{2,63}")
HEADER_NAME_RE = re.compile(r"X-[A-Za-z0-9][A-Za-z0-9-]{0,49}")
HEADER_VALUE_RE = re.compile(r"[\x20-\x7e]{1,200}")
TEXT_VALUE_RE = re.compile(r"[^\x00-\x1f\x7f]{1,120}")
DESCRIPTION_RE = re.compile(r"[^\x00-\x1f\x7f<>]{1,80}")
RESERVED_HEADERS = ("x-spambuntu-rule", "x-spambuntu-scores", "x-spam", "x-spamd-result", "x-rspamd-action", "x-rspamd-pre-result")

# Règles fournies avec l'appliance : jamais supprimées si « protected » ; « inbound_notspam » est toujours la dernière.
PROTECTED = ("inbound_blocked", "inbound_safe", "inbound_notspam")
LAST_RULE = "inbound_notspam"
LOCKED_CONDITIONS = {   # conditions non modifiables de ces règles
    "inbound_blocked": [{"field": "blocklist", "op": "is", "value": True}],
    "inbound_safe": [{"field": "safelist", "op": "is", "value": True}],
    "inbound_notspam": [{"field": "spam", "op": ">=", "value": 0}],
}


LOCKED_DISPOSITIONS = {   # actions autorisées pour les règles fournies (les autres ne feraient aucun sens)
    "inbound_blocked": ("reject", "quarantine"),
    "inbound_safe": ("deliver",),
    "inbound_notspam": ("deliver",),
}


class RulesError(Exception):
    """Règle ou liste invalide (message destiné à l'administrateur)."""


def _rule(rule_id, description, conditions, disposition, *, folder="", user_access=False, headers=(), explain=True, enabled=True, match="all"):
    return {"id": rule_id, "enabled": enabled, "description": description, "match": match,
            "conditions": [dict(c) for c in conditions], "disposition": disposition, "folder": folder,
            "user_access": user_access, "headers": [dict(h) for h in headers], "explain": explain}


def _cond(field, op, value):
    return {"field": field, "op": op, "value": value}


def default_rules(dmarc_action: str = "reject") -> list:
    """Règles par défaut. Elles reproduisent les seuils de la page « Messagerie » (marquage, quarantaine, rejet)."""
    dmarc = _rule("inbound_dmarc", "Échec DMARC (politique « reject » de l'expéditeur)", [_cond("dmarc_reject", "is", True)], "reject")
    if dmarc_action == "quarantine":
        dmarc.update(disposition="quarantine", folder="Usurpation de domaine")
    elif dmarc_action == "score":
        dmarc["enabled"] = False
    return [
        _rule("inbound_blocked", "Liste de blocage", LOCKED_CONDITIONS["inbound_blocked"], "reject"),
        _rule("inbound_malware", "Logiciel malveillant ou pièce jointe dangereuse", [_cond("malware", ">=", 50)], "quarantine", folder="Malware"),
        _rule("inbound_impostor", "Usurpation d'identité et fraude", [_cond("impostor", ">=", 80)], "quarantine", folder="Usurpation"),
        _rule("inbound_phish", "Hameçonnage", [_cond("phish", ">=", 80)], "quarantine", folder="Hameçonnage"),
        _rule("inbound_safe", "Liste sûre", LOCKED_CONDITIONS["inbound_safe"], "deliver"),
        dmarc,
        _rule("inbound_spam_definite", "Spam certain", [_cond("spam", ">=", 100)], "reject"),
        _rule("inbound_spam", "Spam mis en quarantaine", [_cond("spam", ">=", 50)], "quarantine", folder="Spam", user_access=True),
        _rule("inbound_junk", "Courrier indésirable probable", [_cond("spam", ">=", 25)], "tag"),
        _rule("inbound_bulk", "Courrier en masse", [_cond("bulk", ">=", 80)], "quarantine", folder="Courrier en masse", user_access=True, enabled=False),
        _rule("inbound_lowpriority", "Faible priorité", [_cond("bulk", ">=", 80)], "continue",
              headers=[{"name": "X-Spambuntu-Tag", "value": "lowpriority"}], enabled=False),
        _rule("inbound_notspam", "Courrier légitime", LOCKED_CONDITIONS["inbound_notspam"], "deliver"),
    ]


# --------------------------------------------------------------------------- validation

def folder_id(name: str) -> str:
    """Identifiant ASCII d'un dossier (sert dans les en-têtes Rspamd, où les accents sont évités)."""
    text = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:30]
    return text or "dossier"


def _number(value, label, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise RulesError(f"{label} : valeur numérique attendue")
    try:
        number = float(str(value).strip().replace(",", "."))
    except ValueError:
        raise RulesError(f"{label} : valeur numérique attendue") from None
    if not low <= number <= high:
        raise RulesError(f"{label} : la valeur doit être comprise entre {low:g} et {high:g}")
    return int(number) if number == int(number) else round(number, 2)


def validate_condition(raw) -> dict:
    if not isinstance(raw, dict) or set(raw) - {"field", "op", "value"}:
        raise RulesError("Condition mal formée")
    field, op, value = raw.get("field"), raw.get("op"), raw.get("value")
    spec = FIELDS.get(field)
    if spec is None:
        raise RulesError(f"Champ de condition inconnu : {str(field)[:40]!r}")
    kind = spec["type"]
    if op not in OPS[kind]:
        raise RulesError(f"« {spec['label']} » : opérateur {str(op)[:20]!r} incompatible")
    if kind == "number":
        value = _number(value, spec["label"], spec["min"], spec["max"])
    elif kind == "bool":
        if not isinstance(value, bool):
            raise RulesError(f"« {spec['label']} » : choisissez vrai ou faux")
    elif kind == "symbol":
        if not isinstance(value, str) or not SYMBOL_RE.fullmatch(value.strip().upper()):
            raise RulesError("Nom de règle Rspamd invalide (majuscules, chiffres et _)")
        value = value.strip().upper()
    else:
        if not isinstance(value, str) or not TEXT_VALUE_RE.fullmatch(value.strip()):
            raise RulesError(f"« {spec['label']} » : texte de 1 à 120 caractères attendu")
        value = value.strip().lower()
    return {"field": field, "op": op, "value": value}


def validate_header(raw) -> dict:
    if not isinstance(raw, dict) or set(raw) - {"name", "value"}:
        raise RulesError("En-tête mal formé")
    name, value = raw.get("name"), raw.get("value")
    if not isinstance(name, str) or not HEADER_NAME_RE.fullmatch(name.strip()):
        raise RulesError(f"Nom d'en-tête invalide : {str(name)[:40]!r} (il doit commencer par X-)")
    if name.strip().lower() in RESERVED_HEADERS:
        raise RulesError(f"En-tête réservé : {name.strip()}")
    if not isinstance(value, str) or not HEADER_VALUE_RE.fullmatch(value.strip()):
        raise RulesError("Valeur d'en-tête invalide (texte ASCII de 1 à 200 caractères)")
    return {"name": name.strip(), "value": value.strip()}


def validate_rule(raw) -> dict:
    keys = {"id", "enabled", "description", "match", "conditions", "disposition", "folder", "user_access", "headers", "explain"}
    if not isinstance(raw, dict) or set(raw) - keys:
        raise RulesError("Règle mal formée")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not RULE_ID_RE.fullmatch(rule_id):
        raise RulesError("Classification invalide : minuscules, chiffres et _ (3 à 40 caractères, commence par une lettre)")
    description = raw.get("description", "")
    if not isinstance(description, str) or not DESCRIPTION_RE.fullmatch(description.strip()):
        raise RulesError("Description invalide (1 à 80 caractères)")
    if raw.get("match", "all") not in ("all", "any"):
        raise RulesError("Mode de combinaison invalide (all ou any)")
    disposition = raw.get("disposition")
    if disposition not in DISPOSITIONS:
        raise RulesError("Action invalide")
    for flag in ("enabled", "user_access", "explain"):
        if not isinstance(raw.get(flag, False), bool):
            raise RulesError(f"Option invalide : {flag}")
    conditions = raw.get("conditions")
    if not isinstance(conditions, list) or not 1 <= len(conditions) <= MAX_CONDITIONS:
        raise RulesError(f"Une règle a de 1 à {MAX_CONDITIONS} conditions")
    headers = raw.get("headers", [])
    if not isinstance(headers, list) or len(headers) > MAX_HEADERS:
        raise RulesError(f"Au plus {MAX_HEADERS} en-têtes personnalisés")
    folder = raw.get("folder", "")
    if disposition == "quarantine":
        if not isinstance(folder, str) or not FOLDER_RE.fullmatch(folder.strip()):
            raise RulesError("Nom de dossier invalide (1 à 40 caractères : lettres, chiffres, espace, . ' - _)")
        folder = " ".join(folder.split())
    else:
        folder = ""
    names = [h.get("name", "").lower() for h in headers if isinstance(h, dict)]
    if len(set(names)) != len(names):
        raise RulesError("Deux en-têtes portent le même nom")
    return {
        "id": rule_id, "enabled": raw.get("enabled", True), "description": " ".join(description.split()),
        "match": raw.get("match", "all"), "conditions": [validate_condition(c) for c in conditions],
        "disposition": disposition, "folder": folder,
        "user_access": raw.get("user_access", False) if disposition == "quarantine" else False,
        "headers": [validate_header(h) for h in headers], "explain": raw.get("explain", True),
    }


def validate_rules(raw, dmarc_action: str = "reject") -> list:
    """Valide la liste complète. Absente (None) : règles par défaut. Garantit l'invariant « inbound_notspam est la dernière »."""
    if raw is None:
        return default_rules(dmarc_action)
    if not isinstance(raw, list) or len(raw) > MAX_RULES:
        raise RulesError(f"Liste de règles invalide (maximum {MAX_RULES})")
    rules, seen = [], set()
    for item in raw:
        rule = validate_rule(item)
        if rule["id"] in seen:
            raise RulesError(f"Classification en double : {rule['id']}")
        seen.add(rule["id"])
        rules.append(rule)
    fallback = next((r for r in rules if r["id"] == LAST_RULE), None) or next(r for r in default_rules() if r["id"] == LAST_RULE)
    rules = [r for r in rules if r["id"] != LAST_RULE]
    for rule in rules:
        allowed = LOCKED_DISPOSITIONS.get(rule["id"])
        if allowed and rule["disposition"] not in allowed:
            raise RulesError(f"Action impossible pour la règle « {rule['id']} »")
        if rule["id"] in LOCKED_CONDITIONS:
            rule["conditions"], rule["match"] = copy.deepcopy(LOCKED_CONDITIONS[rule["id"]]), "all"
    fallback["conditions"], fallback["match"] = copy.deepcopy(LOCKED_CONDITIONS[LAST_RULE]), "all"
    fallback.update(enabled=True, disposition="deliver", folder="", user_access=False)
    rules.append(fallback)
    # Règles fournies manquantes (configuration ancienne ou abîmée) : liste de blocage en tête, liste sûre avant la dernière.
    if "inbound_blocked" not in seen:
        rules.insert(0, next(r for r in default_rules() if r["id"] == "inbound_blocked"))
    if "inbound_safe" not in seen:
        rules.insert(len(rules) - 1, next(r for r in default_rules() if r["id"] == "inbound_safe"))
    return rules


def _entry_kind(entry: str) -> str:
    if "@" in entry:
        return "address"
    try:
        ipaddress.ip_network(entry, strict=False)
        return "ip"
    except ValueError:
        return "domain"


_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_ADDRESS_RE = re.compile(r"[a-z0-9._%+-]{1,64}@" + _LABEL + r"(?:\." + _LABEL + r")+")
_DOMAIN_RE = re.compile(_LABEL + r"(?:\." + _LABEL + r")+")


def validate_list(raw, what: str = "liste") -> list:
    """Adresse (a@b.fr), domaine (b.fr, sous-domaines compris) ou adresse IP / réseau (203.0.113.0/24)."""
    if not isinstance(raw, list) or len(raw) > MAX_LIST:
        raise RulesError(f"La {what} est invalide (maximum {MAX_LIST} entrées)")
    clean = []
    for item in raw:
        if not isinstance(item, str) or len(item) > 254:
            raise RulesError(f"Entrée invalide dans la {what}")
        entry = item.strip().lower()
        kind = _entry_kind(entry)
        if kind == "address" and not _ADDRESS_RE.fullmatch(entry):
            raise RulesError(f"Adresse invalide dans la {what} : {item[:60]!r}")
        if kind == "domain" and (not _DOMAIN_RE.fullmatch(entry) or entry.rsplit(".", 1)[1].isdigit()):
            raise RulesError(f"Entrée invalide dans la {what} : {item[:60]!r} (adresse, domaine ou réseau IP attendus)")
        if kind == "ip":
            net = ipaddress.ip_network(entry, strict=False)
            if net.prefixlen == 0:
                raise RulesError(f"Un réseau « tout internet » est refusé dans la {what}")
            entry = str(net.network_address) if net.num_addresses == 1 else str(net)
        if entry not in clean:
            clean.append(entry)
    return clean


def validate_lists(raw) -> dict:
    if raw is None:
        return {"block": [], "safe": []}
    if not isinstance(raw, dict) or set(raw) - {"block", "safe"}:
        raise RulesError("Listes invalides")
    return {"block": validate_list(raw.get("block", []), "liste de blocage"), "safe": validate_list(raw.get("safe", []), "liste sûre")}


# --------------------------------------------------------------------------- opérations sur la liste ordonnée

def _index(rules: list, rule_id: str) -> int:
    for i, rule in enumerate(rules):
        if rule["id"] == rule_id:
            return i
    raise RulesError("Règle introuvable")


def upsert(rules: list, rule: dict, original_id: str | None = None) -> list:
    """Ajoute la règle (en avant-dernière position) ou remplace `original_id` à sa place."""
    rules = copy.deepcopy(rules)
    if original_id is None:
        if any(r["id"] == rule["id"] for r in rules):
            raise RulesError(f"La classification « {rule['id']} » existe déjà")
        rules.insert(len(rules) - 1, rule)
    else:
        i = _index(rules, original_id)
        if rule["id"] != original_id and any(r["id"] == rule["id"] for r in rules):
            raise RulesError(f"La classification « {rule['id']} » existe déjà")
        if original_id in PROTECTED and rule["id"] != original_id:
            raise RulesError("La classification d'une règle fournie ne peut pas être renommée")
        rules[i] = rule
    return validate_rules(rules)


def toggle(rules: list, rule_id: str) -> list:
    if rule_id == LAST_RULE:
        raise RulesError("Cette règle est toujours active")
    rules = copy.deepcopy(rules)
    rule = rules[_index(rules, rule_id)]
    rule["enabled"] = not rule["enabled"]
    return validate_rules(rules)


def move(rules: list, rule_id: str, delta: int) -> list:
    if rule_id == LAST_RULE:
        raise RulesError("Cette règle reste toujours en dernier")
    rules = copy.deepcopy(rules)
    i = _index(rules, rule_id)
    j = i + (1 if delta > 0 else -1)
    if j < 0 or j >= len(rules) - 1:       # la dernière position est réservée à inbound_notspam
        return rules
    rules[i], rules[j] = rules[j], rules[i]
    return validate_rules(rules)


def delete(rules: list, rule_id: str) -> list:
    if rule_id in PROTECTED:
        raise RulesError("Cette règle fait partie des règles fournies : elle peut être modifiée mais pas supprimée")
    rules = copy.deepcopy(rules)
    del rules[_index(rules, rule_id)]
    return validate_rules(rules)


def clone(rules: list, rule_id: str) -> tuple:
    """(nouvelle liste, identifiant de la copie). La copie est insérée juste après l'original, désactivée."""
    rules = copy.deepcopy(rules)
    i = _index(rules, rule_id)
    if rule_id == LAST_RULE:
        raise RulesError("Cette règle ne peut pas être clonée")
    copy_rule = copy.deepcopy(rules[i])
    base = rule_id[:33]
    new_id, n = f"{base}_copie", 2
    while any(r["id"] == new_id for r in rules):
        new_id, n = f"{base}_copie{n}", n + 1
    copy_rule.update(id=new_id, enabled=False, description=(copy_rule["description"] + " (copie)")[:80])
    rules.insert(i + 1, copy_rule)
    return validate_rules(rules), new_id


def rule_warnings(rule: dict) -> list:
    """Avertissements (non bloquants) sur une règle : réglage légitime mais risqué."""
    if rule["disposition"] != "deliver" or rule["id"] in PROTECTED:
        return []
    senders = [c for c in rule["conditions"] if c["field"] == "sender"]
    if senders and (rule["match"] == "any" or len(senders) == len(rule["conditions"])):
        return ["Cette règle livre le courrier d'après l'adresse de l'expéditeur, qui se falsifie facilement : "
                "elle passe avant les règles suivantes, y compris celles qui détectent un programme malveillant. "
                "La liste sûre, elle, exige que l'expéditeur soit authentifié (SPF ou DMARC)."]
    return []


def folders(rules: list) -> list:
    """Dossiers de quarantaine définis par les règles : [{"id", "name", "user_access"}], sans doublon."""
    seen, out = set(), []
    for rule in rules:
        if rule["disposition"] == "quarantine" and folder_id(rule["folder"]) not in seen:
            seen.add(folder_id(rule["folder"]))
            out.append({"id": folder_id(rule["folder"]), "name": rule["folder"], "user_access": rule["user_access"]})
    return out


# --------------------------------------------------------------------------- description en français

def describe_condition(cond: dict) -> str:
    spec = FIELDS[cond["field"]]
    if spec["type"] == "bool":
        return spec["label"] if cond["value"] else spec["label_no"]
    if spec["type"] == "number":
        return f"{spec['label']} {OP_LABELS[cond['op']]} {cond['value']}"
    return f"{spec['label']} {OP_LABELS[cond['op']]} « {cond['value']} »"


def describe_conditions(rule: dict) -> str:
    joiner = " ET " if rule["match"] == "all" else " OU "
    return joiner.join(describe_condition(c) for c in rule["conditions"])


def describe_actions(rule: dict) -> list:
    lines = []
    if rule["explain"]:
        lines.append("Ajouter les en-têtes X-Spambuntu-*.")
    lines += [f"Ajouter l'en-tête {h['name']}: {h['value']}." for h in rule["headers"]]
    d = rule["disposition"]
    if d == "quarantine":
        who = "accessible à l'utilisateur" if rule["user_access"] else "réservé à l'administrateur"
        lines.append(f"Mettre en quarantaine, dossier [{rule['folder']}] ({who}).")
    else:
        lines.append({"deliver": "Livrer le message sans évaluer les règles suivantes.",
                      "tag": "Livrer le message en le marquant (X-Spam: Yes).",
                      "reject": "Rejeter le message (refus SMTP définitif).",
                      "continue": "Poursuivre avec la règle suivante."}[d])
    return lines


# --------------------------------------------------------------------------- évaluation (équivalent Python du moteur Lua)

def spam_score(raw: float, th: dict) -> int:
    """Score de spam 0-100 : le seuil de marquage vaut 25, de quarantaine 50, de rejet 100 (interpolation linéaire)."""
    if raw <= 0:
        return 0
    if raw >= th["reject"]:
        return 100
    points = ((0.0, 0.0), (th["tag"], 25.0), (th["quarantine"], 50.0), (th["reject"], 100.0))
    for (x0, y0), (x1, y1) in zip(points, points[1:]):
        if raw < x1:
            return int(y0 + (raw - x0) / (x1 - x0) * (y1 - y0))
    return 100


def class_scores(symbols, raw: float, th: dict) -> dict:
    names = set(symbols)
    out = {"spam": spam_score(raw, th)}
    for cls, signals in SIGNALS.items():
        total = 0
        for kind, name, points in signals:
            if (kind == "exact" and name in names) or (kind == "contains" and any(name in s for s in names)):
                total += points
        out[cls] = min(100, total)
    return out


def _domains_of(addr: str) -> list:
    domain = addr.rpartition("@")[2]
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts) - 1)] if domain else []


def in_list(entries: list, addrs: list, ip: str) -> bool:
    exact = {e for e in entries if "@" in e}
    domains = {e for e in entries if "@" not in e and _entry_kind(e) == "domain"}
    for addr in addrs:
        if addr and (addr in exact or any(d in domains for d in _domains_of(addr))):
            return True
    if ip:
        try:
            client = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in entries:
            if "@" not in entry and _entry_kind(entry) == "ip" and client in ipaddress.ip_network(entry, strict=False):
                return True
    return False


def _aligned(a: str, b: str) -> bool:
    return bool(a) and bool(b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


def build_context(*, symbols, raw: float, th: dict, lists: dict, mime_from: str = "", env_from: str = "", rcpts=(), ip: str = "") -> dict:
    """Contexte d'évaluation d'un message (adresses en minuscules)."""
    names = set(symbols)
    mime_from, env_from = (mime_from or "").lower(), (env_from or "").lower()
    from_domain, env_domain = mime_from.rpartition("@")[2], env_from.rpartition("@")[2]
    authenticated = "DMARC_POLICY_ALLOW" in names or ("R_SPF_ALLOW" in names and _aligned(from_domain, env_domain))
    safe_by_ip = in_list(lists["safe"], [], ip)
    return {
        "scores": class_scores(names, raw, th), "raw": raw, "symbols": names,
        "blocklist": in_list(lists["block"], [mime_from, env_from], ip),
        "safelist": safe_by_ip or (authenticated and in_list(lists["safe"], [mime_from], "")),
        "dmarc_reject": "DMARC_POLICY_REJECT" in names,
        "senders": [a for a in (mime_from, env_from) if a], "recipients": [r.lower() for r in rcpts],
    }


def condition_matches(cond: dict, ctx: dict) -> bool:
    field, op, value = cond["field"], cond["op"], cond["value"]
    if field in ctx["scores"]:
        return ctx["scores"][field] >= value if op == ">=" else ctx["scores"][field] <= value
    if field == "score":
        return ctx["raw"] >= value if op == ">=" else ctx["raw"] <= value
    if field in ("blocklist", "safelist", "dmarc_reject"):
        return bool(ctx[field]) == value
    if field == "symbol":
        return (value in ctx["symbols"]) == (op == "present")
    values = ctx["senders"] if field == "sender" else ctx["recipients"]
    test = {"contains": lambda v: value in v, "equals": lambda v: v == value, "ends_with": lambda v: v.endswith(value)}[op]
    return any(test(v) for v in values)


def evaluate(rules: list, ctx: dict) -> dict:
    """{"matched": [règles satisfaites, dans l'ordre], "final": règle qui décide (ou None)}."""
    matched, final = [], None
    for rule in rules:
        if not rule["enabled"]:
            continue
        results = [condition_matches(c, ctx) for c in rule["conditions"]]
        if all(results) if rule["match"] == "all" else any(results):
            matched.append(rule)
            if rule["disposition"] != "continue":
                final = rule
                break
    return {"matched": matched, "final": final}


# --------------------------------------------------------------------------- rendu pour Rspamd

def render(rules: list, lists: dict, thresholds: dict, quarantine_enabled: bool) -> dict:
    """Configuration lue par le moteur Lua (/etc/rspamd/local.d/spambuntu-rules.json). Règles actives seulement."""
    active = []
    for rule in rules:
        if not rule["enabled"]:
            continue
        active.append({
            "id": rule["id"], "match": rule["match"], "conditions": rule["conditions"], "disposition": rule["disposition"],
            "folder": folder_id(rule["folder"]) if rule["disposition"] == "quarantine" else "",
            "access": "user" if rule["user_access"] else "admin", "headers": rule["headers"], "explain": rule["explain"],
        })
    signals = {cls: [{"kind": k, "name": n, "points": p} for k, n, p in items] for cls, items in SIGNALS.items()}
    return {"enabled": True, "quarantine_enabled": quarantine_enabled, "thresholds": thresholds, "signals": signals,
            "lists": lists, "rules": active}
