#!/usr/bin/env python3
"""Configuration de la passerelle de messagerie Spambuntu (Postfix + Rspamd).

  spambuntu-mail init                 crée la configuration par défaut si elle n'existe pas (root)
  spambuntu-mail apply                applique /etc/spambuntu/mail.json : rend les fichiers, recharge (root)
  spambuntu-mail apply --from-request applique la demande déposée par la console web (root)
  spambuntu-mail show                 affiche la configuration

La console web n'écrit jamais dans /etc : elle dépose une demande JSON, qu'une unité root valide
(à nouveau, intégralement) avant de l'installer. Toute valeur injectée dans la configuration de
Postfix ou de Rspamd passe d'abord par les validateurs de ce module.
"""
from __future__ import annotations

import argparse
import contextlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CONF_PATH = Path("/etc/spambuntu/mail.json")
STATE_DIR = Path("/var/lib/spambuntu/mail")
POSTFIX_DIR = Path("/etc/postfix/spambuntu")
RSPAMD_DIR = Path("/etc/rspamd")
REQUEST_MAX_AGE = 600
MAX_DOMAINS = 200
MAX_NETWORKS = 50

DEFAULTS = {
    "hostname": "",
    "domains": [],
    "thresholds": {"tag": 5.0, "quarantine": 8.0, "reject": 15.0},
    "quarantine_enabled": True,
    "verify_recipients": True,
    "max_message_mb": 50,
    "trusted_networks": [],
    "digest_enabled": False,            # résumé quotidien de quarantaine envoyé aux destinataires
    "digest_from": "",                  # expéditeur du résumé (vide : quarantaine@<nom d'hôte>)
    "digest_base_url": "",              # https://hôte[:port] de la console, pour les liens de libération (vide : sans liens)
    "digest_release_max_score": 10.0,   # score au-delà duquel un message n'est pas libérable depuis le résumé
}

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")
DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


class MailError(Exception):
    """Configuration invalide ou opération refusée (message destiné à l'administrateur)."""


# --------------------------------------------------------------------------- validation

def _hostname(value, what: str) -> str:
    if not isinstance(value, str) or len(value) > 253 or not HOSTNAME_RE.fullmatch(value):
        raise MailError(f"{what} invalide : {str(value)[:60]!r}")
    return value.lower()


def _relay(value) -> str:
    """« hôte » ou « hôte:port » (hôte = nom DNS ou IPv4). Retourne « hôte:port »."""
    if not isinstance(value, str):
        raise MailError("Serveur de destination invalide")
    host, sep, port = value.strip().partition(":")
    if sep and not port.isdigit():
        raise MailError(f"Port invalide dans « {value[:60]} »")
    port_n = int(port) if sep else 25
    if not 1 <= port_n <= 65535:
        raise MailError(f"Port hors limites dans « {value[:60]} »")
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        host = _hostname(host, "Nom du serveur de destination")
    return f"{host}:{port_n}"


def _number(value, what: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise MailError(f"{what} invalide")
    try:
        number = float(value)
    except ValueError:
        raise MailError(f"{what} invalide") from None
    if not low <= number <= high:
        raise MailError(f"{what} doit être compris entre {low:g} et {high:g}")
    return round(number, 2)


def validate(raw) -> dict:
    """Valide et normalise une configuration. Lève MailError ; ne renvoie que des valeurs sûres."""
    if not isinstance(raw, dict):
        raise MailError("Configuration illisible")
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise MailError(f"Champ inconnu : {sorted(unknown)[0]}")
    cfg = json.loads(json.dumps(DEFAULTS))
    cfg.update({k: v for k, v in raw.items() if k != "thresholds"})

    cfg["hostname"] = _hostname(cfg["hostname"], "Nom d'hôte") if cfg["hostname"] else ""

    domains = cfg["domains"]
    if not isinstance(domains, list) or len(domains) > MAX_DOMAINS:
        raise MailError(f"Liste de domaines invalide (maximum {MAX_DOMAINS})")
    seen, clean = set(), []
    for item in domains:
        if not isinstance(item, dict) or set(item) - {"name", "relay"}:
            raise MailError("Domaine mal formé")
        name = item.get("name")
        if not isinstance(name, str) or len(name) > 253 or not DOMAIN_RE.fullmatch(name):
            raise MailError(f"Nom de domaine invalide : {str(name)[:60]!r}")
        name = name.lower()
        if name in seen:
            raise MailError(f"Domaine en double : {name}")
        seen.add(name)
        clean.append({"name": name, "relay": _relay(item.get("relay", ""))})
    cfg["domains"] = clean

    given = raw.get("thresholds", {})
    if not isinstance(given, dict) or set(given) - set(DEFAULTS["thresholds"]):
        raise MailError("Seuils invalides")
    thresholds = {**DEFAULTS["thresholds"], **given}
    tag = _number(thresholds["tag"], "Seuil de marquage", 0.5, 50)
    quarantine = _number(thresholds["quarantine"], "Seuil de quarantaine", 0.5, 50)
    reject = _number(thresholds["reject"], "Seuil de rejet", 0.5, 100)
    if not tag < quarantine < reject:
        raise MailError("Les seuils doivent être croissants : marquage < quarantaine < rejet")
    cfg["thresholds"] = {"tag": tag, "quarantine": quarantine, "reject": reject}

    if not isinstance(cfg["quarantine_enabled"], bool):
        raise MailError("Option de quarantaine invalide")
    if not isinstance(cfg["verify_recipients"], bool):
        raise MailError("Option de vérification des destinataires invalide")
    cfg["max_message_mb"] = int(_number(cfg["max_message_mb"], "Taille maximale des messages (Mo)", 1, 500))

    if not isinstance(cfg["digest_enabled"], bool):
        raise MailError("Option du résumé quotidien invalide")
    sender = cfg["digest_from"]
    if sender != "" and not (isinstance(sender, str) and re.fullmatch(r"[A-Za-z0-9._+-]{1,64}@" + _LABEL + r"(?:\." + _LABEL + r")+", sender)):
        raise MailError("Expéditeur du résumé invalide")
    base = cfg["digest_base_url"]
    if base != "":
        m = re.fullmatch(r"https://(" + _LABEL + r"(?:\." + _LABEL + r")*|\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?", base if isinstance(base, str) else "")
        if not m or (m.group(2) and not 1 <= int(m.group(2)) <= 65535):
            raise MailError("Adresse de la console invalide (https://hôte[:port])")
    cfg["digest_release_max_score"] = _number(cfg["digest_release_max_score"], "Score maximal de libération", 0, 100)

    networks = cfg["trusted_networks"]
    if not isinstance(networks, list) or len(networks) > MAX_NETWORKS:
        raise MailError("Réseaux de confiance invalides")
    nets = []
    for net in networks:
        try:
            parsed = ipaddress.ip_network(str(net).strip(), strict=False)
        except ValueError:
            raise MailError(f"Réseau invalide : {str(net)[:60]!r}") from None
        if parsed.prefixlen == 0:
            raise MailError("Un réseau de confiance ne peut pas être « tout internet »")
        nets.append(str(parsed))
    cfg["trusted_networks"] = nets
    return cfg


# --------------------------------------------------------------------------- rendu

TLS_DIR = Path("/etc/spambuntu/tls")


def render(cfg: dict, system_hostname: str = "localhost.localdomain", tls: bool = False) -> dict:
    """Retourne {"files": {nom: contenu}, "postconf": {clé: valeur}} pour une configuration VALIDÉE."""
    th = cfg["thresholds"]
    files = {
        "relay_domains": "".join(f"{d['name']} OK\n" for d in cfg["domains"]),
        "transport": "".join(
            f"{d['name']} smtp:[{d['relay'].rsplit(':', 1)[0]}]:{d['relay'].rsplit(':', 1)[1]}\n" for d in cfg["domains"]
        ),
        # Le fichier est inclus DANS la section « actions » de Rspamd : uniquement des clés.
        "rspamd-actions.conf": (
            "# Géré par Spambuntu : ne pas modifier\n"
            f"reject = {th['reject']};\n"
            # Marquage (en-tête X-Spam: Yes) < quarantaine (le milter demande à Postfix de garder le message
            # en attente, file « hold ») < rejet. Sans quarantaine, le niveau retombe sur le marquage.
            f"add_header = {th['tag']};\n"
            + (f"quarantine = {th['quarantine']};\n" if cfg["quarantine_enabled"] else "")
            + "greylist = null;\n"
        ),
        "rspamd-milter_headers.conf": (
            "# Géré par Spambuntu : ne pas modifier\n"
            'use = ["x-rspamd-action", "spam-header", "authentication-results", "x-spamd-result"];\n'
            'routines { "spam-header" { header = "X-Spam"; value = "Yes"; remove = 0; } }\n'
            "authenticated_headers = [];\n"
            "extended_spam_headers = false;\n"
            "skip_local = false;\n"
            "skip_authenticated = false;\n"
        ),
        # Pas de greylisting par défaut : il retarde tout premier message d'un nouvel expéditeur.
        "rspamd-greylist.conf": "# Géré par Spambuntu : ne pas modifier\nenabled = false;\n",
        # Les réseaux de confiance (serveurs internes) ne sont pas jugés comme des expéditeurs externes.
        "rspamd-options.inc": "# Géré par Spambuntu : ne pas modifier\n"
        + (f"local_addrs = [{', '.join(chr(34) + n + chr(34) for n in cfg['trusted_networks'])}];\n"
           if cfg["trusted_networks"] else ""),
        "rspamd-redis.conf": '# Géré par Spambuntu : ne pas modifier\nservers = "127.0.0.1";\n',
    }
    mynetworks = ["127.0.0.0/8", "[::1]/128", *cfg["trusted_networks"]]
    size = cfg["max_message_mb"] * 1024 * 1024
    postconf = {
        "myhostname": cfg["hostname"] or system_hostname,
        "inet_interfaces": "all",
        "mydestination": "",
        "mynetworks": ", ".join(mynetworks),
        "relay_domains": f"texthash:{POSTFIX_DIR}/relay_domains",
        "transport_maps": f"texthash:{POSTFIX_DIR}/transport",
        "relay_recipient_maps": "",
        "local_recipient_maps": "",
        "smtpd_helo_required": "yes",
        "smtpd_relay_restrictions": "permit_mynetworks, reject_unauth_destination",
        # Avec la vérification, Postfix demande au serveur de destination si le destinataire existe avant d'accepter
        # le message : un destinataire inconnu est refusé tout de suite (pas de rejet renvoyé à un faux expéditeur).
        "smtpd_recipient_restrictions": "permit_mynetworks, reject_non_fqdn_recipient, reject_unauth_destination"
        + (", reject_unverified_recipient" if cfg["verify_recipients"] else ""),
        "unverified_recipient_reject_code": "550",
        "address_verify_negative_cache": "yes",
        "smtpd_milters": "inet:127.0.0.1:11332",
        "non_smtpd_milters": "$smtpd_milters",
        "milter_default_action": "tempfail",
        "milter_protocol": "6",
        "milter_mail_macros": "i {mail_addr} {client_addr} {client_name} {auth_authen}",
        "header_checks": "",
        "message_size_limit": str(size),
        "smtp_tls_security_level": "may",
        "smtpd_tls_security_level": "may" if tls else "none",
        "smtpd_tls_cert_file": f"{TLS_DIR}/smtp.crt" if tls else "",
        "smtpd_tls_key_file": f"{TLS_DIR}/smtp.key" if tls else "",
        "smtpd_tls_protocols": "!SSLv2, !SSLv3, !TLSv1, !TLSv1.1",
        "smtpd_tls_loglevel": "1",
        "disable_vrfy_command": "yes",
        "smtpd_banner": "$myhostname ESMTP",
    }
    return {"files": files, "postconf": postconf}


# --------------------------------------------------------------------------- application

def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False, **kw)


def write_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def load_config(conf: Path = CONF_PATH) -> dict:
    raw = read_json(conf, None)
    return validate(raw) if raw is not None else validate({})


def read_request(request: Path) -> dict:
    """Lit la demande de la console : fichier ordinaire, non lié symboliquement, récent."""
    try:
        fd = os.open(request, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise MailError(f"Demande illisible : {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not os.path.isfile(request) or st.st_size > 256 * 1024:
            raise MailError("Demande invalide")
        if time.time() - st.st_mtime > REQUEST_MAX_AGE:
            raise MailError("Demande périmée : renvoyez-la depuis la console")
        try:
            data = json.loads(fh.read().decode("utf-8"))
        except ValueError:
            raise MailError("Demande illisible") from None
    return data


class Applier:
    """Applique une configuration validée. `root` permet de tester dans un arbre factice ;
    `run` est injectable (tests)."""

    def __init__(self, root: Path | None = None, run=_run, reload: bool = True):
        self.root = Path(root) if root else None
        self.run = run
        self.reload = reload

    def p(self, path: Path) -> Path:
        return self.root / str(path).lstrip("/") if self.root else Path(path)

    def _postconf_get(self, key: str) -> str:
        out = self.run(["postconf", "-h", key])
        return out.stdout.strip() if out.returncode == 0 else ""

    def apply(self, cfg: dict) -> None:
        system_hostname = (Path(self.p(Path("/etc/hostname"))).read_text().strip()
                           if self.p(Path("/etc/hostname")).is_file() else "localhost.localdomain") or "localhost.localdomain"
        tls = self.p(TLS_DIR / "smtp.crt").is_file() and self.p(TLS_DIR / "smtp.key").is_file()
        plan = render(cfg, system_hostname, tls)
        targets = {
            "relay_domains": self.p(POSTFIX_DIR / "relay_domains"),
            "transport": self.p(POSTFIX_DIR / "transport"),
            "rspamd-actions.conf": self.p(RSPAMD_DIR / "override.d" / "actions.conf"),
            "rspamd-milter_headers.conf": self.p(RSPAMD_DIR / "local.d" / "milter_headers.conf"),
            "rspamd-greylist.conf": self.p(RSPAMD_DIR / "local.d" / "greylist.conf"),
            "rspamd-options.inc": self.p(RSPAMD_DIR / "local.d" / "options.inc"),
            "rspamd-redis.conf": self.p(RSPAMD_DIR / "local.d" / "redis.conf"),
        }
        before = {name: (path.read_text(encoding="utf-8") if path.is_file() else None) for name, path in targets.items()}
        old_conf = {key: self._postconf_get(key) for key in plan["postconf"]}
        try:
            for name, path in targets.items():
                write_atomic(path, plan["files"][name])
            settings = [f"{k}={v}" for k, v in plan["postconf"].items()]
            res = self.run(["postconf", "-e", *settings])
            if res.returncode != 0:
                raise MailError(f"postconf a échoué : {res.stderr.strip()[:300]}")
            res = self.run(["postfix", "check"])
            if res.returncode != 0:
                raise MailError(f"Configuration Postfix refusée : {res.stderr.strip()[:300]}")
            res = self.run(["rspamadm", "configtest"])
            if res.returncode != 0:
                raise MailError(f"Configuration Rspamd refusée : {(res.stdout + res.stderr).strip()[:300]}")
        except Exception:
            self._restore(targets, before, old_conf)
            raise
        if not self.reload:
            return
        for unit in ("rspamd", "postfix"):
            res = self.run(["systemctl", "reload-or-restart", unit])
            if res.returncode != 0:
                raise MailError(f"Rechargement de {unit} impossible : {res.stderr.strip()[:300]}")

    def _restore(self, targets, before, old_conf) -> None:
        for name, path in targets.items():
            if before[name] is None:
                with contextlib.suppress(OSError):
                    path.unlink()
            else:
                with contextlib.suppress(OSError):
                    write_atomic(path, before[name])
        if old_conf:
            self.run(["postconf", "-e", *[f"{k}={v}" for k, v in old_conf.items()]])


def ensure_tls_certificate(tls_dir: Path = TLS_DIR, hostname: str = "", run=_run) -> bool:
    """Certificat auto-signé pour le TLS entrant de Postfix (jamais écrasé). Retourne True s'il en existe un."""
    crt, key = tls_dir / "smtp.crt", tls_dir / "smtp.key"
    if crt.is_file() and key.is_file():
        return True
    host = hostname or (Path("/etc/hostname").read_text().strip() if Path("/etc/hostname").is_file() else "") or "spambuntu"
    if not HOSTNAME_RE.fullmatch(host):
        host = "spambuntu"
    tls_dir.mkdir(parents=True, exist_ok=True)
    res = run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
               "-days", "3650", "-subj", f"/CN={host}", "-addext", f"subjectAltName=DNS:{host}",
               "-keyout", str(key), "-out", str(crt)])
    if res.returncode != 0:
        return False
    os.chmod(key, 0o600)        # lu par le processus maître de Postfix (root) uniquement
    os.chmod(crt, 0o644)
    return True


def write_status(state_dir: Path, ok: bool, message: str) -> None:
    write_atomic(state_dir / "user" / "mail-status.json",
                 json.dumps({"ok": ok, "message": message,
                             "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, ensure_ascii=False))


def cmd_apply(args, applier: Applier | None = None, conf: Path = CONF_PATH, state_dir: Path = STATE_DIR) -> int:
    applier = applier or Applier()
    try:
        if args.from_request:
            if os.geteuid() != 0 and not applier.root:
                raise MailError("Cette commande doit être exécutée en root")
            cfg = validate(read_request(state_dir / "user" / "mail-request.json"))
            write_atomic(conf, json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", 0o640)
            with contextlib.suppress(OSError, KeyError):
                import grp
                os.chown(conf, -1, grp.getgrnam("spambuntu").gr_gid)
            with contextlib.suppress(OSError):
                (state_dir / "user" / "mail-request.json").unlink()
        else:
            cfg = load_config(conf)
        applier.apply(cfg)
    except MailError as exc:
        write_status(state_dir, False, str(exc))
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    write_status(state_dir, True, "Configuration appliquée")
    print("Configuration de la messagerie appliquée")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-mail", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init", help="créer la configuration par défaut")
    i.add_argument("--no-reload", action="store_true", help="ne pas recharger les services (installation, ISO)")
    a = sub.add_parser("apply", help="appliquer la configuration")
    a.add_argument("--from-request", action="store_true")
    sub.add_parser("show", help="afficher la configuration")
    args = ap.parse_args(argv)
    if args.cmd == "show":
        print(json.dumps(load_config(), indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "init":
        if not CONF_PATH.exists():
            write_atomic(CONF_PATH, json.dumps(validate({}), indent=2) + "\n", 0o640)
            with contextlib.suppress(OSError, KeyError):
                import grp
                os.chown(CONF_PATH, -1, grp.getgrnam("spambuntu").gr_gid)
        STATE_DIR.joinpath("user").mkdir(parents=True, exist_ok=True)
        ensure_tls_certificate()
        return cmd_apply(argparse.Namespace(from_request=False), applier=Applier(reload=not args.no_reload))
    return cmd_apply(args)


if __name__ == "__main__":
    sys.exit(main())
