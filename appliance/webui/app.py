"""Console web Spambuntu (Flask).

Lancement : gunicorn "app:create_app()" depuis le répertoire webui de la release active.
La console tourne sous un utilisateur non privilégié : elle ne fait que déposer une demande
(apply-request.json) puis démarrer une unité systemd dédiée via sudo. L'installation elle-même
est faite par cette unité, en root, par le moteur de mise à jour.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

RELEASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RELEASE_DIR / "updater"))
sys.path.insert(0, str(RELEASE_DIR / "mail"))
import spambuntu_ai as aicfg  # noqa: E402
import spambuntu_digest as digest  # noqa: E402
import spambuntu_mail as mailcfg  # noqa: E402
import spambuntu_quarantine as quarantine  # noqa: E402
import spambuntu_update as upd  # noqa: E402

try:
    VERSION = (RELEASE_DIR / "VERSION").read_text().strip()
except OSError:
    VERSION = "dev"

REQUEST_TTL = 120      # secondes avant de considérer qu'une demande n'a jamais été prise en charge
LOGIN_WINDOW = 300     # fenêtre de limitation des tentatives de connexion (secondes)
LOGIN_MAX_FAILURES = 8
APPLY_UNIT = "spambuntu-update-apply.service"
ROLLBACK_UNIT = "spambuntu-update-rollback.service"
MAIL_UNIT = "spambuntu-mail-apply.service"
AI_UNIT = "spambuntu-ai-apply.service"
QUARANTINE_BIN = "/usr/local/sbin/spambuntu-quarantine"
STATS_BIN = "/usr/local/sbin/spambuntu-mailstats"
STATS_WINDOWS = {"24": 24, "72": 72, "168": 168}
JOURNAL_CATEGORIES = ("delivered", "tagged", "quarantined", "rejected", "deferred")
JOURNAL_QUERY_RE = re.compile(r"[\w@.+\-:\[\] ]{1,100}")


def start_unit_via_sudo(unit: str):
    """Démarre une unité systemd autorisée par sudoers. Retourne (ok, message)."""
    try:
        r = subprocess.run(["sudo", "-n", "/usr/bin/systemctl", "start", "--no-block", unit],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def run_stats_via_sudo(args: list) -> dict:
    """Appelle le programme root de statistiques (lecture seule du journal de Rspamd). Retourne son JSON."""
    try:
        r = subprocess.run(["sudo", "-n", STATS_BIN, *args], capture_output=True, text=True, timeout=60)
        data = json.loads(r.stdout)
        return data if isinstance(data, dict) else {"ok": False, "error": "Réponse inattendue"}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"ok": False, "error": "Le service de statistiques ne répond pas"}


def chart_bars(summary: dict, width: int = 720, height: int = 140) -> list:
    """Géométrie d'un histogramme empilé (SVG généré côté serveur : la CSP interdit les styles en ligne)."""
    buckets = summary.get("timeline") or []
    if not buckets:
        return []
    peak = max(sum(b.get(c, 0) for c in ("delivered", "tagged", "quarantined", "rejected", "deferred")) for b in buckets) or 1
    slot = width / len(buckets)
    bars = []
    for i, b in enumerate(buckets):
        y = height
        for cat in ("delivered", "tagged", "deferred", "quarantined", "rejected"):
            h = round(b.get(cat, 0) / peak * (height - 4), 2)
            if h <= 0:
                continue
            y = round(y - h, 2)
            bars.append({"x": round(i * slot + 1, 2), "y": y, "w": round(max(slot - 2, 1), 2), "h": h, "cat": cat,
                         "tip": f"{time.strftime('%d/%m %H:%M', time.localtime(b['start']))} · {cat} : {b.get(cat, 0)}"})
    return bars


def run_quarantine_via_sudo(args: list) -> dict:
    """Appelle le programme root de quarantaine (sudoers n'autorise que ses sous-commandes). Retourne son JSON."""
    try:
        r = subprocess.run(["sudo", "-n", QUARANTINE_BIN, *args], capture_output=True, text=True, timeout=60)
        data = json.loads(r.stdout)
        return data if isinstance(data, dict) else {"ok": False, "error": "Réponse inattendue"}
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return {"ok": False, "error": "Le service de quarantaine ne répond pas"}


def parse_ai_form(form) -> dict:
    """Formulaire de l'analyse IA -> demande brute (validation stricte par spambuntu_ai)."""
    def number(name, cast):
        try:
            return cast(form.get(name, "").strip().replace(",", "."))
        except ValueError:
            raise aicfg.AIError(f"Valeur numérique invalide : {name}") from None

    data = {
        "mode": form.get("mode", "off"), "endpoint": (form.get("endpoint") or "").strip(),
        "model_fast": (form.get("model_fast") or "").strip(), "model_deep": (form.get("model_deep") or "").strip(),
        "ambiguous_min": number("ambiguous_min", float), "ambiguous_max": number("ambiguous_max", float),
        "max_add": number("max_add", float), "max_calls_per_hour": number("max_calls_per_hour", int),
        "timeout_s": number("timeout_s", int),
        "internal_domains": [d.strip() for d in (form.get("internal_domains") or "").replace(",", "\n").splitlines() if d.strip()],
        "ca_pem": (form.get("ca_pem") or "").strip(), "token": form.get("token") or "",
        "clear_token": form.get("clear_token") == "on",
    }
    if data["ca_pem"] == "":
        data["ca_file"] = form.get("ca_file", "")
    return data


def parse_mail_form(form) -> dict:
    """Transforme le formulaire en configuration brute (la validation stricte est faite par spambuntu_mail)."""
    domains = []
    for number, line in enumerate((form.get("domains") or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise mailcfg.MailError(f"Ligne {number} : format attendu « domaine.tld serveur[:port] »")
        domains.append({"name": parts[0], "relay": parts[1]})
    networks = [n.strip() for n in (form.get("trusted_networks") or "").replace(",", "\n").splitlines() if n.strip()]
    return {
        "hostname": (form.get("hostname") or "").strip(),
        "domains": domains,
        "thresholds": {"tag": form.get("tag", ""), "quarantine": form.get("quarantine", ""), "reject": form.get("reject", "")},
        "quarantine_enabled": form.get("quarantine_enabled") == "on",
        "verify_recipients": form.get("verify_recipients") == "on",
        "max_message_mb": form.get("max_message_mb", ""),
        "trusted_networks": networks,
        "digest_enabled": form.get("digest_enabled") == "on",
        "digest_from": (form.get("digest_from") or "").strip(),
        "digest_base_url": (form.get("digest_base_url") or "").strip().rstrip("/"),
        "digest_release_max_score": form.get("digest_release_max_score") or "10",
    }


def create_app(conf_path: str | None = None, update_conf: str | None = None) -> Flask:
    app = Flask(__name__)
    conf_path = conf_path or os.environ.get("SPAMBUNTU_WEBUI_CONF", "/etc/spambuntu/webui.json")
    try:
        conf = json.loads(Path(conf_path).read_text(encoding="utf-8"))
        admin_user, password_hash, secret = conf["admin_user"], conf["password_hash"], conf["secret_key"]
    except (OSError, ValueError, KeyError) as exc:
        raise RuntimeError(
            f"Configuration de la console illisible ({conf_path}) : {exc}. "
            "Créez-la avec « spambuntu-passwd --random »."
        ) from exc

    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=bool(conf.get("cookie_secure", False)),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        UPDATE_CONF=update_conf,
        UNIT_STARTER=start_unit_via_sudo,
        QUARANTINE_RUNNER=run_quarantine_via_sudo,
        STATS_RUNNER=run_stats_via_sudo,
        MAIL_CONF=os.environ.get("SPAMBUNTU_MAIL_CONF", "/etc/spambuntu/mail.json"),
        MAIL_STATE=os.environ.get("SPAMBUNTU_MAIL_STATE", "/var/lib/spambuntu/mail"),
        AI_CONF=os.environ.get("SPAMBUNTU_AI_CONF", str(aicfg.CONF_PATH)),
        AI_TOKEN=os.environ.get("SPAMBUNTU_AI_TOKEN", str(aicfg.TOKEN_PATH)),
        AI_STATE=os.environ.get("SPAMBUNTU_AI_STATE", str(aicfg.CONSOLE_DIR)),
    )
    failures: dict = {}

    def cfg() -> upd.Config:
        return upd.Config.load(app.config["UPDATE_CONF"])

    # ------------------------------------------------------------------ sécurité

    def csrf_token() -> str:
        if not session.get("csrf"):
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    @app.before_request
    def protect_against_csrf():
        if request.endpoint in ("digest_release", "user_action"):
            return          # sans session : protégé par le jeton signé du lien
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected = session.get("csrf") or ""
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
                abort(403)

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        if request.path.startswith("/api/") or request.path in ("/login", "/healthz"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.template_filter("timestamp")
    def timestamp_filter(value):
        return time.strftime("%d/%m/%Y %H:%M", time.localtime(int(value))) if value else "?"

    @app.context_processor
    def template_globals():
        return {"csrf_token": csrf_token(), "version": VERSION, "user": session.get("user")}

    def login_required(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("user"):
                if request.path.startswith("/api/"):
                    return jsonify(error="Authentification requise"), 401
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapper

    @app.errorhandler(upd.UpdateError)
    def handle_update_error(exc):
        return jsonify(error=str(exc)), 500

    @app.errorhandler(403)
    def forbidden(_exc):
        if request.path.startswith("/api/"):
            return jsonify(error="Jeton CSRF invalide : rechargez la page"), 403
        return render_template("login.html", error="Session expirée : réessayez."), 403

    # ------------------------------------------------------------------ pages

    @app.get("/healthz")
    def healthz():
        """Sonde utilisée par le moteur de mise à jour après redémarrage."""
        return jsonify(status="ok", version=VERSION)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            ip = request.remote_addr or "?"
            now = time.time()
            recent = [t for t in failures.get(ip, []) if now - t < LOGIN_WINDOW]
            if len(recent) >= LOGIN_MAX_FAILURES:
                return render_template("login.html", error="Trop de tentatives : réessayez dans quelques minutes."), 429
            user_ok = hmac.compare_digest(request.form.get("username", "").encode(), admin_user.encode())
            pass_ok = check_password_hash(password_hash, request.form.get("password", ""))
            if user_ok and pass_ok:
                failures.pop(ip, None)
                session.clear()
                session["user"] = admin_user
                session["csrf"] = secrets.token_hex(16)
                session.permanent = True
                return redirect(url_for("index"))
            if len(failures) > 1000:
                failures.clear()
            failures[ip] = recent + [now]
            return render_template("login.html", error="Identifiant ou mot de passe incorrect."), 401
        return render_template("login.html", error=None)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        stats = app.config["STATS_RUNNER"](["summary", "--hours", "24"])
        return render_template("index.html", active="index", check=upd.read_check(cfg()),
                               stats=stats if stats.get("ok") else None, bars=chart_bars(stats) if stats.get("ok") else [])

    @app.get("/journal")
    @login_required
    def journal_page():
        query = (request.args.get("q") or "").strip()
        category = request.args.get("action", "")
        hours = request.args.get("hours", "24")
        error = None
        if hours not in STATS_WINDOWS:
            hours = "24"
        if category and category not in JOURNAL_CATEGORIES:
            category = ""
        if query and not JOURNAL_QUERY_RE.fullmatch(query):
            error, query = "Recherche invalide : lettres, chiffres et @ . + - : uniquement.", ""
        args = ["search", "--hours", hours, "--limit", "200"]
        if query:
            args += ["--q", query]
        if category:
            args += ["--action", category]
        result = app.config["STATS_RUNNER"](args)
        if not result.get("ok"):
            error = error or result.get("error")
        return render_template("journal.html", active="journal", records=result.get("records", []), error=error,
                               q=query, category=category, hours=hours, categories=JOURNAL_CATEGORIES)

    @app.get("/system/update")
    @login_required
    def update_page():
        return render_template("update.html", active="update")

    # ------------------------------------------------------------------ messagerie

    def flash(kind: str, text: str) -> None:
        session["flash"] = {"kind": kind, "text": text}

    @app.context_processor
    def flash_global():
        return {"flash": session.pop("flash", None)}

    def mail_state_dir() -> Path:
        return Path(app.config["MAIL_STATE"]) / "user"

    @app.get("/messagerie")
    @login_required
    def mail_page():
        try:
            current = mailcfg.load_config(Path(app.config["MAIL_CONF"]))
        except mailcfg.MailError:
            current = mailcfg.validate({})
        status = upd.read_json(mail_state_dir() / "mail-status.json", None)
        pending = (mail_state_dir() / "mail-request.json").exists()
        return render_template("messagerie.html", active="mail", cfg=current, status=status, pending=pending,
                               domains_text="\n".join(f"{d['name']} {d['relay']}" for d in current["domains"]),
                               networks_text="\n".join(current["trusted_networks"]))

    @app.post("/messagerie")
    @login_required
    def mail_save():
        try:
            new = mailcfg.validate(parse_mail_form(request.form))
        except mailcfg.MailError as exc:
            flash("error", f"Configuration refusée : {exc}")
            return redirect(url_for("mail_page"))
        request_file = mail_state_dir() / "mail-request.json"
        upd.write_json_atomic(request_file, new)
        ok, message = app.config["UNIT_STARTER"](MAIL_UNIT)
        if not ok:
            request_file.unlink(missing_ok=True)
            flash("error", f"Impossible d'appliquer la configuration : {message}")
        else:
            flash("success", "Configuration envoyée : application en cours…")
        return redirect(url_for("mail_page"))

    def digest_page(status: int, **ctx):
        response = app.make_response((render_template("digest.html", **ctx), status))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/digest/<token>")
    def digest_confirm(token):
        try:
            _, rcpt = digest.verify_token(secret, token)
        except digest.DigestError as exc:
            return digest_page(400, error=str(exc))
        return digest_page(200, rcpt=rcpt, token=token)

    @app.post("/digest/<token>")
    def digest_release(token):
        try:
            queue_id, rcpt = digest.verify_token(secret, token)
        except digest.DigestError as exc:
            return digest_page(400, error=str(exc))
        try:
            limit = mailcfg.load_config(Path(app.config["MAIL_CONF"]))["digest_release_max_score"]
        except mailcfg.MailError:
            limit = 0
        result = app.config["QUARANTINE_RUNNER"](["release", queue_id, "--actor", "digest", "--recipient", rcpt,
                                                    "--max-score", str(limit)])
        if result.get("ok"):
            return digest_page(200, done=True)
        return digest_page(400, error=result.get("error") or "Échec")

    # ------------------------------------------------------------------ espace utilisateur (lien signé du résumé)

    def user_limit() -> float:
        try:
            return mailcfg.load_config(Path(app.config["MAIL_CONF"]))["digest_release_max_score"]
        except mailcfg.MailError:
            return 0.0

    def user_page(status: int, **ctx):
        response = app.make_response((render_template("espace_utilisateur.html", **ctx), status))
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/mes-messages/<token>")
    def user_messages(token):
        try:
            _, rcpt = digest.verify_token(secret, token, scope="l")
        except digest.DigestError as exc:
            return user_page(400, error=str(exc), messages=[], blocked=0, rcpt="", token="")
        result = app.config["QUARANTINE_RUNNER"](["list", "--recipient", rcpt, "--max-score", str(user_limit())])
        if not result.get("ok"):
            return user_page(502, error="Impossible de lire vos messages pour le moment.", messages=[], blocked=0, rcpt=rcpt, token=token)
        return user_page(200, error=None, messages=result.get("messages", []), blocked=int(result.get("blocked", 0)),
                         rcpt=rcpt, token=token)

    @app.post("/mes-messages/<token>/<action>")
    def user_action(token, action):
        if action not in ("release", "delete"):
            abort(404)
        try:
            _, rcpt = digest.verify_token(secret, token, scope="l")
        except digest.DigestError as exc:
            return user_page(400, error=str(exc), messages=[], blocked=0, rcpt="", token="")
        queue_id = request.form.get("queue_id", "")
        if not quarantine.QUEUE_ID_RE.fullmatch(queue_id):
            flash("error", "Identifiant de message invalide")
            return redirect(url_for("user_messages", token=token))
        args = [action, queue_id, "--actor", "utilisateur", "--recipient", rcpt]
        if action == "release":
            args += ["--max-score", str(user_limit())]
        result = app.config["QUARANTINE_RUNNER"](args)
        flash("success" if result.get("ok") else "error", result.get("message") or result.get("error") or "Échec")
        return redirect(url_for("user_messages", token=token))

    @app.get("/ia")
    @login_required
    def ai_page():
        try:
            current = aicfg.load_config(Path(app.config["AI_CONF"]))
        except aicfg.AIError:
            current = aicfg.validate({})
        state = Path(app.config["AI_STATE"])
        return render_template("ia.html", active="ai", cfg=current, status=upd.read_json(state / "ai-status.json", None),
                               pending=(state / "ai-request.json").exists(),
                               token_set=Path(app.config["AI_TOKEN"]).exists(),
                               ca_set=bool(current["ca_file"]), domains_text="\n".join(current["internal_domains"]))

    @app.post("/ia")
    @login_required
    def ai_save():
        try:
            new = parse_ai_form(request.form)
            check = {k: v for k, v in new.items() if k not in ("token", "clear_token", "ca_pem")}
            if new["ca_pem"]:
                check["ca_file"] = str(aicfg.CA_PATH)
            aicfg.validate(check)
        except aicfg.AIError as exc:
            flash("error", f"Configuration refusée : {exc}")
            return redirect(url_for("ai_page"))
        state = Path(app.config["AI_STATE"])
        request_file = state / "ai-request.json"
        upd.write_json_atomic(request_file, new, mode=0o600)       # peut contenir le jeton
        ok, message = app.config["UNIT_STARTER"](AI_UNIT)
        if not ok:
            request_file.unlink(missing_ok=True)
            flash("error", f"Impossible d'appliquer la configuration : {message}")
        else:
            flash("success", "Configuration envoyée : application et test de connexion en cours…")
        return redirect(url_for("ai_page"))

    @app.get("/quarantaine")
    @login_required
    def quarantine_page():
        view = request.args.get("vue", "risque")
        if view not in ("risque", "ordinaire", "tout"):
            view = "risque"
        result = app.config["QUARANTINE_RUNNER"](["list"])
        if not result.get("ok"):
            return render_template("quarantaine.html", active="quarantine", messages=[], error=result.get("error"),
                                   view=view, counts={"admin": 0, "user": 0})
        everything = result.get("messages", [])
        counts = {"admin": sum(1 for m in everything if m.get("class") != "user"),
                  "user": sum(1 for m in everything if m.get("class") == "user")}
        shown = [m for m in everything if view == "tout" or (view == "risque") == (m.get("class") != "user")]
        shown.sort(key=lambda m: (m.get("class") == "user", -int(m.get("arrived", 0))))
        return render_template("quarantaine.html", active="quarantine", messages=shown, error=None, view=view, counts=counts)

    @app.post("/quarantaine/<action>")
    @login_required
    def quarantine_action(action):
        if action not in ("release", "delete"):
            abort(404)
        queue_id = request.form.get("queue_id", "")
        if not quarantine.QUEUE_ID_RE.fullmatch(queue_id):
            flash("error", "Identifiant de message invalide")
            return redirect(url_for("quarantine_page"))
        args = [action, queue_id, "--actor", session.get("user", "console")]
        if request.form.get("learn") == "1":
            args.append("--learn")
        if action == "release" and request.form.get("confirm") == "on":
            args.append("--confirm-danger")
        result = app.config["QUARANTINE_RUNNER"](args)
        flash("success" if result.get("ok") else "error", result.get("message") or result.get("error") or "Échec")
        return redirect(url_for("quarantine_page"))

    # ------------------------------------------------------------------ API des mises à jour

    def build_status(c: upd.Config) -> dict:
        apply = upd.read_status(c)
        request_file = c.user_dir / "apply-request.json"
        try:
            age = int(time.time() - request_file.stat().st_mtime)
        except OSError:
            age = None
        if age is not None:
            if age <= REQUEST_TTL:
                data = upd.read_json(request_file, {}) or {}
                apply = {"action": "update", "state": "queued", "step": "queued", "percent": 0,
                         "message": "Démarrage de la mise à jour…", "to": data.get("version"),
                         "started_at": None, "finished_at": None}
            else:  # demande jamais consommée : on la retire pour qu'elle ne soit pas exécutée plus tard
                request_file.unlink(missing_ok=True)
                apply = {"action": "update", "state": "failed", "step": "queued", "percent": 0,
                         "message": "Le service de mise à jour ne s'est pas lancé (demande expirée)",
                         "started_at": upd.now_iso(), "finished_at": upd.now_iso()}
        return {
            "running_version": VERSION,
            "current": upd.current_version(c),
            "check": upd.read_check(c),
            "apply": apply,
            "log": upd.log_tail(c, 40),
            "can_rollback": upd.previous_dir(c) is not None,
        }

    def busy(status: dict) -> bool:
        return bool(status["apply"]) and status["apply"].get("state") in ("queued", "running")

    @app.get("/api/update/status")
    @login_required
    def api_status():
        return jsonify(build_status(cfg()))

    @app.post("/api/update/check")
    @login_required
    def api_check():
        c = cfg()
        if busy(build_status(c)):
            return jsonify(error="Une opération est en cours"), 409
        upd.check(c)
        return jsonify(build_status(c))

    @app.post("/api/update/apply")
    @login_required
    def api_apply():
        c = cfg()
        status = build_status(c)
        if busy(status):
            return jsonify(error="Une opération est déjà en cours"), 409
        latest = status["check"].get("latest") or {}
        wanted = (request.get_json(silent=True) or {}).get("version")
        if not status["check"].get("update_available") or wanted != latest.get("version"):
            return jsonify(error="Aucune mise à jour correspondante : relancez la recherche"), 400
        request_file = c.user_dir / "apply-request.json"
        upd.write_json_atomic(request_file, {"version": latest["version"]})
        ok, message = app.config["UNIT_STARTER"](APPLY_UNIT)
        if not ok:
            request_file.unlink(missing_ok=True)
            return jsonify(error=f"Impossible de lancer la mise à jour : {message}"), 500
        return jsonify(ok=True), 202

    @app.post("/api/update/rollback")
    @login_required
    def api_rollback():
        c = cfg()
        status = build_status(c)
        if busy(status):
            return jsonify(error="Une opération est déjà en cours"), 409
        if not status["can_rollback"]:
            return jsonify(error="Aucune version précédente disponible"), 400
        ok, message = app.config["UNIT_STARTER"](ROLLBACK_UNIT)
        if not ok:
            return jsonify(error=f"Impossible de lancer le retour arrière : {message}"), 500
        return jsonify(ok=True), 202

    return app
