import json
import os
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from werkzeug.security import generate_password_hash

import app as webapp
import spambuntu_update as upd

PASSWORD = "correct horse battery"


@pytest.fixture
def web(env, tmp_path):
    conf = tmp_path / "webui.json"
    conf.write_text(json.dumps({"admin_user": "admin", "password_hash": generate_password_hash(PASSWORD),
                                "secret_key": "k" * 32}))
    application = webapp.create_app(str(conf), str(env.write_conf()))
    application.config["TESTING"] = True
    started = []

    def starter(unit):
        started.append(unit)
        return True, ""

    application.config["UNIT_STARTER"] = starter
    return SimpleNamespace(app=application, client=application.test_client(), started=started, env=env)


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([0-9a-f]+)"', html).group(1)


def login(client, password=PASSWORD, user="admin"):
    return client.post("/login", data={"username": user, "password": password, "csrf_token": csrf(client)})


@pytest.fixture
def auth(web):
    assert login(web.client).status_code == 302
    web.token = csrf(web.client, "/")
    web.headers = {"X-CSRF-Token": web.token}
    return web


def post(web, path, body=None):
    return web.client.post(path, json=body, headers=web.headers)


# ------------------------------------------------------------------ accès

def test_healthz_is_public_and_reports_version(web):
    r = web.client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json() == {"status": "ok", "version": webapp.VERSION}


def test_pages_and_api_require_login(web):
    assert web.client.get("/").status_code == 302
    assert "/login" in web.client.get("/system/update").headers["Location"]
    for path in ("/api/update/status",):
        assert web.client.get(path).status_code == 401
    assert web.client.post("/api/update/check").status_code in (401, 403)


def test_login_wrong_password_and_rate_limit(web):
    for _ in range(webapp.LOGIN_MAX_FAILURES):
        assert login(web.client, password="mauvais").status_code == 401
    assert login(web.client, password=PASSWORD).status_code == 429


def test_login_without_csrf_is_forbidden(web):
    web.client.get("/login")
    r = web.client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert r.status_code == 403


def test_session_cookie_flags_and_security_headers(web):
    r = login(web.client)
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    page = web.client.get("/system/update")
    assert "script-src 'self'" in page.headers["Content-Security-Policy"]
    assert page.headers["X-Frame-Options"] == "DENY"
    html = page.get_data(as_text=True)
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "aucun script inline (CSP)"


def test_api_post_requires_csrf_token(auth):
    r = auth.client.post("/api/update/check")
    assert r.status_code == 403
    r = auth.client.post("/api/update/check", headers={"X-CSRF-Token": "faux"})
    assert r.status_code == 403


def test_logout(auth):
    assert auth.client.post("/logout", data={"csrf_token": auth.token}).status_code == 302
    assert auth.client.get("/api/update/status").status_code == 401


def test_missing_config_gives_clear_error(tmp_path):
    with pytest.raises(RuntimeError, match="spambuntu-passwd"):
        webapp.create_app(str(tmp_path / "absent.json"))


# ------------------------------------------------------------------ API des mises à jour

def test_status_shape(auth):
    data = auth.client.get("/api/update/status").get_json()
    assert data["current"] == "0.1.0"
    assert data["check"]["update_available"] is False
    assert data["apply"] is None
    assert data["can_rollback"] is False


def test_check_then_status_shows_update(auth):
    auth.env.publish("0.2.0")
    data = post(auth, "/api/update/check").get_json()
    assert data["check"]["update_available"] is True
    assert data["check"]["latest"]["version"] == "0.2.0"
    assert auth.client.get("/api/update/status").get_json()["check"]["latest"]["version"] == "0.2.0"


def test_check_reports_error_without_failing(auth):
    auth.env.github.fail_releases = True
    data = post(auth, "/api/update/check").get_json()
    assert "HTTP 500" in data["check"]["error"]


def test_apply_requires_prior_check_and_matching_version(auth):
    auth.env.publish("0.2.0")
    assert post(auth, "/api/update/apply", {"version": "0.2.0"}).status_code == 400  # pas encore recherché
    post(auth, "/api/update/check")
    assert post(auth, "/api/update/apply", {"version": "9.9.9"}).status_code == 400
    assert post(auth, "/api/update/apply", {}).status_code == 400
    assert auth.started == []


def test_apply_queues_request_and_starts_unit(auth):
    auth.env.publish("0.2.0")
    post(auth, "/api/update/check")
    r = post(auth, "/api/update/apply", {"version": "0.2.0"})
    assert r.status_code == 202
    assert auth.started == ["spambuntu-update-apply.service"]
    request_file = auth.env.state / "user" / "apply-request.json"
    assert json.loads(request_file.read_text()) == {"version": "0.2.0"}
    status = auth.client.get("/api/update/status").get_json()
    assert status["apply"]["state"] == "queued"
    assert post(auth, "/api/update/apply", {"version": "0.2.0"}).status_code == 409
    assert post(auth, "/api/update/check").status_code == 409
    assert post(auth, "/api/update/rollback").status_code == 409


def test_apply_when_unit_cannot_start(auth):
    auth.env.publish("0.2.0")
    post(auth, "/api/update/check")
    auth.app.config["UNIT_STARTER"] = lambda unit: (False, "sudo: a password is required")
    r = post(auth, "/api/update/apply", {"version": "0.2.0"})
    assert r.status_code == 500 and "sudo" in r.get_json()["error"]
    assert not (auth.env.state / "user" / "apply-request.json").exists()
    assert auth.client.get("/api/update/status").get_json()["apply"] is None


def test_stale_request_is_reported_and_removed(auth):
    request_file = auth.env.state / "user" / "apply-request.json"
    request_file.parent.mkdir(parents=True)
    request_file.write_text(json.dumps({"version": "0.2.0"}))
    old = time.time() - webapp.REQUEST_TTL - 30
    os.utime(request_file, (old, old))
    apply = auth.client.get("/api/update/status").get_json()["apply"]
    assert apply["state"] == "failed" and "expirée" in apply["message"]
    assert not request_file.exists()


def test_full_flow_web_request_consumed_by_real_updater(auth):
    """La demande déposée par la console est celle que le moteur (root) exécute."""
    auth.env.publish("0.2.0")
    post(auth, "/api/update/check")
    assert post(auth, "/api/update/apply", {"version": "0.2.0"}).status_code == 202
    assert auth.env.apply(from_request=True) == 0
    status = auth.client.get("/api/update/status").get_json()
    assert status["current"] == "0.2.0"
    assert status["apply"]["state"] == "success"
    assert status["check"]["update_available"] is False
    assert status["can_rollback"] is True
    assert any("Mise à jour vers la version 0.2.0 terminée" in line for line in status["log"])


def test_rollback_api(auth):
    assert post(auth, "/api/update/rollback").status_code == 400  # rien avant
    auth.env.publish("0.2.0")
    assert auth.env.apply() == 0
    r = post(auth, "/api/update/rollback")
    assert r.status_code == 202
    assert auth.started == ["spambuntu-update-rollback.service"]


def test_update_page_and_dashboard_render(auth):
    auth.env.publish("0.2.0")
    post(auth, "/api/update/check")
    page = auth.client.get("/system/update").get_data(as_text=True)
    assert "Mises à jour" in page and "update.js" in page
    home = auth.client.get("/").get_data(as_text=True)
    assert "0.2.0" in home and "est disponible" in home


def test_console_imports_in_a_clean_release_layout(tmp_path):
    """La console doit démarrer avec le seul sys.path de app.py (sans l'aide de conftest) : régression 0.3.0."""
    import shutil
    import subprocess
    import sys
    rel = tmp_path / "rel"
    shutil.copytree(Path(__file__).resolve().parent.parent / "appliance", rel,
                    ignore=shutil.ignore_patterns("__pycache__"))
    out = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, 'webui'); import app"],
                         cwd=rel, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
