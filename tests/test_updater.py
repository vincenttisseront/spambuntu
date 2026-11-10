import json
import os
import tarfile

import pytest

import spambuntu_update as upd
from conftest import make_bundle


# ------------------------------------------------------------------ versions

def test_version_ordering():
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0", "1.2.0", "1.10.0", "2.0.0"]
    keys = [upd.version_key(v) for v in order]
    assert keys == sorted(keys)
    assert upd.version_key("v1.2.3") == upd.version_key("1.2.3")
    for bad in ("1.2", "latest", "1.2.3.4", "../etc"):
        with pytest.raises(ValueError):
            upd.version_key(bad)


# ------------------------------------------------------------------ configuration

def test_config_rejects_plain_http_api(env):
    with pytest.raises(upd.UpdateError):
        env.cfg(api_base="http://api.example.com")
    with pytest.raises(upd.UpdateError):
        env.cfg(channel="nightly")
    with pytest.raises(upd.UpdateError):
        env.cfg(repo="pas un depot")


def test_health_url_auto_reads_webui_env(env):
    cfg = env.cfg(health_url="auto")
    assert cfg.resolve_health_url() == "http://127.0.0.1:8080/healthz"
    (env.etc / "webui.env").write_text("SPAMBUNTU_BIND=0.0.0.0:9443\n")
    assert env.cfg(health_url="auto").resolve_health_url() == "http://127.0.0.1:9443/healthz"
    assert env.cfg(health_url="none").resolve_health_url() is None


def test_health_url_is_https_when_console_has_a_certificate(env):
    (env.etc / "webui.env").write_text(
        "SPAMBUNTU_BIND=0.0.0.0:8443\n"
        "SPAMBUNTU_TLS_ARGS=--certfile=/etc/spambuntu/tls/console.crt --keyfile=/etc/spambuntu/tls/console.key\n")
    assert env.cfg(health_url="auto").resolve_health_url() == "https://127.0.0.1:8443/healthz"
    (env.etc / "webui.env").write_text("SPAMBUNTU_BIND=0.0.0.0:8443\nSPAMBUNTU_TLS_ARGS=\n")
    assert env.cfg(health_url="auto").resolve_health_url() == "http://127.0.0.1:8443/healthz"


def test_health_check_accepts_the_consoles_self_signed_certificate(env, tmp_path):
    """Contrôle de santé contre un vrai serveur HTTPS à certificat auto-signé (comme la console de l'appliance)."""
    import subprocess
    import threading
    from werkzeug.serving import make_server

    crt, key = tmp_path / "c.crt", tmp_path / "c.key"
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-days", "1", "-subj", "/CN=test", "-keyout", str(key), "-out", str(crt)],
                   check=True, capture_output=True)

    def wsgi(environ, start_response):
        body = json.dumps({"status": "ok", "version": env.current()}).encode()
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    server = make_server("127.0.0.1", 0, wsgi, ssl_context=(str(crt), str(key)))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        cfg = env.cfg(health_url=f"https://127.0.0.1:{server.server_port}/healthz", health_timeout=5)
        progress = upd.Progress(cfg, "test", "0.1.0", "0.1.0")
        upd.wait_healthy(cfg, progress, "0.1.0")                    # ne lève pas
        with pytest.raises(upd.UpdateError):
            upd.wait_healthy(env.cfg(health_url=cfg.health_url, health_timeout=2), progress, "9.9.9")
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------------ détection

def test_check_detects_new_version(env):
    env.publish("0.2.0")
    result = upd.check(env.cfg())
    assert result["error"] is None
    assert result["current"] == "0.1.0"
    assert result["update_available"] is True
    assert result["latest"]["version"] == "0.2.0"
    assert (env.state / "user" / "check.json").exists()


def test_check_up_to_date(env):
    env.publish("0.1.0")
    result = upd.check(env.cfg())
    assert result["update_available"] is False


def test_check_channels(env):
    env.publish("0.2.0-rc.1", prerelease=True)
    assert upd.check(env.cfg(channel="stable"))["update_available"] is False
    beta = upd.check(env.cfg(channel="beta"))
    assert beta["update_available"] is True and beta["latest"]["prerelease"] is True


def test_check_ignores_drafts_and_unsigned_releases(env):
    env.publish("0.3.0", draft=True)
    env.publish("0.4.0", with_sig=False)
    env.publish("0.2.0")
    assert upd.check(env.cfg())["latest"]["version"] == "0.2.0"


def test_check_picks_highest_not_first(env):
    env.publish("0.2.0")
    env.publish("0.10.0")
    env.publish("0.9.0")
    assert upd.check(env.cfg())["latest"]["version"] == "0.10.0"


def test_check_network_error_keeps_last_known_result(env):
    env.publish("0.2.0")
    upd.check(env.cfg())
    env.github.fail_releases = True
    result = upd.check(env.cfg())
    assert "HTTP 500" in result["error"]
    assert result["latest"]["version"] == "0.2.0"
    assert result["update_available"] is True


def test_check_unreachable_server(env):
    result = upd.check(env.cfg(api_base="http://127.0.0.1:1"))
    assert result["error"] and "Connexion impossible" in result["error"]


def test_read_check_recomputes_availability_after_update(env):
    env.publish("0.2.0")
    upd.check(env.cfg())
    assert upd.read_check(env.cfg())["update_available"] is True
    assert env.apply() == 0
    assert upd.read_check(env.cfg())["update_available"] is False


# ------------------------------------------------------------------ mise à jour réussie

def test_apply_success(env):
    env.publish("0.2.0")
    assert env.apply() == 0
    assert env.current() == "0.2.0"
    assert env.previous() == "0.1.0"
    assert env.status()["state"] == "success"
    assert env.status()["percent"] == 100
    assert any("restart spambuntu-webui.service" in c for c in env.systemctl_calls())
    hooks = env.hook_log()
    assert hooks[0].startswith("pre from=0.1.0 to=0.2.0")
    assert hooks[1].startswith("post from=0.1.0 to=0.2.0")
    backups = list(env.backups.glob("config-0.1.0-to-0.2.0-*.tar.gz"))
    assert len(backups) == 1
    assert oct(backups[0].stat().st_mode & 0o777) == "0o600"
    with tarfile.open(backups[0]) as tar:
        assert "etc-spambuntu/settings.txt" in tar.getnames()
    assert not (env.state / "download").exists()
    assert not [d for d in env.release_dirs() if d.startswith(".staging")]


def test_apply_when_already_up_to_date(env):
    env.publish("0.1.0")
    assert env.apply() == 0
    assert "jour" in env.status()["message"]
    assert env.hook_log() == []


def test_apply_requested_version(env):
    env.publish("0.2.0")
    env.publish("0.3.0")
    assert env.apply(requested="0.2.0") == 0
    assert env.current() == "0.2.0"


def test_apply_without_any_release_fails_cleanly(env):
    assert env.apply() == 1
    assert env.status()["state"] == "failed"
    assert env.current() == "0.1.0"


def test_prune_keeps_current_previous_and_limit(env):
    for v in ("0.2.0", "0.3.0", "0.4.0", "0.5.0"):
        env.publish(v)
        assert env.apply() == 0
    dirs = env.release_dirs()
    assert len(dirs) == 3
    assert "0.5.0" in dirs and "0.4.0" in dirs


# ------------------------------------------------------------------ sécurité

def test_bad_signature_is_rejected(env):
    env.publish("0.2.0", signed_with=env.other_priv)
    assert env.apply() == 1
    assert "Signature invalide" in env.status()["message"]
    assert env.current() == "0.1.0"
    assert env.release_dirs() == ["0.1.0"]
    assert env.hook_log() == []


def test_tampered_bundle_is_rejected(env):
    env.publish("0.2.0")
    blob = bytearray(env.github.blobs[0])
    blob[len(blob) // 2] ^= 0xFF
    env.github.blobs[0] = bytes(blob)
    assert env.apply() == 1
    assert env.current() == "0.1.0"


def test_missing_public_key_refuses_update(env):
    env.publish("0.2.0")
    env.pubkey.unlink()
    assert env.apply() == 1
    assert "Clé publique" in env.status()["message"]
    assert env.current() == "0.1.0"


def test_signed_bundle_with_path_traversal_is_rejected(env):
    env.publish("0.2.0", evil_member="../../evil.txt")
    assert env.apply() == 1
    assert "dangereux" in env.status()["message"]
    assert not (env.tmp / "evil.txt").exists()
    assert env.current() == "0.1.0"


def test_signed_bundle_with_escaping_symlink_is_rejected(env):
    env.publish("0.2.0", symlink=("lien", "../../../../etc/passwd"))
    assert env.apply() == 1
    assert env.current() == "0.1.0"


def test_manifest_version_mismatch_is_rejected(env):
    env.publish("0.2.0", manifest_version="0.9.9")
    assert env.apply() == 1
    assert "ne correspond pas" in env.status()["message"]


def test_min_from_version_blocks_big_jumps(env):
    env.publish("0.3.0", min_from="0.2.0")
    assert env.apply() == 1
    assert "exige d'abord la version 0.2.0" in env.status()["message"]
    assert env.current() == "0.1.0"


def test_safe_extract_rejects_hardlinks_and_devices(tmp_path):
    import io
    for kind in (tarfile.LNKTYPE, tarfile.CHRTYPE):
        archive = tmp_path / f"bad-{kind.decode()}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("x/f")
            info.type = kind
            info.linkname = "/etc/passwd"
            tar.addfile(info, io.BytesIO())
        with pytest.raises(upd.UpdateError):
            upd.safe_extract(archive, tmp_path / f"out-{kind.decode()}")


def test_token_is_sent_to_api_but_dropped_on_cross_host_redirect(env):
    env.github.use_redirect = True
    env.publish("0.2.0")
    assert env.apply() == 0  # sans jeton, le téléchargement via redirection fonctionne aussi
    env.github.requests.clear()
    upd_cfg = env.cfg(token="s3cret")
    upd.check(upd_cfg)
    assert upd_cfg.token == "s3cret"
    assert any(path.startswith("/repos/") and auth == "Bearer s3cret" for _, path, auth in env.github.requests)
    # téléchargement : l'appel initial porte le jeton, la cible de la redirection (autre hôte) non
    env.github.requests.clear()
    bundle = env.tmp / "dl.bin"
    upd.download(upd_cfg, env.github.releases_json()[0]["assets"][0]["url"], bundle)
    by_path = {path.split("/")[1]: auth for _, path, auth in env.github.requests}
    assert by_path["redir"] == "Bearer s3cret"
    assert by_path["assets"] is None


def test_token_from_file_and_env(env, monkeypatch):
    tokfile = env.tmp / "token"
    tokfile.write_text("from-file\n")
    assert env.cfg(token_file=tokfile).token == "from-file"
    monkeypatch.setenv("SPAMBUNTU_TOKEN", "from-env")
    assert env.cfg().token == "from-env"


# ------------------------------------------------------------------ retour arrière automatique

def test_rollback_when_health_check_fails(env):
    env.publish("0.2.0")
    env.health.broken_versions = {"0.2.0"}
    assert env.apply() == 1
    st = env.status()
    assert st["state"] == "rolled_back"
    assert env.current() == "0.1.0"
    assert env.previous() is None
    assert env.release_dirs() == ["0.1.0"]
    assert "Retour automatique" in st["message"]
    assert any("rollback=1" in h for h in env.hook_log())


def test_rollback_restores_previous_link(env):
    env.publish("0.2.0")
    assert env.apply() == 0
    env.publish("0.3.0")
    env.health.broken_versions = {"0.3.0"}
    assert env.apply() == 1
    assert env.current() == "0.2.0"
    assert env.previous() == "0.1.0"
    assert "0.3.0" not in env.release_dirs()


def test_rollback_when_post_hook_fails(env, monkeypatch):
    env.publish("0.2.0")
    monkeypatch.setenv("TEST_FAIL_HOOK", "post")
    assert env.apply() == 1
    assert env.status()["state"] == "rolled_back"
    assert env.current() == "0.1.0"
    assert "post-update.sh" in env.status()["message"]


def test_rollback_when_restart_fails(env):
    env.publish("0.2.0")
    (env.tmp / "systemctl.fail").write_text("")
    # le redémarrage échoue aussi pendant le retour arrière (non bloquant), mais l'ancienne version reste active
    assert env.apply() == 1
    assert env.current() == "0.1.0"
    assert env.status()["state"] == "rolled_back"


def test_pre_hook_failure_aborts_before_any_change(env, monkeypatch):
    env.publish("0.2.0")
    monkeypatch.setenv("TEST_FAIL_HOOK", "pre")
    assert env.apply() == 1
    assert env.status()["state"] == "failed"
    assert env.current() == "0.1.0"
    assert env.release_dirs() == ["0.1.0"]
    assert env.previous() is None


# ------------------------------------------------------------------ retour arrière manuel

def test_manual_rollback_swaps_versions(env):
    env.publish("0.2.0")
    assert env.apply() == 0
    assert upd.manual_rollback(env.cfg()) == 0
    assert env.current() == "0.1.0"
    assert env.previous() == "0.2.0"
    assert env.status()["state"] == "success"
    assert upd.manual_rollback(env.cfg()) == 0
    assert env.current() == "0.2.0"


def test_manual_rollback_without_previous(env):
    with pytest.raises(upd.UpdateError):
        upd.manual_rollback(env.cfg())


# ------------------------------------------------------------------ demande de la console web

def test_apply_from_request(env):
    env.publish("0.2.0")
    env.publish("0.3.0")
    req = env.state / "user" / "apply-request.json"
    req.parent.mkdir(parents=True)
    req.write_text(json.dumps({"version": "0.2.0"}))
    assert env.apply(from_request=True) == 0
    assert env.current() == "0.2.0"
    assert not req.exists()


@pytest.mark.parametrize("payload", ['{"version": "../../etc/passwd"}', "pas du json", '{"autre": 1}', '{"version": 5}'])
def test_invalid_request_is_rejected(env, payload):
    env.publish("0.2.0")
    req = env.state / "user" / "apply-request.json"
    req.parent.mkdir(parents=True)
    req.write_text(payload)
    assert env.apply(from_request=True) == 1
    assert env.current() == "0.1.0"
    assert env.status()["state"] == "failed"


def test_request_file_symlink_is_not_followed(env):
    secret = env.tmp / "secret.json"
    secret.write_text(json.dumps({"version": "0.2.0"}))
    env.publish("0.2.0")
    req = env.state / "user" / "apply-request.json"
    req.parent.mkdir(parents=True)
    req.symlink_to(secret)
    assert env.apply(from_request=True) == 1
    assert env.current() == "0.1.0"


# ------------------------------------------------------------------ concurrence et état

def test_concurrent_apply_is_refused(env):
    env.publish("0.2.0")
    lock = upd.acquire_lock(env.cfg())
    try:
        with pytest.raises(upd.UpdateError, match="déjà en cours"):
            env.apply()
        assert upd.main(["--conf", str(env.conf), "apply"]) == 1
    finally:
        lock.close()
    assert env.current() == "0.1.0"


def test_status_of_dead_process_is_reported_as_failed(env):
    env.state.mkdir(parents=True)
    (env.state / "status.json").write_text(json.dumps({"state": "running", "pid": 2**22 + 12345, "message": "x"}))
    st = upd.read_status(env.cfg())
    assert st["state"] == "failed"
    (env.state / "status.json").write_text(json.dumps({"state": "running", "pid": os.getpid()}))
    assert upd.read_status(env.cfg())["state"] == "running"


def test_apply_requires_root(env, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(upd.UpdateError, match="root"):
        upd.apply_update(env.cfg(allow_nonroot="no"))


def test_cli_check_and_version(env, capsys):
    env.publish("0.2.0")
    assert upd.main(["--conf", str(env.write_conf()), "check"]) == 0
    assert "0.1.0 → 0.2.0" in capsys.readouterr().out
    assert upd.main(["--conf", str(env.conf), "version"]) == 0
    assert capsys.readouterr().out.strip() == "0.1.0"
    assert upd.main(["--conf", str(env.conf), "status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["current"] == "0.1.0"
