"""Passerelle de messagerie : validation, rendu, application, quarantaine, pages de la console."""
import json
import os
import subprocess
import time
from types import SimpleNamespace

import pytest

import app as webapp
import spambuntu_mail as mail
import spambuntu_quarantine as quar
from test_webui import auth, csrf, web  # noqa: F401  (fixtures)

GOOD = {"domains": [{"name": "Exemple.FR", "relay": "mail.exemple.fr"}]}


# ------------------------------------------------------------------ validation

def test_validate_normalizes():
    cfg = mail.validate(GOOD)
    assert cfg["domains"] == [{"name": "exemple.fr", "relay": "mail.exemple.fr:25"}]
    assert cfg["thresholds"] == {"tag": 5.0, "quarantine": 8.0, "reject": 15.0}


@pytest.mark.parametrize("bad", [
    {"domains": [{"name": "a.fr\n", "relay": "h.fr"}]},                   # saut de ligne final
    {"domains": [{"name": "a.fr\nevil.com OK", "relay": "h.fr"}]},        # injection de ligne dans la table
    {"domains": [{"name": "a.fr OK\nb.fr", "relay": "h.fr"}]},
    {"domains": [{"name": "localhost", "relay": "h.fr"}]},               # pas un nom de domaine complet
    {"domains": [{"name": "a.fr", "relay": "h.fr;reboot"}]},
    {"domains": [{"name": "a.fr", "relay": "h.fr:99999"}]},
    {"domains": [{"name": "a.fr", "relay": "h.fr:abc"}]},
    {"domains": [{"name": "a.fr", "relay": "[::1]:25"}]},
    {"domains": [{"name": "a.fr", "relay": "h.fr"}, {"name": "A.fr", "relay": "h2.fr"}]},   # doublon
    {"domains": [{"name": "a.fr", "relay": "h.fr", "extra": 1}]},
    {"domains": "a.fr"},
    {"hostname": "mx.a.fr\nsmtpd_banner=x"},
    {"hostname": "bad host"},
    {"thresholds": {"tag": 9, "quarantine": 8, "reject": 15}},            # ordre
    {"thresholds": {"tag": 5, "quarantine": 8, "reject": 8}},
    {"thresholds": {"tag": "abc"}},
    {"thresholds": {"tag": True}},
    {"thresholds": {"evil": 1}},
    {"thresholds": [1, 2, 3]},
    {"trusted_networks": ["0.0.0.0/0"]},
    {"trusted_networks": ["::/0"]},
    {"trusted_networks": ["10.0.0.0/8; permit"]},
    {"trusted_networks": "10.0.0.0/8"},
    {"quarantine_enabled": "yes"},
    {"max_message_mb": 0},
    {"max_message_mb": 100000},
    {"inconnu": 1},
    [],
])
def test_validate_rejects(bad):
    with pytest.raises(mail.MailError):
        mail.validate(bad)


def test_validate_domain_limit():
    many = {"domains": [{"name": f"d{i}.fr", "relay": "h.fr"} for i in range(mail.MAX_DOMAINS + 1)]}
    with pytest.raises(mail.MailError):
        mail.validate(many)


def test_rendered_values_never_contain_line_breaks_from_user_input():
    cfg = mail.validate({**GOOD, "hostname": "mx.exemple.fr", "trusted_networks": ["10.1.2.3/8"]})
    plan = mail.render(cfg)
    for key, value in plan["postconf"].items():
        assert "\n" not in value, key
    assert plan["files"]["transport"] == "exemple.fr smtp:[mail.exemple.fr]:25\n"
    assert plan["files"]["relay_domains"] == "exemple.fr OK\n"
    assert plan["postconf"]["mynetworks"] == "127.0.0.0/8, [::1]/128, 10.0.0.0/8"
    assert 'local_addrs = ["10.0.0.0/8"];' in plan["files"]["rspamd-options.inc"]


def test_open_relay_is_never_configured():
    plan = mail.render(mail.validate({}))
    assert plan["files"]["relay_domains"] == "" and plan["postconf"]["mydestination"] == ""
    assert "reject_unauth_destination" in plan["postconf"]["smtpd_relay_restrictions"]
    assert plan["postconf"]["mynetworks"] == "127.0.0.0/8, [::1]/128"
    assert plan["postconf"]["milter_default_action"] == "tempfail"        # Rspamd en panne : on diffère, on ne laisse pas passer


def test_quarantine_can_be_disabled():
    on = mail.render(mail.validate({}))["files"]["rspamd-actions.conf"]
    off = mail.render(mail.validate({"quarantine_enabled": False}))["files"]["rspamd-actions.conf"]
    assert "quarantine = 8.0;" in on and "quarantine" not in off
    assert "reject = 15.0;" in off and "add_header = 5.0;" in off and "greylist = null;" in off


# ------------------------------------------------------------------ application

class FakeRun:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail or {}

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        key = " ".join(cmd[:2])
        rc, err = self.fail.get(key, (0, ""))
        out = "oldvalue\n" if cmd[:2] == ["postconf", "-h"] else ""
        return subprocess.CompletedProcess(cmd, rc, out, err)


def test_apply_writes_files_and_reloads_in_order(tmp_path):
    run = FakeRun()
    mail.Applier(root=tmp_path, run=run).apply(mail.validate(GOOD))
    assert (tmp_path / "etc/postfix/spambuntu/transport").read_text() == "exemple.fr smtp:[mail.exemple.fr]:25\n"
    assert "reject = 15.0;" in (tmp_path / "etc/rspamd/override.d/actions.conf").read_text()
    names = [" ".join(c[:2]) for c in run.calls if c[0] != "postconf" or c[1] == "-e"]
    assert names.index("postconf -e") < names.index("postfix check") < names.index("rspamadm configtest") \
        < names.index("systemctl reload-or-restart")


def test_no_reload_skips_systemctl(tmp_path):
    run = FakeRun()
    mail.Applier(root=tmp_path, run=run, reload=False).apply(mail.validate(GOOD))
    assert not any(c[0] == "systemctl" for c in run.calls)


@pytest.mark.parametrize("failing", ["postfix check", "rspamadm configtest", "postconf -e"])
def test_failed_check_restores_previous_files_and_settings(tmp_path, failing):
    first = mail.Applier(root=tmp_path, run=FakeRun())
    first.apply(mail.validate(GOOD))
    before = (tmp_path / "etc/postfix/spambuntu/transport").read_text()
    run = FakeRun(fail={failing: (1, "boom")})
    with pytest.raises(mail.MailError, match="boom"):
        mail.Applier(root=tmp_path, run=run).apply(mail.validate({"domains": [{"name": "autre.fr", "relay": "x.fr"}]}))
    assert (tmp_path / "etc/postfix/spambuntu/transport").read_text() == before
    restored = [c for c in run.calls if c[:2] == ["postconf", "-e"]]
    assert len(restored) >= 1 and restored[-1][2].startswith("myhostname=") or failing == "postconf -e"
    assert not any(c[0] == "systemctl" for c in run.calls)                       # rien rechargé


def test_first_failed_apply_removes_the_files_it_created(tmp_path):
    with pytest.raises(mail.MailError):
        mail.Applier(root=tmp_path, run=FakeRun(fail={"postfix check": (1, "x")})).apply(mail.validate(GOOD))
    assert not (tmp_path / "etc/postfix/spambuntu/transport").exists()


# ------------------------------------------------------------------ demande de la console

def write_request(state, data, age=0):
    request = state / "user" / "mail-request.json"
    request.parent.mkdir(parents=True, exist_ok=True)
    request.write_text(json.dumps(data))
    if age:
        old = time.time() - age
        os.utime(request, (old, old))
    return request


def run_apply(tmp_path):
    conf, state = tmp_path / "mail.json", tmp_path / "state"
    return conf, state, lambda: mail.cmd_apply(SimpleNamespace(from_request=True), mail.Applier(root=tmp_path / "r", run=FakeRun(), reload=False),
                                              conf, state)


def test_apply_from_request_installs_config_and_reports(tmp_path):
    conf, state, apply = run_apply(tmp_path)
    request = write_request(state, GOOD)
    assert apply() == 0
    assert json.loads(conf.read_text())["domains"][0]["name"] == "exemple.fr"
    assert not request.exists()
    assert json.loads((state / "user" / "mail-status.json").read_text())["ok"] is True


def test_apply_from_request_revalidates_and_keeps_old_config(tmp_path):
    conf, state, apply = run_apply(tmp_path)
    write_request(state, GOOD)
    assert apply() == 0
    good = conf.read_text()
    write_request(state, {"domains": [{"name": "x.fr\nevil.fr OK", "relay": "h.fr"}]})   # un client compromis écrit directement le fichier
    assert apply() == 1
    assert conf.read_text() == good
    status = json.loads((state / "user" / "mail-status.json").read_text())
    assert status["ok"] is False and "invalide" in status["message"]


def test_apply_from_request_refuses_stale_symlink_and_oversized(tmp_path):
    conf, state, apply = run_apply(tmp_path)
    write_request(state, GOOD, age=mail.REQUEST_MAX_AGE + 60)
    assert apply() == 1 and not conf.exists()
    request = state / "user" / "mail-request.json"
    request.unlink()
    target = tmp_path / "secret.json"
    target.write_text(json.dumps(GOOD))
    request.symlink_to(target)
    assert apply() == 1 and not conf.exists()
    request.unlink()
    request.write_text(" " * (300 * 1024))
    assert apply() == 1 and not conf.exists()


def test_apply_from_request_requires_root_without_test_root(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("exécuté en root")
    conf, state = tmp_path / "mail.json", tmp_path / "state"
    write_request(state, GOOD)
    assert mail.cmd_apply(SimpleNamespace(from_request=True), mail.Applier(), conf, state) == 1


# ------------------------------------------------------------------ quarantaine

def postqueue_json(*entries):
    return "\n".join(json.dumps(e) for e in entries)


HEAD = (b"Subject: =?utf-8?B?T2ZmcmUgZXhjZXB0aW9ubmVsbGU=?=\nFrom: Pub <pub@x.test>\n"
        b"X-Spamd-Result: default: True [9.40 / 15.00];\n\tQTEST(9.00)[]; MIME_GOOD(-0.10)[text/plain];\n")


class QueueRun:
    def __init__(self, ids=("AAAAAAAAAA1", "BBBBBBBBBB2")):
        self.calls = []
        self.entries = [{"queue_name": "hold", "queue_id": i, "arrival_time": 1700000000 + n, "message_size": 2048,
                         "sender": "pub@x.test", "recipients": [{"address": "moi@exemple.fr"}]} for n, i in enumerate(ids)]
        self.entries.append({"queue_name": "deferred", "queue_id": "DEFERRED001", "arrival_time": 1, "message_size": 1,
                             "sender": "a@b.c", "recipients": []})

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[:2] == ["postqueue", "-j"]:
            return subprocess.CompletedProcess(cmd, 0, postqueue_json(*self.entries).encode(), b"")
        if cmd[0] == "postcat":
            return subprocess.CompletedProcess(cmd, 0, HEAD, b"")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")


def test_listing_only_returns_held_messages_with_decoded_headers():
    messages = quar.listing(QueueRun())
    assert [m["id"] for m in messages] == ["BBBBBBBBBB2", "AAAAAAAAAA1"]            # plus récent d'abord, pas « deferred »
    first = messages[0]
    assert first["subject"] == "Offre exceptionnelle" and first["score"] == 9.4
    assert first["symbols"] == ["QTEST", "MIME_GOOD"] and first["recipients"] == ["moi@exemple.fr"]


@pytest.mark.parametrize("bad", ["", "../etc/passwd", "AAA;id", "-d", "ALL", "A" * 40, "AAAA AAAA", "AAAAAAAAAA1\n", "é" * 8, "DEFERRED001"])
def test_actions_reject_ids_that_are_not_held_messages(bad, tmp_path):
    run = QueueRun()
    with pytest.raises(quar.QuarantineError):
        quar.act("release", bad, "admin", run, tmp_path / "q.log")
    assert not any(c[0] == "postsuper" for c in run.calls)


def test_release_and_delete_commands_and_audit(tmp_path):
    run, log = QueueRun(), tmp_path / "q.log"
    quar.act("release", "AAAAAAAAAA1", "admin", run, log)
    quar.act("delete", "BBBBBBBBBB2", "admin", run, log)
    assert ["postsuper", "-H", "AAAAAAAAAA1"] in run.calls and ["postqueue", "-i", "AAAAAAAAAA1"] in run.calls
    assert ["postsuper", "-d", "BBBBBBBBBB2", "hold"] in run.calls
    lines = log.read_text().splitlines()
    assert lines[0].endswith("admin release AAAAAAAAAA1 ok") and lines[1].endswith("admin delete BBBBBBBBBB2 ok")


def test_actor_is_validated_and_unknown_action_refused(tmp_path):
    for actor in ("a b", "x;y", "", "é"):
        with pytest.raises(quar.QuarantineError):
            quar.act("release", "AAAAAAAAAA1", actor, QueueRun(), tmp_path / "q.log")
    with pytest.raises(quar.QuarantineError):
        quar.act("flush", "AAAAAAAAAA1", "admin", QueueRun(), tmp_path / "q.log")


def test_failed_postfix_command_is_reported_and_logged(tmp_path):
    class Failing(QueueRun):
        def __call__(self, cmd):
            return subprocess.CompletedProcess(cmd, 1, b"", b"") if cmd[0] == "postsuper" else super().__call__(cmd)
    log = tmp_path / "q.log"
    with pytest.raises(quar.QuarantineError, match="échoué"):
        quar.act("delete", "AAAAAAAAAA1", "admin", Failing(), log)
    assert "échec" in log.read_text()


def test_header_decoding_is_bounded_and_inert():
    assert quar.decode_header("=?utf-8?q?a?=\x00\x1b[31m" + "x" * 500, limit=50).count("\x1b") == 0
    assert len(quar.decode_header("x" * 500, limit=50)) == 50
    assert quar.decode_header("=?bogus-charset?q?abc?=") != ""


# ------------------------------------------------------------------ pages de la console

@pytest.fixture
def mailweb(auth, tmp_path):
    auth.app.config.update(MAIL_CONF=str(tmp_path / "mail.json"), MAIL_STATE=str(tmp_path / "mailstate"))
    (tmp_path / "mailstate" / "user").mkdir(parents=True)
    auth.quarantine_calls = []

    def runner(args):
        auth.quarantine_calls.append(args)
        if args[0] == "list":
            return {"ok": True, "messages": [{
                "id": "AAAAAAAAAA1", "sender": "<script>alert(1)</script>@x.test", "recipients": ["moi@exemple.fr"],
                "size": 2048, "arrived": 1700000000, "subject": "<img src=x onerror=alert(1)>", "from": "", "score": 9.4,
                "symbols": ["QTEST"]}]}
        return {"ok": True, "message": "Message libéré et remis en livraison"}

    auth.app.config["QUARANTINE_RUNNER"] = runner
    auth.mail_dir = tmp_path / "mailstate" / "user"
    return auth


FORM = {"domains": "exemple.fr mail.exemple.fr:25\n# commentaire\n", "tag": "5", "quarantine": "8", "reject": "15",
        "quarantine_enabled": "on", "max_message_mb": "50", "hostname": "", "trusted_networks": "10.0.0.0/24\n"}


def test_pages_require_login(web):
    for path in ("/messagerie", "/quarantaine"):
        assert web.client.get(path).status_code == 302
    for path in ("/messagerie", "/quarantaine/release", "/quarantaine/delete"):
        assert web.client.post(path, data={}).status_code in (302, 403)


def test_mail_page_renders_defaults(mailweb):
    html = mailweb.client.get("/messagerie").get_data(as_text=True)
    assert "Domaines protégés" in html and 'name="quarantine" type="number"' in html


def test_mail_save_writes_validated_request_and_starts_unit(mailweb):
    r = mailweb.client.post("/messagerie", data={**FORM, "csrf_token": mailweb.token})
    assert r.status_code == 302 and mailweb.started == ["spambuntu-mail-apply.service"]
    data = json.loads((mailweb.mail_dir / "mail-request.json").read_text())
    assert data["domains"] == [{"name": "exemple.fr", "relay": "mail.exemple.fr:25"}]
    assert data["trusted_networks"] == ["10.0.0.0/24"]
    assert "application en cours" in mailweb.client.get("/messagerie").get_data(as_text=True)


@pytest.mark.parametrize("override", [
    {"domains": "exemple.fr"},                                     # un seul champ
    {"domains": "exemple.fr a b"},
    {"domains": "a.fr h.fr;reboot"},
    {"tag": "9", "quarantine": "8"},
    {"trusted_networks": "0.0.0.0/0"},
    {"max_message_mb": "abc"},
])
def test_mail_save_refuses_invalid_input_without_touching_anything(mailweb, override):
    r = mailweb.client.post("/messagerie", data={**FORM, **override, "csrf_token": mailweb.token}, follow_redirects=True)
    assert "Configuration refusée" in r.get_data(as_text=True)
    assert not (mailweb.mail_dir / "mail-request.json").exists() and mailweb.started == []


def test_mail_save_requires_csrf(mailweb):
    assert mailweb.client.post("/messagerie", data=FORM).status_code == 403
    assert mailweb.started == []


def test_mail_save_cleans_up_when_the_unit_cannot_start(mailweb):
    mailweb.app.config["UNIT_STARTER"] = lambda unit: (False, "sudo: interdit")
    r = mailweb.client.post("/messagerie", data={**FORM, "csrf_token": mailweb.token}, follow_redirects=True)
    assert "Impossible d&#39;appliquer" in r.get_data(as_text=True)
    assert not (mailweb.mail_dir / "mail-request.json").exists()


def test_quarantine_page_escapes_message_content(mailweb):
    html = mailweb.client.get("/quarantaine").get_data(as_text=True)
    assert "<script>alert(1)" not in html and "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html and "9.4" in html


def test_quarantine_actions_go_through_the_runner_with_the_session_user(mailweb):
    for action in ("release", "delete"):
        r = mailweb.client.post(f"/quarantaine/{action}", data={"queue_id": "AAAAAAAAAA1", "csrf_token": mailweb.token},
                                follow_redirects=True)
        assert "Message libéré" in r.get_data(as_text=True)
    assert [c for c in mailweb.quarantine_calls if c[0] != "list"] == [["release", "AAAAAAAAAA1", "--actor", "admin"],
                                             ["delete", "AAAAAAAAAA1", "--actor", "admin"]]


@pytest.mark.parametrize("bad", ["", "../x", "A;B", "-d", "AAAA AAAA", "x" * 80])
def test_quarantine_actions_never_forward_invalid_ids(mailweb, bad):
    mailweb.client.post("/quarantaine/release", data={"queue_id": bad, "csrf_token": mailweb.token})
    assert not [c for c in mailweb.quarantine_calls if c[0] == "release"]


def test_quarantine_unknown_action_and_csrf(mailweb):
    assert mailweb.client.post("/quarantaine/flush", data={"queue_id": "AAAAAAAAAA1", "csrf_token": mailweb.token}).status_code == 404
    assert mailweb.client.post("/quarantaine/release", data={"queue_id": "AAAAAAAAAA1"}).status_code == 403


def test_quarantine_page_survives_a_broken_backend(mailweb):
    mailweb.app.config["QUARANTINE_RUNNER"] = lambda args: {"ok": False, "error": "Le service de quarantaine ne répond pas"}
    html = mailweb.client.get("/quarantaine").get_data(as_text=True)
    assert "ne répond pas" in html


# ------------------------------------------------------------------ vérification des destinataires et TLS

def test_recipient_verification_is_on_by_default_and_optional():
    on = mail.render(mail.validate({}))["postconf"]["smtpd_recipient_restrictions"]
    off = mail.render(mail.validate({"verify_recipients": False}))["postconf"]["smtpd_recipient_restrictions"]
    assert on.endswith("reject_unverified_recipient") and "reject_unverified_recipient" not in off
    assert on.index("reject_unauth_destination") < on.index("reject_unverified_recipient")     # jamais avant le contrôle de relais
    with pytest.raises(mail.MailError):
        mail.validate({"verify_recipients": "oui"})


def test_inbound_tls_only_when_a_certificate_exists(tmp_path):
    cfg = mail.validate(GOOD)
    assert mail.render(cfg)["postconf"]["smtpd_tls_security_level"] == "none"
    run = FakeRun()
    mail.Applier(root=tmp_path, run=run).apply(cfg)
    assert "smtpd_tls_security_level=none" in " ".join(next(c for c in run.calls if c[:2] == ["postconf", "-e"]))
    tls = tmp_path / "etc/spambuntu/tls"
    tls.mkdir(parents=True)
    (tls / "smtp.crt").write_text("x")
    (tls / "smtp.key").write_text("x")
    run = FakeRun()
    mail.Applier(root=tmp_path, run=run).apply(cfg)
    settings = " ".join(next(c for c in run.calls if c[:2] == ["postconf", "-e"]))
    assert "smtpd_tls_security_level=may" in settings and "smtpd_tls_cert_file=/etc/spambuntu/tls/smtp.crt" in settings
    assert "!TLSv1" in mail.render(cfg, tls=True)["postconf"]["smtpd_tls_protocols"]


def test_tls_certificate_generation_is_private_and_never_overwritten(tmp_path):
    tls = tmp_path / "tls"
    assert mail.ensure_tls_certificate(tls, "mx.exemple.fr") is True
    assert oct((tls / "smtp.key").stat().st_mode & 0o777) == "0o600"
    first = (tls / "smtp.crt").read_bytes()
    assert mail.ensure_tls_certificate(tls, "autre.fr") is True and (tls / "smtp.crt").read_bytes() == first
    out = subprocess.run(["openssl", "x509", "-in", str(tls / "smtp.crt"), "-noout", "-subject"],
                         capture_output=True, text=True).stdout
    assert "mx.exemple.fr" in out
    assert mail.ensure_tls_certificate(tmp_path / "t2", "bad host;x") is True          # nom invalide : repli sur « spambuntu »


# ----------------------------------------------------------------------------- explication IA, apprentissage, libération restreinte

HEAD_AI = (b"Subject: Virement urgent\nFrom: pdg@societe.test\n"
           b"X-Spamd-Result: default: False [14.90 / 15.00];\n\tSPAMBUNTU_AI(1.60)[Fraude au pr\xc3\xa9sident probable];\n"
           b"\tSPAMBUNTU_AI_BEC(0.00)[];\n\tQTEST(9.00)[];\n")


class AIQueueRun(QueueRun):
    def __call__(self, cmd):
        if cmd[0] == "postcat" and cmd[1] == "-qh":
            self.calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, HEAD_AI, b"")
        if cmd[0] == "postcat" and cmd[1] == "-qb":
            self.calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, b"corps du message", b"")
        return super().__call__(cmd)


def test_listing_exposes_ai_explanation_apart_from_symbols():
    m = quar.listing(AIQueueRun())[0]
    assert m["ai"] == "Fraude au président probable" and m["ai_flags"] == ["bec"] and m["symbols"] == ["QTEST"]


def test_release_with_learning_feeds_ham_and_records_feedback(tmp_path):
    fed = []
    quar.act("release", "AAAAAAAAAA1", "admin", AIQueueRun(), tmp_path / "q.log", do_learn=True, confirm_danger=True,
             feedback_file=tmp_path / "fb.jsonl", feed=lambda label, msg: fed.append((label, msg)) or True)
    assert fed[0][0] == "ham" and b"Virement urgent" in fed[0][1] and b"corps du message" in fed[0][1]
    entry = json.loads((tmp_path / "fb.jsonl").read_text())
    assert entry["label"] == "ham" and entry["learned"] and entry["score"] == 14.9 and "body" not in entry


def test_delete_with_learning_feeds_spam(tmp_path):
    fed = []
    quar.act("delete", "AAAAAAAAAA1", "admin", AIQueueRun(), tmp_path / "q.log", do_learn=True,
             feedback_file=tmp_path / "fb.jsonl", feed=lambda label, msg: fed.append(label) or True)
    assert fed == ["spam"]


def test_learning_failure_does_not_block_release(tmp_path):
    run = AIQueueRun()
    quar.act("release", "AAAAAAAAAA1", "admin", run, tmp_path / "q.log", do_learn=True, confirm_danger=True,
             feedback_file=tmp_path / "fb.jsonl", feed=lambda *a: False)
    assert ["postsuper", "-H", "AAAAAAAAAA1"] in run.calls
    assert json.loads((tmp_path / "fb.jsonl").read_text())["learned"] is False


def test_restricted_release_checks_recipient_and_score(tmp_path):
    run = QueueRun()                                      # score 9.4, aucun signal de danger : classe « user »
    with pytest.raises(quar.QuarantineError, match="destiné"):
        quar.act("release", "AAAAAAAAAA1", "digest", run, tmp_path / "q.log", recipient="autre@exemple.fr")
    with pytest.raises(quar.QuarantineError, match="trop suspect"):
        quar.act("release", "AAAAAAAAAA1", "digest", run, tmp_path / "q.log", recipient="moi@exemple.fr", max_score=5)
    assert not any(c[0] == "postsuper" for c in run.calls)
    quar.act("release", "AAAAAAAAAA1", "digest", run, tmp_path / "q.log", recipient="MOI@exemple.fr", max_score=20)
    assert ["postsuper", "-H", "AAAAAAAAAA1"] in run.calls
    assert "(MOI@exemple.fr)" in (tmp_path / "q.log").read_text()


def no_score_run():
    class NoScore(QueueRun):
        def __call__(self, cmd):
            if cmd[0] == "postcat":
                return subprocess.CompletedProcess(cmd, 0, b"Subject: x\n", b"")
            return super().__call__(cmd)
    return NoScore()


def test_unscored_message_is_admin_class_and_refused_to_users(tmp_path):
    with pytest.raises(quar.QuarantineError, match="administrateur"):
        quar.act("release", "AAAAAAAAAA1", "digest", no_score_run(), tmp_path / "q.log", recipient="moi@exemple.fr", max_score=20)


# ----------------------------------------------------------------------------- classes « user » / « admin »

def test_classification():
    assert quar.classify(["QTEST", "MIME_GOOD"], [], 9.4) == ("user", [])
    assert quar.classify([], ["bec", "payment"], 6.0)[0] == "admin"
    assert quar.classify(["CLAM_VIRUS"], [], 6.0) == ("admin", ["Programme malveillant"])
    assert quar.classify(["PHISHED_OPENPHISH"], [], 6.0)[1] == ["Hameçonnage"]
    assert quar.classify(["MIME_BAD_EXTENSION"], [], 6.0)[1] == ["Pièce jointe dangereuse"]
    assert quar.classify(["DMARC_POLICY_REJECT"], [], 6.0)[1] == ["Usurpation de domaine"]
    assert quar.classify([], ["spam"], 9.0)[0] == "user" and quar.classify([], ["other"], 9.0)[0] == "user"
    assert quar.classify([], [], 12.0)[1] == ["Score très élevé"] and quar.classify([], [], None)[1] == ["Analyse impossible"]
    assert quar.classify([], ["phishing", "phishing"], 1.0)[1] == ["Hameçonnage"]            # sans doublon


def test_listing_marks_classes_and_reasons():
    assert quar.listing(QueueRun())[0]["class"] == "user"
    dangerous = quar.listing(AIQueueRun())[0]
    assert dangerous["class"] == "admin" and "Fraude au président ou à la facture" in dangerous["danger"]


def test_user_listing_hides_dangerous_messages_and_details():
    class Mixed(QueueRun):
        def __call__(self, cmd):
            if cmd[0] == "postcat" and cmd[1] == "-qh":
                return subprocess.CompletedProcess(cmd, 0, HEAD_AI if cmd[2] == "BBBBBBBBBB2" else HEAD, b"")
            return super().__call__(cmd)
    view = quar.listing_for_user("MOI@exemple.fr", Mixed())
    assert [m["id"] for m in view["messages"]] == ["AAAAAAAAAA1"] and view["blocked"] == 1
    assert set(view["messages"][0]) == {"id", "from", "subject", "arrived", "size", "single"}      # ni score ni règles
    assert quar.listing_for_user("autre@exemple.fr", Mixed()) == {"messages": [], "blocked": 0}
    with pytest.raises(quar.QuarantineError):
        quar.listing_for_user("pas une adresse", Mixed())


def test_users_cannot_release_or_delete_dangerous_messages(tmp_path):
    run = AIQueueRun()
    for action in ("release", "delete"):
        with pytest.raises(quar.QuarantineError, match="administrateur"):
            quar.act(action, "AAAAAAAAAA1", "digest", run, tmp_path / "q.log", recipient="moi@exemple.fr")
    assert not any(c[0] == "postsuper" for c in run.calls)


def test_admin_must_confirm_release_of_dangerous_message(tmp_path):
    run = AIQueueRun()
    with pytest.raises(quar.QuarantineError, match="confirmez"):
        quar.act("release", "AAAAAAAAAA1", "admin", run, tmp_path / "q.log")
    assert not any(c[0] == "postsuper" for c in run.calls)
    quar.act("release", "AAAAAAAAAA1", "admin", run, tmp_path / "q.log", confirm_danger=True)
    assert ["postsuper", "-H", "AAAAAAAAAA1"] in run.calls
    quar.act("delete", "BBBBBBBBBB2", "admin", AIQueueRun(), tmp_path / "q.log")                # supprimer ne demande rien


def test_user_delete_refused_for_multi_recipient_messages(tmp_path):
    run = QueueRun()
    for e in run.entries:
        e["recipients"] = [{"address": "moi@exemple.fr"}, {"address": "autre@exemple.fr"}]
    with pytest.raises(quar.QuarantineError, match="plusieurs"):
        quar.act("delete", "AAAAAAAAAA1", "digest", run, tmp_path / "q.log", recipient="moi@exemple.fr")
    quar.act("release", "AAAAAAAAAA1", "digest", run, tmp_path / "q.log", recipient="moi@exemple.fr")


def test_user_actions_never_train_the_filter(tmp_path):
    fed = []
    quar.act("release", "AAAAAAAAAA1", "digest", QueueRun(), tmp_path / "q.log", recipient="moi@exemple.fr", do_learn=True,
             feedback_file=tmp_path / "fb.jsonl", feed=lambda *a: fed.append(a) or True)
    assert fed == [] and not (tmp_path / "fb.jsonl").exists()


def test_bad_recipient_is_refused(tmp_path):
    for bad in ("a b@x.test", "x@y.test;id", "<x@y.test>", "x"):
        with pytest.raises(quar.QuarantineError):
            quar.act("release", "AAAAAAAAAA1", "digest", QueueRun(), tmp_path / "q.log", recipient=bad)
