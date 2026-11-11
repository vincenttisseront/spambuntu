"""Résumé quotidien de quarantaine : jetons signés, composition, envoi, page de libération."""
import json

import pytest

import spambuntu_digest as dg
import spambuntu_mail as mail
from test_mail import mailweb  # noqa: F401  (fixture)
from test_webui import auth, csrf, web  # noqa: F401  (fixtures)

SECRET = "console-secret"
NOW = 1_800_000_000


def cfg(**kw):
    base = {"domains": [{"name": "exemple.fr", "relay": "mail.exemple.fr:25"}], "digest_enabled": True,
            "digest_base_url": "https://gw.exemple.fr:8443", "hostname": "gw.exemple.fr"}
    base.update(kw)
    return mail.validate(base)


def item(i="AAAAAAAAAA1", rcpts=("moi@exemple.fr",), score=9.0, arrived=NOW - 3600, **kw):
    d = {"id": i, "sender": "pub@x.test", "recipients": list(rcpts), "size": 100, "arrived": arrived, "subject": "Offre",
         "from": "Pub <pub@x.test>", "score": score, "symbols": ["QTEST"], "ai": "", "ai_flags": []}
    d.update(kw)
    return d


def test_token_roundtrip_and_tampering():
    token = dg.make_token(SECRET, "AAAAAAAAAA1", "moi@exemple.fr", NOW)
    assert dg.verify_token(SECRET, token, NOW + 10) == ("AAAAAAAAAA1", "moi@exemple.fr")
    payload, sig = token.split(".")
    for bad in (token + "x", payload + "." + sig[::-1], "x." + sig, "", "pas-un-jeton", token.replace(".", "..")):
        with pytest.raises(dg.DigestError):
            dg.verify_token(SECRET, bad, NOW)
    with pytest.raises(dg.DigestError):
        dg.verify_token("autre-secret", token, NOW)


def test_token_expires():
    token = dg.make_token(SECRET, "AAAAAAAAAA1", "moi@exemple.fr", NOW)
    dg.verify_token(SECRET, token, NOW + dg.TOKEN_TTL - 5)
    with pytest.raises(dg.DigestError, match="expiré"):
        dg.verify_token(SECRET, token, NOW + dg.TOKEN_TTL + 5)


def test_token_cannot_be_forged_for_another_message():
    token = dg.make_token(SECRET, "AAAAAAAAAA1", "moi@exemple.fr", NOW)
    forged = dg._b64(f"BBBBBBBBBB2|moi@exemple.fr|{NOW + 99999}".encode()) + "." + token.split(".")[1]
    with pytest.raises(dg.DigestError):
        dg.verify_token(SECRET, forged, NOW)


def test_each_recipient_gets_only_their_messages(tmp_path):
    sent = []
    items = [item("AAAAAAAAAA1", ("a@exemple.fr",)), item("BBBBBBBBBB2", ("b@exemple.fr", "a@exemple.fr")),
             item("CCCCCCCCCC3", ("ext@autre.test",))]
    report = dg.run_digest(cfg(), items, SECRET, sender=lambda m: sent.append(m) or True, now=NOW, state_file=tmp_path / "s.json")
    by_rcpt = {m["To"]: m.get_content() for m in sent}
    assert set(by_rcpt) == {"a@exemple.fr", "b@exemple.fr"}                     # pas de domaine non déclaré
    assert by_rcpt["b@exemple.fr"].count("Objet :") == 1 and by_rcpt["a@exemple.fr"].count("Objet :") == 2
    assert report["recipients"] == 2 and report["failed"] == 0


def test_links_only_for_releasable_scores(tmp_path):
    sent = []
    items = [item("AAAAAAAAAA1", score=5.0), item("BBBBBBBBBB2", score=14.0, subject="Fraude")]
    dg.run_digest(cfg(), items, SECRET, sender=lambda m: sent.append(m) or True, now=NOW, state_file=tmp_path / "s.json")
    text = sent[0].get_content()
    assert text.count("https://gw.exemple.fr:8443/digest/") == 1
    link = text.split("https://gw.exemple.fr:8443/digest/")[1].split()[0]
    assert dg.verify_token(SECRET, link, NOW) == ("AAAAAAAAAA1", "moi@exemple.fr")


def test_no_links_without_base_url(tmp_path):
    sent = []
    dg.run_digest(cfg(digest_base_url=""), [item()], SECRET, sender=lambda m: sent.append(m) or True, now=NOW, state_file=tmp_path / "s.json")
    assert "/digest/" not in sent[0].get_content()


def test_no_duplicates_across_runs_and_old_messages_skipped(tmp_path):
    sent, state = [], tmp_path / "s.json"
    items = [item("AAAAAAAAAA1"), item("OLDOLDOLD01", arrived=NOW - 40 * 3600)]
    sender = lambda m: sent.append(m) or True  # noqa: E731
    dg.run_digest(cfg(), items, SECRET, sender=sender, now=NOW, state_file=state)
    dg.run_digest(cfg(), items, SECRET, sender=sender, now=NOW + 600, state_file=state)
    assert len(sent) == 1 and "OLDOLDOLD01" not in json.loads(state.read_text())["sent"]
    dg.run_digest(cfg(), items + [item("DDDDDDDDDD4")], SECRET, sender=sender, now=NOW + 1200, state_file=state)
    assert len(sent) == 2 and sent[1].get_content().count("Objet :") == 1


def test_failed_send_is_retried_next_run(tmp_path):
    state = tmp_path / "s.json"
    report = dg.run_digest(cfg(), [item()], SECRET, sender=lambda m: False, now=NOW, state_file=state)
    assert report["failed"] == 1
    sent = []
    dg.run_digest(cfg(), [item()], SECRET, sender=lambda m: sent.append(m) or True, now=NOW + 60, state_file=state)
    assert len(sent) == 1


def test_content_is_sanitized_and_headers_safe(tmp_path):
    sent = []
    evil = item(subject="Offre\r\nBcc: victime@x.test‮", sender="a@b.test\nX: y")
    dg.run_digest(cfg(), [evil], SECRET, sender=lambda m: sent.append(m) or True, now=NOW, state_file=tmp_path / "s.json")
    raw = sent[0].as_string()
    assert "\nBcc:" not in raw and "‮" not in raw
    assert sent[0]["From"] == "quarantaine@gw.exemple.fr" and sent[0]["Auto-Submitted"] == "auto-generated"


def test_explanation_used_when_available(tmp_path):
    sent = []
    dg.run_digest(cfg(), [item(ai="Fraude au président probable")], SECRET, sender=lambda m: sent.append(m) or True, now=NOW, state_file=tmp_path / "s.json")
    assert "Analyse : Fraude au président probable" in sent[0].get_content()


@pytest.mark.parametrize("bad", [{"digest_from": "pas une adresse"}, {"digest_base_url": "http://clair.test"},
                                 {"digest_base_url": "https://x.test/chemin"}, {"digest_base_url": "https://x.test:99999"},
                                 {"digest_release_max_score": 500}, {"digest_enabled": "oui"}])
def test_config_validation(bad):
    with pytest.raises(mail.MailError):
        cfg(**bad)


# ----------------------------------------------------------------------------- console

@pytest.fixture
def digestweb(mailweb):
    mailweb.releases = []

    def runner(args):
        mailweb.releases.append(args)
        return {"ok": True, "message": "Message libéré"} if args[1] == "AAAAAAAAAA1" else {"ok": False, "error": "Ce message n'est plus en quarantaine"}

    mailweb.app.config["QUARANTINE_RUNNER"] = runner
    return mailweb


def secret_of(client_app):
    return client_app.config["SECRET_KEY"]


def test_release_page_needs_no_login_but_valid_token(digestweb):
    client = digestweb.app.test_client()
    token = dg.make_token(secret_of(digestweb.app), "AAAAAAAAAA1", "moi@exemple.fr")
    page = client.get(f"/digest/{token}")
    assert page.status_code == 200 and b"moi@exemple.fr" in page.data and page.headers["Cache-Control"] == "no-store"
    assert digestweb.releases == []                                          # un simple GET ne libère rien (aperçus de liens)
    assert client.get("/digest/n-importe-quoi").status_code == 400


def test_release_by_link_is_restricted(digestweb):
    client = digestweb.app.test_client()
    token = dg.make_token(secret_of(digestweb.app), "AAAAAAAAAA1", "moi@exemple.fr")
    res = client.post(f"/digest/{token}")                                    # sans CSRF ni session : le jeton fait foi
    assert res.status_code == 200 and "libéré".encode() in res.data
    assert digestweb.releases == [["release", "AAAAAAAAAA1", "--actor", "digest", "--recipient", "moi@exemple.fr", "--max-score", "10.0"]]


def test_release_by_link_reports_errors_and_rejects_forgery(digestweb):
    client = digestweb.app.test_client()
    gone = dg.make_token(secret_of(digestweb.app), "BBBBBBBBBB2", "moi@exemple.fr")
    assert client.post(f"/digest/{gone}").status_code == 400
    forged = dg.make_token("autre-secret", "AAAAAAAAAA1", "moi@exemple.fr")
    before = len(digestweb.releases)
    assert client.post(f"/digest/{forged}").status_code == 400 and len(digestweb.releases) == before
    expired = dg.make_token(secret_of(digestweb.app), "AAAAAAAAAA1", "moi@exemple.fr", now=1000)
    assert client.post(f"/digest/{expired}").status_code == 400 and len(digestweb.releases) == before


def test_other_posts_still_need_csrf(web):
    assert web.client.post("/logout").status_code == 403
