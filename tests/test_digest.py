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
         "from": "Pub <pub@x.test>", "score": score, "symbols": ["QTEST"], "ai": "", "ai_flags": [], "class": "user", "danger": []}
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
    items = [item("AAAAAAAAAA1", score=5.0), item("BBBBBBBBBB2", score=11.0, subject="Fraude")]
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


# ----------------------------------------------------------------------------- espace utilisateur et vue administrateur

@pytest.fixture
def portal(mailweb):
    mailweb.calls = []

    def runner(args):
        mailweb.calls.append(args)
        if args[0] == "list" and "--recipient" in args:
            return {"ok": True, "blocked": 2, "messages": [
                {"id": "AAAAAAAAAA1", "from": "<b>Pub</b> <pub@x.test>", "subject": "<img src=x onerror=alert(1)>",
                 "arrived": 1700000000, "size": 100, "single": True},
                {"id": "BBBBBBBBBB2", "from": "Autre <a@x.test>", "subject": "Promo", "arrived": 1700000100, "size": 100, "single": False}]}
        if args[0] == "list":
            return {"ok": True, "messages": [
                {"id": "AAAAAAAAAA1", "class": "user", "danger": [], "sender": "pub@x.test", "from": "Pub", "recipients": ["moi@exemple.fr"],
                 "size": 2048, "arrived": 1700000000, "subject": "Promo", "score": 6.0, "symbols": ["QTEST"], "ai": "", "ai_flags": []},
                {"id": "CCCCCCCCCC3", "class": "admin", "danger": ["Hameçonnage", "Demande de paiement"], "sender": "pdg@evil.test", "from": "PDG",
                 "recipients": ["moi@exemple.fr"], "size": 1024, "arrived": 1700000500, "subject": "Virement urgent", "score": 14.0,
                 "symbols": ["PHISHED"], "ai": "Fraude au président probable", "ai_flags": ["bec"]}]}
        return {"ok": True, "message": "Message libéré et remis en livraison"}

    mailweb.app.config["QUARANTINE_RUNNER"] = runner
    mailweb.token = lambda scope="l", qid="-": dg.make_token(mailweb.app.config["SECRET_KEY"], qid, "moi@exemple.fr", scope=scope)
    return mailweb


def test_user_space_lists_messages_escaped_without_technical_details(portal):
    client = portal.app.test_client()
    page = client.get(f"/mes-messages/{portal.token()}")
    html = page.get_data(as_text=True)
    assert page.status_code == 200 and "moi@exemple.fr" in html and "2 message(s) ont été bloqués" in html
    assert "<img src=x" not in html and "&lt;img src=x" in html
    assert "score" not in html.lower() and "Hameçonnage" not in html
    assert html.count("Libérer ce message") == 2 and html.count(">Supprimer<") == 1       # pas de suppression si plusieurs destinataires
    assert portal.calls[0][:3] == ["list", "--recipient", "moi@exemple.fr"] and "--max-score" in portal.calls[0]
    assert "no-store" in page.headers["Cache-Control"]


def test_user_space_needs_a_valid_list_token(portal):
    client = portal.app.test_client()
    release_token = portal.token("r", "AAAAAAAAAA1")
    assert client.get(f"/mes-messages/{release_token}").status_code == 400          # un jeton de libération n'ouvre pas la liste
    assert client.get("/mes-messages/forge").status_code == 400
    assert client.post(f"/mes-messages/{release_token}/release", data={"queue_id": "AAAAAAAAAA1"}).status_code == 400
    assert not [c for c in portal.calls if c[0] in ("release", "delete")]
    assert client.get(f"/digest/{portal.token()}").status_code == 400                # et réciproquement


def test_user_actions_are_scoped_to_the_token_recipient(portal):
    client = portal.app.test_client()
    token = portal.token()
    res = client.post(f"/mes-messages/{token}/release", data={"queue_id": "AAAAAAAAAA1"})
    assert res.status_code == 302
    assert portal.calls[-1][:6] == ["release", "AAAAAAAAAA1", "--actor", "utilisateur", "--recipient", "moi@exemple.fr"]
    assert "--max-score" in portal.calls[-1] and "--confirm-danger" not in portal.calls[-1]
    client.post(f"/mes-messages/{token}/delete", data={"queue_id": "AAAAAAAAAA1"})
    assert portal.calls[-1][:6] == ["delete", "AAAAAAAAAA1", "--actor", "utilisateur", "--recipient", "moi@exemple.fr"]
    assert client.post(f"/mes-messages/{token}/format", data={"queue_id": "AAAAAAAAAA1"}).status_code == 404
    before = len(portal.calls)
    client.post(f"/mes-messages/{token}/release", data={"queue_id": "x;y --confirm-danger"})
    assert len(portal.calls) == before


def test_admin_view_separates_risk_from_ordinary(portal):
    risk = portal.client.get("/quarantaine").get_data(as_text=True)
    assert "Virement urgent" in risk and "Hameçonnage" in risk and "Promo" not in risk
    assert "Libérer après analyse" in risk and 'name="confirm" required' in risk and "Légitime : libérer" not in risk
    ordinary = portal.client.get("/quarantaine?vue=ordinaire").get_data(as_text=True)
    assert "Promo" in ordinary and "Virement urgent" not in ordinary and "Légitime : libérer" in ordinary
    everything = portal.client.get("/quarantaine?vue=tout").get_data(as_text=True)
    assert everything.index("Virement urgent") < everything.index("Promo")                 # le risque d'abord
    assert "Virement urgent" in portal.client.get("/quarantaine?vue=nimportequoi").get_data(as_text=True)       # vue inconnue : repli sur « à examiner »


def test_admin_release_of_risky_message_forwards_confirmation(portal):
    token = csrf(portal.client, "/quarantaine")
    portal.client.post("/quarantaine/release", data={"queue_id": "CCCCCCCCCC3", "learn": "0", "csrf_token": token})
    assert "--confirm-danger" not in portal.calls[-1]
    portal.client.post("/quarantaine/release", data={"queue_id": "CCCCCCCCCC3", "learn": "0", "confirm": "on", "csrf_token": token})
    assert "--confirm-danger" in portal.calls[-1]


def test_digest_never_details_risky_messages(tmp_path):
    sent = []
    risky = item("CCCCCCCCCC3", subject="Virement urgent", **{"class": "admin", "danger": ["Hameçonnage"]})
    dg.run_digest(cfg(), [item("AAAAAAAAAA1"), risky], SECRET, sender=lambda m: sent.append(m) or True, now=NOW, state_file=tmp_path / "s.json")
    text = sent[0].get_content()
    assert "Virement urgent" not in text and "1 autre(s) message(s) ont été bloqués" in text and "/mes-messages/" in text
    link = text.split("/mes-messages/")[1].split()[0]
    assert dg.verify_token(SECRET, link, NOW, scope="l") == ("-", "moi@exemple.fr")
    only_risky = []
    dg.run_digest(cfg(), [risky], SECRET, sender=lambda m: only_risky.append(m) or True, now=NOW, state_file=tmp_path / "s2.json")
    assert only_risky == []                                                         # rien à gérer : pas de résumé
