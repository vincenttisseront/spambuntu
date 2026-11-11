"""Protection d'identité : configuration, rendu des fichiers Rspamd, règles Lua, classification en quarantaine."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import spambuntu_mail as mail
import spambuntu_quarantine as quar

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "appliance" / "mail" / "rspamd" / "identity_lib.lua"
BASE = {"domains": [{"name": "exemple.fr", "relay": "mail.exemple.fr"}]}


# ------------------------------------------------------------------ validation

def test_defaults_enable_identity_and_reject_dmarc():
    cfg = mail.validate({})
    assert cfg["identity_enabled"] is True and cfg["vip"] == [] and cfg["brand_domains"] == []
    assert cfg["dmarc_action"] == "reject"


def test_vip_and_brands_are_normalized():
    cfg = mail.validate({**BASE, "vip": [{"name": "  Jean   Dupont ", "address": "Jean.Dupont@Exemple.FR"},
                                         {"name": "Jean Dupont", "address": "jean.dupont@exemple.fr"}],
                         "brand_domains": ["Banque-Exemple.FR", "banque-exemple.fr"]})
    assert cfg["vip"] == [{"name": "Jean Dupont", "address": "jean.dupont@exemple.fr"}]
    assert cfg["brand_domains"] == ["banque-exemple.fr"]


@pytest.mark.parametrize("bad", [
    {"vip": [{"name": "Jean", "address": "j@exemple.fr"}]},                       # prénom et nom exigés
    {"vip": [{"name": "Jean Dupont", "address": "pas-une-adresse"}]},
    {"vip": [{"name": "Jean \"Dupont\"", "address": "j@exemple.fr"}]},            # guillemets
    {"vip": [{"name": "Jean\nDupont", "address": "j@exemple.fr"}]},
    {"vip": [{"name": "Jean Dupont", "address": "j@exemple.fr", "x": 1}]},
    {"vip": "Jean Dupont"},
    {"vip": [{"name": "Jean Dupont", "address": "j@exemple.fr"}] * 1 + [{"name": f"Nom{i} Prenom", "address": f"a{i}@exemple.fr"} for i in range(201)]},
    {"brand_domains": ["pas un domaine"]},
    {"brand_domains": ["localhost"]},
    {"brand_domains": [123]},
    {"dmarc_action": "drop"},
    {"identity_enabled": "oui"},
])
def test_identity_validation_rejects(bad):
    with pytest.raises(mail.MailError):
        mail.validate({**BASE, **bad})


# ------------------------------------------------------------------ rendu

def test_identity_file_content_and_scores():
    cfg = mail.validate({**BASE, "vip": [{"name": "Jean Dupont", "address": "jean.dupont@exemple.fr"}], "brand_domains": ["banque-exemple.fr"]})
    identity = json.loads(mail.render_identity(cfg)["rspamd-identity.json"])
    assert identity["domains"] == ["exemple.fr"] and identity["vip"][0]["name"] == "Jean Dupont"
    assert "paypal.com" in identity["brands"] and identity["brands"][-1] == "banque-exemple.fr"
    # Une usurpation suspectée atteint la quarantaine, jamais le rejet ; l'indice faible reste sous le marquage.
    assert identity["score_identity"] == cfg["thresholds"]["quarantine"] < cfg["thresholds"]["reject"]
    assert identity["score_brand"] < cfg["thresholds"]["tag"] and identity["score_image"] < cfg["thresholds"]["tag"]


def test_identity_score_never_reaches_reject_even_with_odd_thresholds():
    cfg = mail.validate({**BASE, "thresholds": {"tag": 5, "quarantine": 14.95, "reject": 15}})
    assert json.loads(mail.render_identity(cfg)["rspamd-identity.json"])["score_identity"] < 15


def test_identity_without_quarantine_falls_back_to_tagging():
    cfg = mail.validate({**BASE, "quarantine_enabled": False})
    assert json.loads(mail.render_identity(cfg)["rspamd-identity.json"])["score_identity"] == cfg["thresholds"]["tag"]


def test_disabling_identity_empties_the_rules():
    cfg = mail.validate({**BASE, "identity_enabled": False, "vip": [{"name": "Jean Dupont", "address": "j@exemple.fr"}]})
    identity = json.loads(mail.render_identity(cfg)["rspamd-identity.json"])
    assert identity["enabled"] is False and identity["vip"] == [] and identity["brands"] == []


@pytest.mark.parametrize("action,quarantine,expected", [
    ("reject", True, {"reject": "reject", "quarantine": "quarantine"}),
    ("quarantine", True, {"reject": "quarantine", "quarantine": "quarantine"}),
    ("quarantine", False, {"reject": "add_header", "quarantine": "add_header"}),
    ("score", True, {}),
])
def test_dmarc_actions(action, quarantine, expected):
    cfg = mail.validate({**BASE, "dmarc_action": action, "quarantine_enabled": quarantine})
    text = mail.render_identity(cfg)["rspamd-dmarc.conf"]
    found = dict(line.strip().rstrip(";").replace('"', "").split(" = ") for line in text.splitlines() if line.startswith("  "))
    assert found == expected


def test_apply_writes_identity_and_dmarc_files(tmp_path):
    from test_mail import FakeRun
    mail.Applier(root=tmp_path, run=FakeRun(), reload=False).apply(mail.validate(BASE))
    assert json.loads((tmp_path / "etc/rspamd/local.d/spambuntu-identity.json").read_text())["domains"] == ["exemple.fr"]
    assert "actions" in (tmp_path / "etc/rspamd/local.d/dmarc.conf").read_text()


# ------------------------------------------------------------------ règles Lua (rspamadm lua)

@pytest.mark.skipif(shutil.which("rspamadm") is None, reason="rspamadm absent")
def test_lua_identity_library():
    res = subprocess.run(["rspamadm", "lua", "-s", str(ROOT / "tests" / "lua" / "identity_lib_test.lua")], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=60, env={**os.environ, "IDENTITY_LIB": str(LIB)})
    assert "TOUT EST BON" in res.stdout, res.stdout + res.stderr


# ------------------------------------------------------------------ classification

@pytest.mark.parametrize("symbols,label", [
    (["SPAMBUNTU_VIP_SPOOF"], "Usurpation d'un dirigeant ou d'un nom d'affichage"),
    (["SPOOF_DISPLAY_NAME"], "Usurpation d'un dirigeant ou d'un nom d'affichage"),
    (["SPAMBUNTU_LOOKALIKE"], "Domaine imitateur"),
    (["SPAMBUNTU_IDN_HOMOGLYPH"], "Domaine imitateur"),
])
def test_identity_symbols_make_a_message_admin_only(symbols, label):
    cls, reasons = quar.classify(symbols, [], 8.5)
    assert cls == "admin" and label in reasons


def test_weak_identity_hints_do_not_make_a_message_dangerous():
    assert quar.classify(["SPAMBUNTU_BRAND_IN_DOMAIN", "SPAMBUNTU_IMAGE_ONLY"], [], 6.0) == ("user", [])


# ------------------------------------------------------------------ console

from test_mail import FORM, mailweb  # noqa: E402,F401  (fixture)
from test_webui import auth, web  # noqa: E402,F401  (fixtures)


def test_form_saves_vip_brands_and_dmarc_action(mailweb):
    data = {**FORM, "identity_enabled": "on", "vip": "Jean Dupont ; Jean.Dupont@exemple.fr\n# commentaire\n",
            "brand_domains": "banque-exemple.fr, autre-marque.com", "dmarc_action": "quarantine", "csrf_token": mailweb.token}
    assert mailweb.client.post("/messagerie", data=data).status_code == 302
    saved = json.loads((mailweb.mail_dir / "mail-request.json").read_text())
    assert saved["vip"] == [{"name": "Jean Dupont", "address": "jean.dupont@exemple.fr"}]
    assert saved["brand_domains"] == ["banque-exemple.fr", "autre-marque.com"] and saved["dmarc_action"] == "quarantine"
    assert saved["identity_enabled"] is True


@pytest.mark.parametrize("override", [
    {"vip": "Jean Dupont jean@exemple.fr"},          # séparateur manquant
    {"vip": "Jean ; jean@exemple.fr"},                # nom incomplet
    {"brand_domains": "pas un domaine"},
    {"dmarc_action": "drop"},
])
def test_form_refuses_invalid_identity_settings(mailweb, override):
    r = mailweb.client.post("/messagerie", data={**FORM, **override, "csrf_token": mailweb.token}, follow_redirects=True)
    assert "Configuration refusée" in r.get_data(as_text=True)
    assert not (mailweb.mail_dir / "mail-request.json").exists()


def test_page_shows_identity_section_with_saved_values(mailweb):
    mailweb.client.post("/messagerie", data={**FORM, "vip": "Jean Dupont ; j@exemple.fr", "csrf_token": mailweb.token})
    cfg = mail.validate({"vip": [{"name": "Jean Dupont", "address": "j@exemple.fr"}], "domains": [{"name": "exemple.fr", "relay": "m.exemple.fr"}]})
    Path(mailweb.app.config["MAIL_CONF"]).write_text(json.dumps(cfg))
    html = mailweb.client.get("/messagerie").get_data(as_text=True)
    assert "Protection contre l'usurpation" in html and "Jean Dupont ; j@exemple.fr" in html
