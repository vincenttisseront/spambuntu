"""Règles de filtrage : modèle, moteur Python (et son équivalent Lua), configuration Rspamd, pages de la console."""
import copy
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import spambuntu_mail as mail
import spambuntu_rules as rules

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "data" / "rules_golden.json"
LIB = ROOT / "appliance" / "mail" / "rspamd" / "rules_lib.lua"
BASE = {"domains": [{"name": "exemple.fr", "relay": "mail.exemple.fr"}]}


def default():
    return rules.default_rules()


def ids(items):
    return [r["id"] for r in items]


def cond(field, op, value):
    return {"field": field, "op": op, "value": value}


def custom(rule_id="inbound_test", **over):
    return {"id": rule_id, "enabled": True, "description": "Règle de test", "match": "all", "conditions": [cond("spam", ">=", 60)],
            "disposition": "quarantine", "folder": "Test", "user_access": False, "headers": [], "explain": True, **over}


# ------------------------------------------------------------------ règles par défaut

def test_default_rules_mirror_the_reference_layout():
    items = default()
    assert ids(items) == ["inbound_blocked", "inbound_malware", "inbound_impostor", "inbound_phish", "inbound_safe", "inbound_dmarc",
                          "inbound_spam_definite", "inbound_spam", "inbound_junk", "inbound_bulk", "inbound_lowpriority", "inbound_notspam"]
    assert items[-1]["id"] == rules.LAST_RULE and items[-1]["enabled"]
    assert rules.validate_rules(items) == items                      # les valeurs par défaut sont déjà normalisées


def test_dangerous_defaults_are_reserved_to_the_administrator():
    by_id = {r["id"]: r for r in default()}
    for rule_id in ("inbound_malware", "inbound_impostor", "inbound_phish"):
        assert by_id[rule_id]["disposition"] == "quarantine" and by_id[rule_id]["user_access"] is False
    assert by_id["inbound_spam"]["user_access"] is True               # le spam ordinaire reste géré par l'utilisateur
    assert by_id["inbound_safe"]["disposition"] == "deliver" and by_id["inbound_blocked"]["disposition"] == "reject"


def test_legacy_dmarc_values_initialize_the_dmarc_rule():
    reject = next(r for r in rules.default_rules("reject") if r["id"] == "inbound_dmarc")
    quarantine = next(r for r in rules.default_rules("quarantine") if r["id"] == "inbound_dmarc")
    score = next(r for r in rules.default_rules("score") if r["id"] == "inbound_dmarc")
    assert reject["disposition"] == "reject" and reject["enabled"]
    assert quarantine["disposition"] == "quarantine" and quarantine["user_access"] is False and quarantine["folder"]
    assert score["enabled"] is False


# ------------------------------------------------------------------ validation d'une règle

@pytest.mark.parametrize("over", [
    {"id": "Mauvais Id"}, {"id": "ab"}, {"id": "1abc"}, {"id": "x" * 41}, {"id": "a-b-c"},
    {"description": ""}, {"description": "x" * 81}, {"description": "<b>gras</b>"}, {"description": "ligne\nbrisée"},
    {"match": "none"}, {"disposition": "discard"}, {"disposition": "drop"}, {"enabled": "oui"}, {"explain": 1},
    {"conditions": []}, {"conditions": [cond("spam", ">=", 1)] * 7}, {"conditions": "spam"},
    {"conditions": [cond("inconnu", ">=", 1)]}, {"conditions": [cond("spam", "contains", 1)]},
    {"conditions": [cond("spam", ">=", 101)]}, {"conditions": [cond("spam", ">=", -1)]}, {"conditions": [cond("spam", ">=", "beaucoup")]},
    {"conditions": [cond("spam", ">=", True)]},
    {"conditions": [cond("blocklist", "is", "oui")]}, {"conditions": [cond("symbol", "present", "deux mots")]},
    {"conditions": [cond("symbol", "present", "X; DROP")]}, {"conditions": [cond("sender", "contains", "")]},
    {"conditions": [cond("sender", "contains", "a" * 121)]}, {"conditions": [cond("sender", "contains", "a\nb")]},
    {"conditions": [{"field": "spam", "op": ">=", "value": 1, "x": 1}]},
    {"folder": ""}, {"folder": "<script>"}, {"folder": "a" * 41}, {"folder": "../etc"}, {"folder": "a\nb"},
    {"headers": [{"name": "Subject", "value": "x"}]}, {"headers": [{"name": "X-Spam", "value": "No"}]},
    {"headers": [{"name": "x-spambuntu-rule", "value": "a"}]}, {"headers": [{"name": "X-A", "value": "ligne\nbrisée"}]},
    {"headers": [{"name": "X-A", "value": ""}]}, {"headers": [{"name": "X-A", "value": "é"}]},
    {"headers": [{"name": "X-A", "value": "1"}, {"name": "x-a", "value": "2"}]},
    {"headers": [{"name": f"X-A{i}", "value": "1"} for i in range(4)]},
    {"headers": [{"name": "X-A", "value": "1", "z": 1}]},
    {"inconnu": 1},
])
def test_rule_validation_rejects(over):
    with pytest.raises(rules.RulesError):
        rules.validate_rule(custom(**over))


def test_rule_normalization():
    rule = rules.validate_rule(custom(description="  Un   test  ", folder="  Mon   dossier ", conditions=[
        cond("sender", "ends_with", "  PayPal.COM "), cond("symbol", "present", " mime_bad_extension "), cond("spam", ">=", "60,5")]))
    assert rule["description"] == "Un test" and rule["folder"] == "Mon dossier"
    assert rule["conditions"] == [cond("sender", "ends_with", "paypal.com"), cond("symbol", "present", "MIME_BAD_EXTENSION"), cond("spam", ">=", 60.5)]


def test_folder_is_dropped_unless_quarantine():
    rule = rules.validate_rule(custom(disposition="reject", folder="Reste", user_access=True))
    assert rule["folder"] == "" and rule["user_access"] is False


def test_folder_ids_are_ascii_and_stable():
    assert rules.folder_id("Hameçonnage") == "hameconnage"
    assert rules.folder_id("Courrier en masse") == "courrier_en_masse"
    assert rules.folder_id("---") == "dossier"
    assert rules.folder_id("Usurpation d'identité") == "usurpation_d_identite"


# ------------------------------------------------------------------ liste ordonnée

def test_notspam_is_always_last_active_and_unconditional():
    items = default()
    items.insert(0, items.pop())                                      # placée en tête par erreur
    items[0].update(enabled=False, disposition="deliver", conditions=[cond("spam", ">=", 99)])
    fixed = rules.validate_rules(items)
    assert fixed[-1]["id"] == rules.LAST_RULE and fixed[-1]["enabled"]
    assert fixed[-1]["conditions"] == rules.LOCKED_CONDITIONS[rules.LAST_RULE]


def test_locked_conditions_cannot_be_rewritten():
    items = default()
    items[0]["conditions"] = [cond("spam", ">=", 0)]                  # « tout est bloqué » : refusé
    items[0]["match"] = "any"
    fixed = rules.validate_rules(items)
    assert fixed[0]["conditions"] == rules.LOCKED_CONDITIONS["inbound_blocked"] and fixed[0]["match"] == "all"


def test_locked_rules_keep_a_sensible_action():
    items = default()
    items[0]["disposition"] = "deliver"                               # liste de blocage qui livre : refusé
    with pytest.raises(rules.RulesError):
        rules.validate_rules(items)
    items = default()
    items[4]["disposition"] = "reject"                                # liste sûre qui rejette : refusé
    with pytest.raises(rules.RulesError):
        rules.validate_rules(items)
    items = default()
    items[0].update(disposition="quarantine", folder="Bloqués")       # en revanche la mise en quarantaine est permise
    assert rules.validate_rules(items)[0]["disposition"] == "quarantine"


def test_missing_provided_rules_are_restored():
    stripped = [r for r in default() if r["id"] not in ("inbound_blocked", "inbound_safe", "inbound_notspam")]
    fixed = rules.validate_rules(stripped)
    assert fixed[0]["id"] == "inbound_blocked" and fixed[-1]["id"] == "inbound_notspam" and "inbound_safe" in ids(fixed)


def test_rule_list_bounds():
    items = default()
    with pytest.raises(rules.RulesError):
        rules.validate_rules(items + [dict(items[1], id=f"extra_{i:03d}") for i in range(60)])
    with pytest.raises(rules.RulesError):
        rules.validate_rules(items + [dict(items[1])])                 # doublon
    with pytest.raises(rules.RulesError):
        rules.validate_rules("règles")
    assert rules.validate_rules(None) == default()


def test_upsert_adds_before_the_last_rule_and_replaces_in_place():
    added = rules.upsert(default(), rules.validate_rule(custom()))
    assert ids(added)[-2:] == ["inbound_test", "inbound_notspam"]
    edited = rules.upsert(added, rules.validate_rule(custom(description="Autre")), "inbound_test")
    assert ids(edited) == ids(added) and edited[-2]["description"] == "Autre"
    renamed = rules.upsert(added, rules.validate_rule(custom("inbound_autre")), "inbound_test")
    assert "inbound_autre" in ids(renamed) and "inbound_test" not in ids(renamed)
    with pytest.raises(rules.RulesError):
        rules.upsert(added, rules.validate_rule(custom()), None)                       # existe déjà
    with pytest.raises(rules.RulesError):
        rules.upsert(added, rules.validate_rule(custom("inbound_spam")), "inbound_test")  # collision
    with pytest.raises(rules.RulesError):
        rules.upsert(default(), rules.validate_rule(custom("inbound_autre")), "inbound_notspam")   # règle fournie non renommable
    with pytest.raises(rules.RulesError):
        rules.upsert(default(), rules.validate_rule(custom()), "absente")


def test_upsert_does_not_mutate_its_input():
    original = default()
    snapshot = copy.deepcopy(original)
    rules.upsert(original, rules.validate_rule(custom()))
    rules.toggle(original, "inbound_spam")
    rules.move(original, "inbound_spam", -1)
    rules.delete(original, "inbound_junk")
    rules.clone(original, "inbound_spam")
    assert original == snapshot


def test_toggle_move_delete_and_clone():
    items = default()
    toggled = rules.toggle(items, "inbound_spam")
    assert not next(r for r in toggled if r["id"] == "inbound_spam")["enabled"]
    with pytest.raises(rules.RulesError):
        rules.toggle(items, "inbound_notspam")
    up = rules.move(items, "inbound_junk", -1)
    assert ids(up).index("inbound_junk") == ids(items).index("inbound_junk") - 1
    assert rules.move(items, "inbound_blocked", -1) == items                           # déjà en tête : rien ne bouge
    last_movable = ids(items)[-2]
    assert ids(rules.move(items, last_movable, 1)) == ids(items)                       # jamais après notspam
    with pytest.raises(rules.RulesError):
        rules.move(items, "inbound_notspam", -1)
    assert "inbound_junk" not in ids(rules.delete(items, "inbound_junk"))
    for protected in rules.PROTECTED:
        with pytest.raises(rules.RulesError):
            rules.delete(items, protected)
    with pytest.raises(rules.RulesError):
        rules.delete(items, "absente")
    cloned, new_id = rules.clone(items, "inbound_spam")
    twin = next(r for r in cloned if r["id"] == new_id)
    assert ids(cloned).index(new_id) == ids(cloned).index("inbound_spam") + 1 and twin["enabled"] is False
    assert twin["conditions"] == next(r for r in items if r["id"] == "inbound_spam")["conditions"]
    again, second = rules.clone(cloned, "inbound_spam")
    assert second != new_id and second in ids(again)
    with pytest.raises(rules.RulesError):
        rules.clone(items, "inbound_notspam")


def test_folders_are_deduplicated_and_keep_the_user_access():
    items = rules.upsert(default(), rules.validate_rule(custom(folder="Spam", user_access=False)))
    by_name = {f["name"]: f for f in rules.folders(items)}
    assert set(by_name) >= {"Malware", "Usurpation", "Hameçonnage", "Spam", "Courrier en masse"}
    assert [f["name"] for f in rules.folders(items)].count("Spam") == 1


# ------------------------------------------------------------------ description

def test_french_descriptions():
    rule = rules.validate_rule(custom(match="any", conditions=[cond("malware", ">=", 50), cond("dmarc_reject", "is", True),
                                                               cond("sender", "ends_with", ".xyz")], headers=[{"name": "X-Tag", "value": "a"}]))
    text = rules.describe_conditions(rule)
    assert " OU " in text and "≥ 50" in text and "Échec DMARC" in text and "se termine par « .xyz »" in text
    lines = rules.describe_actions(rule)
    assert any("X-Tag: a" in line for line in lines) and any("[Test]" in line and "administrateur" in line for line in lines)
    assert "accessible à l'utilisateur" in rules.describe_actions(rules.validate_rule(custom(user_access=True)))[-1]
    assert rules.describe_actions(rules.validate_rule(custom(disposition="continue")))[-1].startswith("Poursuivre")
    negative = rules.describe_condition(cond("blocklist", "is", False))
    assert "n'est pas" in negative


def test_warning_for_delivering_on_the_sender_address_only():
    risky = rules.validate_rule(custom(disposition="deliver", conditions=[cond("sender", "ends_with", "partenaire.fr")]))
    assert rules.rule_warnings(risky)
    either = rules.validate_rule(custom(disposition="deliver", match="any", conditions=[cond("sender", "ends_with", "x.fr"), cond("spam", "<=", 10)]))
    assert rules.rule_warnings(either)
    safe = rules.validate_rule(custom(disposition="deliver", conditions=[cond("sender", "ends_with", "partenaire.fr"), cond("safelist", "is", True)]))
    assert rules.rule_warnings(safe) == []
    assert rules.rule_warnings(rules.validate_rule(custom())) == []
    assert rules.rule_warnings(next(r for r in default() if r["id"] == "inbound_safe")) == []


# ------------------------------------------------------------------ listes

def test_lists_are_normalized():
    lists = rules.validate_lists({"block": ["Pirate@Evil.TEST", "evil.test", " 198.51.100.0/24 ", "198.51.100.7/32", "2001:db8::/32", "evil.test"],
                                  "safe": ["partenaire.fr"]})
    assert lists["block"] == ["pirate@evil.test", "evil.test", "198.51.100.0/24", "198.51.100.7", "2001:db8::/32"]
    assert rules.validate_lists(None) == {"block": [], "safe": []}


@pytest.mark.parametrize("bad", [
    ["0.0.0.0/0"], ["::/0"], ["pas un domaine"], ["a@b"], ["@evil.test"], ["x" * 300], [123], ["évil.test"],
    ["a@b.test; rm"], ["999.1.1.1"], ["evil..test"], ["-evil.test"], ["<b>x</b>.test"],
])
def test_lists_refuse_dangerous_entries(bad):
    with pytest.raises(rules.RulesError):
        rules.validate_lists({"block": bad})


def test_lists_bounds_and_shape():
    with pytest.raises(rules.RulesError):
        rules.validate_lists({"block": [f"h{i}.test" for i in range(rules.MAX_LIST + 1)]})
    with pytest.raises(rules.RulesError):
        rules.validate_lists({"autre": []})
    with pytest.raises(rules.RulesError):
        rules.validate_lists(["a.test"])


# ------------------------------------------------------------------ moteur Python

GOLDEN_DATA = json.loads(GOLDEN.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", GOLDEN_DATA["cases"], ids=[c["name"] for c in GOLDEN_DATA["cases"]])
def test_python_engine_matches_the_shared_fixtures(case):
    i = case["input"]
    ctx = rules.build_context(symbols=i["symbols"], raw=i["raw"], th=GOLDEN_DATA["thresholds"], lists=case["lists"], mime_from=i["mime_from"],
                              env_from=i["env_from"], rcpts=i["rcpts"], ip=i["ip"])
    result = rules.evaluate(case["rules"], ctx)
    expected = case["expected"]
    assert ctx["scores"] == expected["scores"]
    assert (ctx["blocklist"], ctx["safelist"]) == (expected["blocklist"], expected["safelist"])
    assert (result["final"] or {}).get("id") == expected["final"]
    assert ids(result["matched"]) == expected["matched"]
    rules.validate_rules(case["rules"])                                                # les cas de référence sont des configurations valides


def decide(symbols=(), raw=0.4, lists=None, **kwargs):
    ctx = rules.build_context(symbols=symbols, raw=raw, th=mail.DEFAULTS["thresholds"], lists=lists or {"block": [], "safe": []}, **kwargs)
    return rules.evaluate(default(), ctx)["final"]["id"]


def test_decisions_follow_the_documented_priorities():
    assert decide() == "inbound_notspam"
    assert decide(raw=6) == "inbound_junk" and decide(raw=9) == "inbound_spam" and decide(raw=20) == "inbound_spam_definite"
    assert decide(["MIME_DOUBLE_BAD_EXTENSION"]) == "inbound_malware"
    assert decide(["PHISHED_OPENPHISH"]) == "inbound_phish"
    assert decide(["SPAMBUNTU_VIP_SPOOF"]) == "inbound_impostor"
    assert decide(["DMARC_POLICY_REJECT"]) == "inbound_dmarc"
    assert decide(raw=9, ip="198.51.100.2", lists={"block": ["198.51.100.0/24"], "safe": []}) == "inbound_blocked"


def test_safe_list_needs_authentication_but_the_block_list_does_not():
    lists = {"block": ["evil.test"], "safe": ["partenaire.test", "192.0.2.10"]}
    spoofed = dict(mime_from="a@partenaire.test", env_from="a@partenaire.test", raw=20)
    assert decide(lists=lists, **spoofed) == "inbound_spam_definite"                  # adresse usurpée : pas de passe-droit
    assert decide(["DMARC_POLICY_ALLOW"], lists=lists, **spoofed) == "inbound_safe"
    assert decide(lists=lists, ip="192.0.2.10", raw=20) == "inbound_safe"             # une IP de confiance suffit
    assert decide(["DMARC_POLICY_ALLOW"], lists=lists, mime_from="a@evil.test", env_from="a@evil.test") == "inbound_blocked"
    assert decide(["PHISHED_OPENPHISH", "DMARC_POLICY_ALLOW"], lists=lists, mime_from="a@partenaire.test") == "inbound_phish"


def test_disabled_rules_are_skipped_and_continue_rules_only_tag():
    items = rules.toggle(default(), "inbound_spam")
    ctx = rules.build_context(symbols=[], raw=9, th=mail.DEFAULTS["thresholds"], lists={"block": [], "safe": []})
    assert rules.evaluate(items, ctx)["final"]["id"] == "inbound_junk"
    items = rules.toggle(rules.toggle(default(), "inbound_bulk"), "inbound_lowpriority")
    items = rules.move(items, "inbound_lowpriority", -1)                              # la règle « poursuivre » passe devant
    ctx = rules.build_context(symbols=["MAILLIST", "HAS_LIST_UNSUB"], raw=1, th=mail.DEFAULTS["thresholds"], lists={"block": [], "safe": []})
    result = rules.evaluate(items, ctx)
    assert "inbound_lowpriority" in ids(result["matched"]) and result["final"]["id"] != "inbound_lowpriority"


def test_any_and_all_combination():
    ctx = rules.build_context(symbols=["R_SPF_FAIL"], raw=1, th=mail.DEFAULTS["thresholds"], lists={"block": [], "safe": []},
                              mime_from="x@promo.xyz", env_from="x@promo.xyz", rcpts=["Compta@Exemple.fr"])
    both = [cond("sender", "ends_with", ".xyz"), cond("symbol", "present", "R_SPF_FAIL")]
    assert rules.evaluate([custom(conditions=both, match="all", enabled=True), default()[-1]], ctx)["final"]["id"] == "inbound_test"
    one_wrong = both + [cond("recipient", "equals", "autre@exemple.fr")]
    assert rules.evaluate([custom(conditions=one_wrong, match="all"), default()[-1]], ctx)["final"]["id"] == "inbound_notspam"
    assert rules.evaluate([custom(conditions=one_wrong, match="any"), default()[-1]], ctx)["final"]["id"] == "inbound_test"
    assert rules.evaluate([custom(conditions=[cond("recipient", "equals", "compta@exemple.fr")]), default()[-1]], ctx)["final"]["id"] == "inbound_test"


# ------------------------------------------------------------------ moteur Lua (même fixtures)

@pytest.mark.skipif(shutil.which("rspamadm") is None, reason="rspamadm absent")
def test_lua_engine_matches_the_python_engine():
    res = subprocess.run(["rspamadm", "lua", "-s", str(ROOT / "tests" / "lua" / "rules_lib_test.lua")], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=120,
                         env={**os.environ, "RULES_LIB": str(LIB), "RULES_GOLDEN": str(GOLDEN)})
    assert "OK" in res.stdout and "obtenu" not in res.stdout, res.stdout + res.stderr


# ------------------------------------------------------------------ rendu pour Rspamd

def test_render_keeps_only_active_rules_and_ascii_folders():
    cfg = mail.validate({**BASE, "rules": [r for r in rules.toggle(default(), "inbound_spam")]})
    rendered = json.loads(mail.render_identity(cfg)["rspamd-rules.json"])
    assert "inbound_spam" not in ids(rendered["rules"]) and rendered["rules"][-1]["id"] == "inbound_notspam"
    phish = next(r for r in rendered["rules"] if r["id"] == "inbound_phish")
    assert phish["folder"] == "hameconnage" and phish["access"] == "admin"
    assert rendered["thresholds"] == cfg["thresholds"] and rendered["quarantine_enabled"] is True
    assert set(rendered["signals"]) == {"malware", "phish", "impostor", "bulk"}


def test_render_follows_the_quarantine_switch_and_lists():
    cfg = mail.validate({**BASE, "quarantine_enabled": False, "lists": {"block": ["evil.test"], "safe": ["a@b.fr"]}})
    rendered = json.loads(mail.render_identity(cfg)["rspamd-rules.json"])
    assert rendered["quarantine_enabled"] is False and rendered["lists"] == {"block": ["evil.test"], "safe": ["a@b.fr"]}


def test_apply_writes_the_rules_file(tmp_path):
    from test_mail import FakeRun
    mail.Applier(root=tmp_path, run=FakeRun(), reload=False).apply(mail.validate(BASE))
    written = json.loads((tmp_path / "etc/rspamd/local.d/spambuntu-rules.json").read_text())
    assert written["rules"][0]["id"] == "inbound_blocked" and written["enabled"] is True


def test_mail_config_rejects_bad_rules_and_lists():
    with pytest.raises(mail.MailError):
        mail.validate({**BASE, "rules": [custom(disposition="discard")]})
    with pytest.raises(mail.MailError):
        mail.validate({**BASE, "lists": {"block": ["0.0.0.0/0"]}})
    cfg = mail.validate({**BASE, "rules": [custom()]})                                    # une liste partielle est complétée
    assert cfg["rules"][0]["id"] == "inbound_blocked" and cfg["rules"][-1]["id"] == "inbound_notspam" and "inbound_test" in ids(cfg["rules"])


# ------------------------------------------------------------------ pages de la console

from test_mail import mailweb  # noqa: E402,F401  (fixture)
from test_webui import auth, web  # noqa: E402,F401  (fixtures)


@pytest.fixture
def rweb(mailweb):
    mailweb.app.config["STATS_RUNNER"] = lambda args: {"ok": True, "rule_hits": {"inbound_spam": 7, "inbound_notspam": 120}, "counts": {}}
    return mailweb


def saved(web):
    return json.loads((web.mail_dir / "mail-request.json").read_text())


def apply_pending(web):
    """Simule le service root : la demande devient la configuration appliquée."""
    request = web.mail_dir / "mail-request.json"
    Path(web.app.config["MAIL_CONF"]).write_text(request.read_text())
    request.unlink()


def post(web, path, **data):
    return web.client.post(path, data={**data, "csrf_token": web.token})


def rule_of(cfg, rule_id):
    return next((r for r in cfg["rules"] if r["id"] == rule_id), None)


def test_rule_pages_require_login(web):
    for path in ("/regles", "/regles/nouvelle", "/regles/listes", "/regles/inbound_spam/modifier"):
        assert web.client.get(path).status_code == 302
    for path in ("/regles/nouvelle", "/regles/listes", "/regles/inbound_spam/activer", "/regles/inbound_spam/supprimer"):
        assert web.client.post(path, data={}).status_code in (302, 403)


def test_rules_page_lists_every_rule_like_the_reference_table(rweb):
    html = rweb.client.get("/regles").get_data(as_text=True)
    for rule in default():
        assert rule["id"] in html
    for text in ("Active", "Classification", "Condition", "Action", "Ordre", "Ajouter une règle", "Listes de blocage et sûre"):
        assert text in html
    assert "Score de spam ≥ 50" in html and "Mettre en quarantaine, dossier [Spam]" in html and "Poursuivre avec la règle suivante" in html
    assert "<strong>7</strong>" in html and "<strong>120</strong>" in html                # déclenchements sur 24 h
    assert 'href="/regles/inbound_spam/modifier"' in html
    assert 'action="/regles/inbound_notspam/activer"' not in html                         # toujours active
    assert 'action="/regles/inbound_notspam/supprimer"' not in html and 'action="/regles/inbound_safe/supprimer"' not in html
    assert 'action="/regles/inbound_junk/supprimer"' in html
    assert "csrf_token" in html and "Sidebar" not in html and 'href="/regles"' in html


def test_rules_page_survives_missing_statistics(rweb):
    rweb.app.config["STATS_RUNNER"] = lambda args: {"ok": False, "error": "indisponible"}
    html = rweb.client.get("/regles").get_data(as_text=True)
    assert "inbound_spam" in html and "indisponibles" in html


def test_toggle_move_clone_delete_write_a_request_for_the_root_service(rweb):
    assert post(rweb, "/regles/inbound_spam/activer").status_code == 302
    assert rule_of(saved(rweb), "inbound_spam")["enabled"] is False
    assert rweb.started[-1] == "spambuntu-mail-apply.service"
    post(rweb, "/regles/inbound_junk/monter")                                             # sans attendre l'application de la précédente
    order = ids(saved(rweb)["rules"])
    assert order.index("inbound_junk") == ids(default()).index("inbound_junk") - 1
    assert rule_of(saved(rweb), "inbound_spam")["enabled"] is False                       # la modification précédente est conservée
    post(rweb, "/regles/inbound_junk/descendre")
    assert ids(saved(rweb)["rules"]) == ids(default())
    r = post(rweb, "/regles/inbound_spam/cloner")
    assert r.status_code == 302 and r.headers["Location"].endswith("/regles/inbound_spam_copie/modifier")
    copy_rule = rule_of(saved(rweb), "inbound_spam_copie")
    assert copy_rule["enabled"] is False
    post(rweb, "/regles/inbound_spam_copie/supprimer")
    assert rule_of(saved(rweb), "inbound_spam_copie") is None and rule_of(saved(rweb), "inbound_spam") is not None


def test_pending_request_is_the_base_of_the_next_change(rweb):
    post(rweb, "/regles/inbound_spam/activer")
    post(rweb, "/regles/inbound_junk/activer")                                            # la précédente n'est pas encore appliquée
    cfg = saved(rweb)
    assert rule_of(cfg, "inbound_spam")["enabled"] is False and rule_of(cfg, "inbound_junk")["enabled"] is False
    apply_pending(rweb)
    post(rweb, "/regles/inbound_bulk/activer")
    assert rule_of(saved(rweb), "inbound_spam")["enabled"] is False and rule_of(saved(rweb), "inbound_bulk")["enabled"] is True


def test_protected_rules_refuse_deletion_and_notspam_refuses_changes(rweb):
    for rule_id in rules.PROTECTED:
        r = post(rweb, f"/regles/{rule_id}/supprimer", ).get_data(as_text=True)
        assert not (rweb.mail_dir / "mail-request.json").exists()
    follow = rweb.client.post("/regles/inbound_notspam/activer", data={"csrf_token": rweb.token}, follow_redirects=True).get_data(as_text=True)
    assert "Modification refusée" in follow and "toujours active" in follow
    assert not (rweb.mail_dir / "mail-request.json").exists()
    rweb.client.post("/regles/inbound_notspam/monter", data={"csrf_token": rweb.token})
    assert not (rweb.mail_dir / "mail-request.json").exists()


def test_unknown_actions_and_rules(rweb):
    assert post(rweb, "/regles/inbound_spam/formater").status_code == 404
    assert post(rweb, "/regles/Pas%20Valide/activer").status_code == 404
    r = rweb.client.post("/regles/inexistante/activer", data={"csrf_token": rweb.token}, follow_redirects=True)
    assert "Règle introuvable" in r.get_data(as_text=True)
    assert rweb.client.get("/regles/inexistante/modifier").status_code == 404
    assert post(rweb, "/regles/inexistante/modifier").status_code == 404
    assert not (rweb.mail_dir / "mail-request.json").exists()


def test_actions_need_the_csrf_token(rweb):
    assert rweb.client.post("/regles/inbound_spam/activer", data={}).status_code in (302, 403)
    assert not (rweb.mail_dir / "mail-request.json").exists()


def test_a_failed_unit_start_leaves_no_request_behind(rweb):
    rweb.app.config["UNIT_STARTER"] = lambda unit: (False, "refusé")
    r = rweb.client.post("/regles/inbound_spam/activer", data={"csrf_token": rweb.token}, follow_redirects=True)
    assert "Impossible d&#39;appliquer" in r.get_data(as_text=True) and not (rweb.mail_dir / "mail-request.json").exists()


NEW = {"id": "inbound_facture", "description": "Factures douteuses", "match": "all", "enabled": "on", "explain": "on",
       "cond_field_0": "recipient", "cond_op_0": "equals", "cond_value_0": "Compta@Exemple.fr",
       "cond_field_1": "spam", "cond_op_1": ">=", "cond_value_1": "30",
       "disposition": "quarantine", "folder": "Factures", "user_access": "on"}


def test_create_rule_from_the_form(rweb):
    assert rweb.client.get("/regles/nouvelle").status_code == 200
    r = post(rweb, "/regles/nouvelle", **NEW)
    assert r.status_code == 302 and r.headers["Location"].endswith("/regles")
    rule = rule_of(saved(rweb), "inbound_facture")
    assert rule["conditions"] == [cond("recipient", "equals", "compta@exemple.fr"), cond("spam", ">=", 30)]
    assert rule["folder"] == "Factures" and rule["user_access"] is True and rule["enabled"] is True and rule["headers"] == []
    order = ids(saved(rweb)["rules"])
    assert order[-2:] == ["inbound_facture", "inbound_notspam"]


def test_create_rule_with_headers_and_boolean_condition(rweb):
    data = {**NEW, "id": "inbound_tag", "disposition": "continue", "folder": "",
            "cond_field_0": "dmarc_reject", "cond_op_0": "is:false", "cond_value_0": "", "cond_field_1": "", "cond_op_1": "", "cond_value_1": "",
            "hdr_name_0": "X-Origine", "hdr_value_0": "externe"}
    post(rweb, "/regles/nouvelle", **data)
    rule = rule_of(saved(rweb), "inbound_tag")
    assert rule["conditions"] == [cond("dmarc_reject", "is", False)] and rule["headers"] == [{"name": "X-Origine", "value": "externe"}]
    assert rule["disposition"] == "continue" and rule["folder"] == ""


@pytest.mark.parametrize("override,message", [
    ({"id": "Mauvais Id"}, "Classification invalide"),
    ({"id": "inbound_spam"}, "existe déjà"),
    ({"description": ""}, "Description invalide"),
    ({"cond_field_0": "", "cond_field_1": ""}, "conditions"),
    ({"cond_op_1": "contains"}, "incompatible"),
    ({"cond_value_1": "200"}, "comprise entre"),
    ({"cond_value_1": "beaucoup"}, "numérique"),
    ({"disposition": "discard"}, "Action invalide"),
    ({"folder": ""}, "dossier"),
    ({"folder": "<script>alert(1)</script>"}, "dossier"),
    ({"hdr_name_0": "Subject", "hdr_value_0": "x"}, "commencer par X-"),
    ({"hdr_name_0": "X-Spam", "hdr_value_0": "No"}, "réservé"),
    ({"hdr_name_0": "X-A", "hdr_value_0": ""}, "Valeur d&#39;en-tête invalide"),
])
def test_invalid_rule_forms_are_redisplayed_with_the_entries(rweb, override, message):
    r = post(rweb, "/regles/nouvelle", **{**NEW, **override})
    html = r.get_data(as_text=True)
    assert r.status_code == 422 and message in html
    assert 'value="Factures douteuses"' in html or "description" in override                   # saisie conservée
    assert not (rweb.mail_dir / "mail-request.json").exists()


def test_form_output_is_escaped(rweb):
    r = post(rweb, "/regles/nouvelle", **{**NEW, "description": "<img src=x onerror=alert(1)>", "folder": "<b>x</b>"})
    html = r.get_data(as_text=True)
    assert r.status_code == 422 and "<img src=x" not in html and "<b>x</b>" not in html


def test_edit_form_shows_the_current_rule_and_saves_changes(rweb):
    html = rweb.client.get("/regles/inbound_spam/modifier").get_data(as_text=True)
    assert 'value="inbound_spam"' in html and 'name="cond_field_0"' in html and "Dossier de quarantaine" in html
    assert 'value="Spam"' in html and "checked" in html
    r = post(rweb, "/regles/inbound_spam/modifier", id="inbound_spam", description="Spam sérieux", match="all", enabled="on",
             cond_field_0="spam", cond_op_0=">=", cond_value_0="60", disposition="quarantine", folder="Spam", explain="on")
    assert r.status_code == 302
    edited = rule_of(saved(rweb), "inbound_spam")
    assert edited["conditions"] == [cond("spam", ">=", 60)] and edited["description"] == "Spam sérieux" and edited["user_access"] is False
    assert ids(saved(rweb)["rules"]) == ids(default())                                          # même place


def test_a_rule_can_be_renamed_but_a_provided_one_cannot(rweb):
    post(rweb, "/regles/nouvelle", **NEW)
    apply_pending(rweb)
    post(rweb, "/regles/inbound_facture/modifier", **{**NEW, "id": "inbound_compta"})
    assert "inbound_compta" in ids(saved(rweb)["rules"]) and "inbound_facture" not in ids(saved(rweb)["rules"])
    apply_pending(rweb)
    r = post(rweb, "/regles/inbound_safe/modifier", id="autre_nom", description="Sûre", disposition="deliver", explain="on")
    assert r.status_code == 302 and "inbound_safe" in ids(saved(rweb)["rules"]) and "autre_nom" not in ids(saved(rweb)["rules"])


def test_locked_rules_ignore_posted_conditions(rweb):
    html = rweb.client.get("/regles/inbound_blocked/modifier").get_data(as_text=True)
    assert 'name="cond_field_0"' not in html and "liste de blocage" in html and "readonly" in html
    assert "Rejeter" in html and "Livrer le message et arrêter" not in html                     # actions limitées
    post(rweb, "/regles/inbound_blocked/modifier", id="inbound_blocked", description="Bloqués", disposition="reject", explain="on",
         cond_field_0="spam", cond_op_0=">=", cond_value_0="0")
    assert rule_of(saved(rweb), "inbound_blocked")["conditions"] == rules.LOCKED_CONDITIONS["inbound_blocked"]
    apply_pending(rweb)
    r = post(rweb, "/regles/inbound_blocked/modifier", id="inbound_blocked", description="Bloqués", disposition="deliver", explain="on")
    assert r.status_code == 422 and "Action impossible" in r.get_data(as_text=True)


def test_notspam_stays_enabled_even_if_the_box_is_unchecked(rweb):
    post(rweb, "/regles/inbound_notspam/modifier", description="Légitime", disposition="deliver", explain="on")
    last = saved(rweb)["rules"][-1]
    assert last["id"] == "inbound_notspam" and last["enabled"] is True and last["conditions"] == rules.LOCKED_CONDITIONS["inbound_notspam"]
    html = rweb.client.get("/regles/inbound_notspam/modifier").get_data(as_text=True)
    assert 'name="enabled"' not in html


def test_delivering_on_the_sender_address_raises_a_warning(rweb):
    data = {**NEW, "id": "inbound_vip", "disposition": "deliver", "folder": "", "cond_field_0": "sender", "cond_op_0": "ends_with",
            "cond_value_0": "partenaire.fr", "cond_field_1": "", "cond_op_1": "", "cond_value_1": ""}
    r = rweb.client.post("/regles/nouvelle", data={**data, "csrf_token": rweb.token}, follow_redirects=True)
    assert "Attention" in r.get_data(as_text=True) and "falsifie" in r.get_data(as_text=True)
    assert rule_of(saved(rweb), "inbound_vip") is not None                                       # avertissement, pas un refus


def test_lists_page_round_trip(rweb):
    assert "Liste de blocage" in rweb.client.get("/regles/listes").get_data(as_text=True)
    r = post(rweb, "/regles/listes", block="Evil.test\n# commentaire\n203.0.113.0/24, pirate@evil.test\n", safe="partenaire.fr ; ceo@vip.test\n")
    assert r.status_code == 302
    cfg = saved(rweb)
    assert cfg["lists"] == {"block": ["evil.test", "203.0.113.0/24", "pirate@evil.test"], "safe": ["partenaire.fr", "ceo@vip.test"]}
    assert rule_of(cfg, "inbound_blocked") is not None                                           # règles conservées
    apply_pending(rweb)
    html = rweb.client.get("/regles/listes").get_data(as_text=True)
    assert "203.0.113.0/24" in html and "partenaire.fr" in html and "doit être authentifié" in html


@pytest.mark.parametrize("block", ["0.0.0.0/0", "pas un domaine", "a@b", "x" * 300])
def test_lists_page_refuses_dangerous_entries(rweb, block):
    r = rweb.client.post("/regles/listes", data={"block": block, "safe": "", "csrf_token": rweb.token}, follow_redirects=True)
    assert "Listes refusées" in r.get_data(as_text=True) and not (rweb.mail_dir / "mail-request.json").exists()


def test_messagerie_form_preserves_rules_and_lists(rweb):
    from test_mail import FORM
    post(rweb, "/regles/inbound_spam/activer")
    post(rweb, "/regles/listes", block="evil.test", safe="")
    post(rweb, "/regles/nouvelle", **NEW)
    apply_pending(rweb)
    assert rweb.client.post("/messagerie", data={**FORM, "csrf_token": rweb.token}).status_code == 302
    cfg = saved(rweb)
    assert rule_of(cfg, "inbound_spam")["enabled"] is False and rule_of(cfg, "inbound_facture") is not None
    assert cfg["lists"]["block"] == ["evil.test"]
    assert "dmarc_action" not in cfg


def test_messagerie_page_points_to_the_rules(rweb):
    html = rweb.client.get("/messagerie").get_data(as_text=True)
    assert 'href="/regles"' in html and "dmarc_action" not in html


def test_navigation_has_a_rules_entry(rweb):
    html = rweb.client.get("/regles").get_data(as_text=True)
    assert 'class="active" aria-current="page"' in html and "Règles de filtrage" in html


def test_security_headers_on_rule_pages(rweb):
    for path in ("/regles", "/regles/nouvelle", "/regles/listes", "/regles/inbound_spam/modifier"):
        r = rweb.client.get(path)
        csp = r.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "unsafe-inline" not in csp
        body = r.get_data(as_text=True)
        assert " style=" not in body and "onclick=" not in body and "<script>" not in body
        if path != "/regles/listes":
            assert 'src="/static/rules.js"' in body


# ------------------------------------------------------------------ quarantaine : la règle appliquée

import spambuntu_logs as logs  # noqa: E402
import spambuntu_quarantine as quar  # noqa: E402

RULE_SYMBOL = "SPAMBUNTU_RULE(0.00)[{rule},{folder},{access},spam:60,malware:0,phish:{phish},impostor:0,bulk:10];"


def spamd(rule="inbound_spam", folder="spam", access="user", phish=0, extra="", score="9.50"):
    return f"default: True [{score} / 15.00];\n\tR_SPF_FAIL(1.00)[-all];\n{extra}\t" + RULE_SYMBOL.format(rule=rule, folder=folder, access=access, phish=phish)


def test_the_rule_symbol_is_parsed_defensively():
    parsed = quar.rule_of(spamd())
    assert parsed == {"id": "inbound_spam", "folder": "spam", "access": "user",
                      "scores": {"spam": 60, "malware": 0, "phish": 0, "impostor": 0, "bulk": 10}}
    assert quar.rule_of("default: True [1.00 / 15.00];\n\tR_SPF_FAIL(1.00)[-all];") == {}
    assert quar.rule_of(spamd(rule="Mauvais Id")) == {}                                     # identifiant falsifié
    assert quar.rule_of(spamd(folder="../../etc"))["folder"] == ""
    assert quar.rule_of(spamd(access="root"))["access"] == ""
    assert quar.rule_of(spamd(phish=900))["scores"].get("phish") is None                    # score hors bornes ignoré
    assert quar.rule_of("SPAMBUNTU_RULE(0.00)[inbound_spam]") == {}                         # options incomplètes


def test_an_administrator_folder_makes_the_message_administrator_only():
    cls, reasons = quar.classify([], [], 9.0, {"id": "inbound_finance", "folder": "finance", "access": "admin"}, {"finance": "Finance"})
    assert cls == "admin" and reasons == ["Dossier « Finance » réservé à l'administrateur"]
    assert quar.classify([], [], 9.0, {"id": "inbound_spam", "folder": "spam", "access": "user"}, {"spam": "Spam"}) == ("user", [])
    assert quar.classify([], [], 9.0, {}, {}) == ("user", [])


@pytest.mark.parametrize("symbols,flags,score", [
    (["PHISHED_OPENPHISH"], [], 9.0), (["CLAM_VIRUS"], [], 9.0), (["SPAMBUNTU_VIP_SPOOF"], [], 9.0),
    ([], ["bec"], 9.0), ([], [], 13.0), ([], [], None),
])
def test_a_user_folder_never_relaxes_a_danger_signal(symbols, flags, score):
    """Une règle « accessible à l'utilisateur » ne doit jamais rendre libérable un message dangereux."""
    cls, reasons = quar.classify(symbols, flags, score, {"id": "inbound_open", "folder": "ouvert", "access": "user"}, {"ouvert": "Ouvert"})
    assert cls == "admin" and reasons


class HeldRun:
    def __init__(self, result, rcpts=("compta@exemple.fr",)):
        self.result = result
        self.entry = {"queue_name": "hold", "queue_id": "AAAAAAAAAA1", "arrival_time": 1700000000, "message_size": 2048,
                      "sender": "s@x.test", "recipients": [{"address": r} for r in rcpts]}
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[:2] == ["postqueue", "-j"]:
            return subprocess.CompletedProcess(cmd, 0, json.dumps(self.entry).encode(), b"")
        if cmd[:2] == ["postcat", "-qh"]:
            head = f"From: S <s@x.test>\nSubject: Test\nX-Spamd-Result: {self.result}\n"
            return subprocess.CompletedProcess(cmd, 0, head.encode(), b"")
        if cmd[:2] == ["postcat", "-qb"]:
            return subprocess.CompletedProcess(cmd, 0, b"\nBonjour\n", b"")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")


def test_listing_and_detail_expose_the_applied_rule():
    run = HeldRun(spamd())
    item = quar.listing(run)[0]
    assert item["rule"] == "inbound_spam" and item["folder"] == "spam" and item["folder_name"] == "Spam" and item["class"] == "user"
    shown = quar.show("AAAAAAAAAA1", run)
    assert shown["rule"] == "inbound_spam" and shown["folder_access"] == "user" and shown["class_scores"]["spam"] == 60
    admin_item = quar.listing(HeldRun(spamd(rule="inbound_phish", folder="hameconnage", access="admin", phish=90)))[0]
    assert admin_item["class"] == "admin" and admin_item["folder_name"] == "Hameçonnage"


def test_a_recipient_cannot_act_on_an_administrator_folder(tmp_path):
    ordinary = HeldRun(spamd())
    assert quar.act("release", "AAAAAAAAAA1", "utilisateur", ordinary, tmp_path / "q.log", recipient="compta@exemple.fr") == "Message libéré et remis en livraison"
    restricted = HeldRun(spamd(rule="inbound_finance", folder="finance", access="admin"))
    with pytest.raises(quar.QuarantineError):
        quar.act("release", "AAAAAAAAAA1", "utilisateur", restricted, tmp_path / "q.log", recipient="compta@exemple.fr")
    with pytest.raises(quar.QuarantineError):
        quar.act("delete", "AAAAAAAAAA1", "utilisateur", restricted, tmp_path / "q.log", recipient="compta@exemple.fr")
    assert not any(c[:2] == ["postsuper", "-H"] for c in restricted.calls)
    # l'administrateur, lui, doit confirmer la libération d'un dossier réservé
    with pytest.raises(quar.QuarantineError):
        quar.act("release", "AAAAAAAAAA1", "admin", restricted, tmp_path / "q.log")
    assert quar.act("release", "AAAAAAAAAA1", "admin", restricted, tmp_path / "q.log", confirm_danger=True)


def test_a_forged_rule_header_cannot_open_a_dangerous_message_to_the_user(tmp_path):
    """Un expéditeur qui envoie lui-même « SPAMBUNTU_RULE …,user » reste jugé sur les symboles de danger."""
    forged = HeldRun(spamd(extra="\tPHISHED_OPENPHISH(5.00)[x];\n"))
    with pytest.raises(quar.QuarantineError):
        quar.act("release", "AAAAAAAAAA1", "utilisateur", forged, tmp_path / "q.log", recipient="compta@exemple.fr")


# ------------------------------------------------------------------ journal : la règle appliquée

def rule_log(applied, action="quarantine"):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    return (f"{stamp} #1(normal) <a>; task; rspamd_task_write_log: id: <m@x>, qid: <AAAAAAAAAA1>, ip: 203.0.113.9, from: <s@x.test>, "
            f"(default: T ({action}): [9.50/15.00] [R_SPF_FAIL(1.00){{-all;}},{applied}]), len: 300, time: 12.5ms, dns req: 2, digest: <d>, rcpts: <compta@exemple.fr>, mime_rcpts: <compta@exemple.fr>")


import time  # noqa: E402


def test_the_journal_records_the_applied_rule_and_scores():
    record = logs.parse_line(rule_log("SPAMBUNTU_RULE(0.00){inbound_spam;spam;user;spam:60;malware:0;phish:0;impostor:0;bulk:10;}"))
    assert record["rule"] == "inbound_spam" and record["folder"] == "spam" and record["class_scores"]["spam"] == 60
    plain = logs.parse_line(rule_log("MIME_GOOD(-0.10){}", action="no action"))
    assert plain["rule"] == "" and plain["folder"] == ""
    forged = logs.parse_line(rule_log("SPAMBUNTU_RULE(0.00){Mauvais Id;spam;user;}"))
    assert forged["rule"] == ""


def test_the_journal_filters_and_counts_by_rule():
    spam = logs.parse_line(rule_log("SPAMBUNTU_RULE(0.00){inbound_spam;spam;user;spam:60;}"))
    junk = logs.parse_line(rule_log("SPAMBUNTU_RULE(0.00){inbound_junk;-;-;spam:30;}", action="add header"))
    other = logs.parse_line(rule_log("MIME_GOOD(-0.10){}", action="no action"))
    found = logs.search([spam, junk, other], rule="inbound_spam")
    assert [r["rule"] for r in found] == ["inbound_spam"]
    assert logs.summarize([spam, junk, junk, other], 24)["rule_hits"] == {"inbound_spam": 1, "inbound_junk": 2}


# ------------------------------------------------------------------ pages : quarantaine et journal

@pytest.fixture
def qweb(mailweb):
    messages = [
        {"id": "AAAAAAAAAA1", "class": "user", "danger": [], "sender": "n@shop.test", "from": "Shop", "recipients": ["marie@exemple.fr"], "size": 1,
         "arrived": 1700000000, "subject": "Promo", "score": 9.0, "symbols": [], "rule": "inbound_spam", "folder": "spam", "folder_name": "Spam"},
        {"id": "BBBBBBBBBB2", "class": "admin", "danger": ["Hameçonnage"], "sender": "x@evil.test", "from": "X", "recipients": ["marie@exemple.fr"], "size": 1,
         "arrived": 1700000100, "subject": "Compte suspendu", "score": 14.0, "symbols": [], "rule": "inbound_phish", "folder": "hameconnage", "folder_name": "Hameçonnage"},
    ]
    detail = {"id": "BBBBBBBBBB2", "class": "admin", "danger": ["Hameçonnage"], "sender": "x@evil.test", "recipients": ["marie@exemple.fr"], "arrived": 1700000100,
              "size": 1, "score": 14.0, "reject_limit": 15.0, "symbols": [], "ai": "", "ai_flags": [], "headers": {"subject": "Compte suspendu", "from": "X"},
              "preview": {"text": "", "links": [], "attachments": []}, "rule": "inbound_phish", "folder": "hameconnage", "folder_name": "Hameçonnage",
              "folder_access": "admin", "class_scores": {"spam": 90, "malware": 0, "phish": 85, "impostor": 10, "bulk": 0}}

    def runner(args):
        if args[0] == "list":
            return {"ok": True, "messages": messages}
        if args[0] == "show":
            return {"ok": True, "message": detail}
        return {"ok": True, "message": "ok"}

    mailweb.app.config["QUARANTINE_RUNNER"] = runner
    return mailweb


def test_quarantine_list_shows_and_filters_by_folder(qweb):
    html = qweb.client.get("/quarantaine?vue=tout").get_data(as_text=True)
    assert 'class="folder-line"' in html.replace(' title="Dossier Hameçonnage · règle inbound_phish"', "") and ">Hameçonnage</div>" in html
    assert '<option value="spam"' in html and '<option value="hameconnage"' in html
    only = qweb.client.get("/quarantaine?vue=tout&dossier=spam").get_data(as_text=True)
    assert "Promo" in only and "Compte suspendu" not in only
    assert "Compte suspendu" not in qweb.client.get("/quarantaine?vue=tout&dossier=%3Cb%3E").get_data(as_text=True)       # valeur inconnue : aucun résultat


def test_quarantine_detail_shows_the_rule_and_class_scores(qweb):
    html = qweb.client.get("/quarantaine/message/BBBBBBBBBB2").get_data(as_text=True)
    assert "Règle de filtrage appliquée" in html and 'href="/regles/inbound_phish/modifier"' in html
    assert "réservé à l'administrateur" in html and "Hameçonnage" in html
    assert 'value="85"' in html and "Scores par classe" in html and " style=" not in html


def test_journal_filters_by_rule_and_links_to_it(mailweb):
    calls = []
    mailweb.app.config["STATS_RUNNER"] = lambda args: calls.append(args) or {
        "ok": True, "records": [{"ts": 1700000000, "category": "quarantined", "score": 9.5, "qid": "AAAAAAAAAA1", "mid": "m@x", "ip": "203.0.113.9", "sender": "s@x.test",
                                 "rcpts": ["a@exemple.fr"], "symbols": ["R_SPF_FAIL"], "rule": "inbound_spam"}]}
    html = mailweb.client.get("/journal?filtre=inbound_spam").get_data(as_text=True)
    assert calls[-1][calls[-1].index("--rule") + 1] == "inbound_spam"
    assert 'href="/regles/inbound_spam/modifier"' in html and "Règle appliquée" in html and '<option value="inbound_spam" selected>' in html
    mailweb.client.get("/journal?filtre=Mauvais%20Id;rm")
    assert "--rule" not in calls[-1]                                                         # identifiant invalide : ignoré


def test_trace_page_shows_the_applied_rule(mailweb):
    verdict = {"ts": 1700000000, "category": "quarantined", "action": "quarantine", "score": 9.5, "limit": 15.0, "sender": "s@x.test", "rcpts": ["a@exemple.fr"],
               "ip": "203.0.113.9", "size": 300, "time_ms": 12.5, "qid": "AAAAAAAAAA1", "mid": "m@x", "sym_all": [], "rule": "inbound_spam", "folder": "spam",
               "class_scores": {"spam": 60, "malware": 0, "phish": 0, "impostor": 0, "bulk": 10}}
    mailweb.app.config["STATS_RUNNER"] = lambda args: {"ok": True, "verdicts": [verdict], "delivery": []}
    html = mailweb.client.get("/journal/trace?id=AAAAAAAAAA1").get_data(as_text=True)
    assert 'href="/regles/inbound_spam/modifier"' in html and "dossier <code>spam</code>" in html
    assert "Scores par classe" in html and "Spam <strong>60</strong>" in html
