"""Régénère tests/data/rules_golden.json à partir du moteur Python (python3 tests/data/make_rules_golden.py).

Le fichier est relu par tests/test_rules.py (moteur Python) et par tests/lua/rules_lib_test.lua (moteur Lua) :
les deux doivent rendre exactement les mêmes scores, listes et décisions. Relire le diff à chaque régénération.
"""
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "appliance" / "mail"))
import spambuntu_rules as r  # noqa: E402

TH = {"tag": 5.0, "quarantine": 8.0, "reject": 15.0}
LISTS = {"block": ["pirate@evil.test", "evil.test", "198.51.100.0/24", "2001:db8:bad::/48"],
         "safe": ["partenaire.test", "ceo@vip.test", "192.0.2.10", "2001:db8:5afe::1"]}
BASE = {"symbols": [], "raw": 0.4, "mime_from": "client@autre.test", "env_from": "client@autre.test", "rcpts": ["compta@exemple.fr"], "ip": "203.0.113.9"}


def case(name, rules="default", lists=None, **inp):
    return {"name": name, "rules": rules, "lists": lists or {"block": [], "safe": []}, "input": {**BASE, **inp}}


def custom_rules():
    rules = r.default_rules()
    rules = [x for x in rules if x["id"] not in ("inbound_bulk", "inbound_lowpriority")]
    extra = {x["id"]: x for x in r.default_rules() if x["id"] in ("inbound_lowpriority", "inbound_bulk")}
    for key in ("inbound_lowpriority", "inbound_bulk"):      # « continuer » d'abord, puis la règle qui décide
        extra[key]["enabled"] = True
        rules.insert(-1, extra[key])
    vip = r._rule("custom_finance", "Courrier à la comptabilité", [
        r._cond("recipient", "equals", "compta@exemple.fr"), r._cond("symbol", "present", "R_SPF_FAIL")], "quarantine",
        folder="Finance", user_access=False, match="all")
    any_rule = r._rule("custom_any", "Expéditeur suspect", [
        r._cond("sender", "ends_with", ".xyz"), r._cond("score", "<=", -1)], "reject", match="any")
    rules.insert(0, any_rule)
    rules.insert(1, vip)
    return r.validate_rules(rules)


CASES = [
    case("courrier propre"),
    case("marquage", raw=6.0),
    case("quarantaine spam", raw=9.0),
    case("rejet spam certain", raw=20.0),
    case("hameconnage connu", symbols=["PHISHED_OPENPHISH"], raw=3.0),
    case("virus", symbols=["CLAM_VIRUS"], raw=2.0),
    case("double extension", symbols=["MIME_DOUBLE_BAD_EXTENSION"], raw=2.0),
    case("extension seule", symbols=["MIME_BAD_EXTENSION"], raw=2.0),
    case("usurpation dirigeant", symbols=["SPAMBUNTU_VIP_SPOOF"], raw=8.0),
    case("marque dans domaine", symbols=["SPAMBUNTU_BRAND_IN_DOMAIN"], raw=2.0),
    case("dmarc reject", symbols=["DMARC_POLICY_REJECT"], raw=6.0),
    case("ia hameconnage", symbols=["SPAMBUNTU_AI", "SPAMBUNTU_AI_PHISHING"], raw=6.0),
    case("ia bec", symbols=["SPAMBUNTU_AI_BEC"], raw=6.0),
    case("liste noire adresse", lists=LISTS, mime_from="pirate@evil.test", env_from="pirate@evil.test"),
    case("liste noire domaine parent", lists=LISTS, mime_from="x@a.b.evil.test", env_from="x@a.b.evil.test"),
    case("liste noire enveloppe", lists=LISTS, mime_from="client@autre.test", env_from="bounce@evil.test"),
    case("liste noire reseau ipv4", lists=LISTS, ip="198.51.100.77"),
    case("liste noire reseau ipv6", lists=LISTS, ip="2001:db8:bad::99"),
    case("hors liste noire", lists=LISTS, ip="198.51.101.1"),
    case("liste sure sans authentification", lists=LISTS, mime_from="x@partenaire.test", env_from="x@partenaire.test", raw=20.0),
    case("liste sure avec dmarc", lists=LISTS, symbols=["DMARC_POLICY_ALLOW"], mime_from="x@partenaire.test", env_from="x@partenaire.test", raw=20.0),
    case("liste sure spf aligne", lists=LISTS, symbols=["R_SPF_ALLOW"], mime_from="x@partenaire.test", env_from="bounce@mail.partenaire.test", raw=9.0),
    case("liste sure spf non aligne", lists=LISTS, symbols=["R_SPF_ALLOW"], mime_from="x@partenaire.test", env_from="bounce@autre.test", raw=9.0),
    case("liste sure adresse", lists=LISTS, symbols=["DMARC_POLICY_ALLOW"], mime_from="ceo@vip.test", env_from="ceo@vip.test", raw=9.0),
    case("liste sure ip", lists=LISTS, ip="192.0.2.10", raw=9.0),
    case("liste sure ipv6", lists=LISTS, ip="2001:db8:5afe::1", raw=9.0),
    case("hameconnage prime sur liste sure", lists=LISTS, symbols=["DMARC_POLICY_ALLOW", "PHISHED_OPENPHISH"], mime_from="x@partenaire.test", env_from="x@partenaire.test"),
    case("en masse desactive", symbols=["MAILLIST", "HAS_LIST_UNSUB"], raw=1.0),
    case("symbole contient trojan", symbols=["HEUR_TROJAN_DROPPER"], raw=1.0),
    case("regles personnalisees : courrier propre", rules=custom_rules()),
    case("regles personnalisees : en masse", rules=custom_rules(), symbols=["MAILLIST", "HAS_LIST_UNSUB"], raw=1.0),
    case("regles personnalisees : finance", rules=custom_rules(), symbols=["R_SPF_FAIL"], raw=2.0),
    case("regles personnalisees : expediteur .xyz", rules=custom_rules(), mime_from="a@promo.xyz", env_from="a@promo.xyz"),
    case("regles personnalisees : score negatif", rules=custom_rules(), raw=-3.0),
]


def main():
    out = {"signals": r.render(r.default_rules(), {"block": [], "safe": []}, TH, True)["signals"], "thresholds": TH, "cases": []}
    for c in CASES:
        rules = r.default_rules() if c["rules"] == "default" else c["rules"]
        i = c["input"]
        ctx = r.build_context(symbols=i["symbols"], raw=i["raw"], th=TH, lists=c["lists"], mime_from=i["mime_from"], env_from=i["env_from"], rcpts=i["rcpts"], ip=i["ip"])
        res = r.evaluate(rules, ctx)
        out["cases"].append({
            "name": c["name"], "rules": copy.deepcopy(rules), "lists": c["lists"], "input": i,
            "expected": {"scores": ctx["scores"], "blocklist": ctx["blocklist"], "safelist": ctx["safelist"],
                         "final": res["final"]["id"] if res["final"] else None, "matched": [x["id"] for x in res["matched"]]},
        })
    (ROOT / "tests" / "data" / "rules_golden.json").write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    for c in out["cases"]:
        e = c["expected"]
        print(f"{c['name']:44} final={e['final']:22} matched={','.join(e['matched'])} bl={e['blocklist']} sl={e['safelist']}")


if __name__ == "__main__":
    main()
