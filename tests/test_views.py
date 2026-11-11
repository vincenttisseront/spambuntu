"""Vues d'analyse : détail d'un message en quarantaine, filtres du journal, trace d'un message."""
import gzip
import json
import subprocess
import time

import pytest

import spambuntu_logs as logs
import spambuntu_quarantine as quar
import spambuntu_symbols as symbols

MIME = (b"From: =?utf-8?Q?Jean_Dupont_-_PDG?= <jean.dupont.ceo@gmail.test>\nTo: compta@exemple.fr\nReply-To: paiements@evil.test\n"
        b"Subject: Virement urgent\nDate: Wed, 11 Nov 2026 10:00:00 +0000\nMessage-ID: <abc@mail.test>\n"
        b"X-Spamd-Result: default: True [14.90 / 15.00];\n\tSPAMBUNTU_VIP_SPOOF(8.00)[Jean_Dupont];\n\tR_SPF_FAIL(1.00)[-all];\n"
        b"\tSPAMBUNTU_AI(5.00)[Fraude au president];\n\tSPAMBUNTU_AI_BEC(0.00)[];\n\tMIME_GOOD(-0.10)[text/html];\n"
        b"Content-Type: multipart/mixed; boundary=XX\n")
BODY = (b"--XX\nContent-Type: text/html; charset=utf-8\n\n<html><body><p>Bonjour,</p><p>Merci de r\xc3\xa9gler la facture.</p>"
        b"<script>alert(1)</script><a href=\"http://evil.test/pay?id=1\">Payer</a> http://autre.test/x</body></html>\n"
        b"--XX\nContent-Type: application/pdf; name=\"facture.pdf\"\nContent-Disposition: attachment; filename=\"facture.pdf\"\n"
        b"Content-Transfer-Encoding: base64\n\nJVBERi0xLjQK\n--XX--\n")


class Run:
    def __init__(self, size=4096, rcpts=("compta@exemple.fr",)):
        self.entry = {"queue_name": "hold", "queue_id": "AAAAAAAAAA1", "arrival_time": 1700000000, "message_size": size,
                      "sender": "jean.dupont.ceo@gmail.test", "recipients": [{"address": r} for r in rcpts]}

    def __call__(self, cmd):
        if cmd[:2] == ["postqueue", "-j"]:
            return subprocess.CompletedProcess(cmd, 0, json.dumps(self.entry).encode(), b"")
        if cmd[:2] == ["postcat", "-qh"]:
            return subprocess.CompletedProcess(cmd, 0, MIME, b"")
        if cmd[:2] == ["postcat", "-qb"]:
            return subprocess.CompletedProcess(cmd, 0, BODY, b"")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")


# ------------------------------------------------------------------ quarantaine : détail

def test_show_gives_the_full_analysis():
    d = quar.show("AAAAAAAAAA1", Run())
    assert d["class"] == "admin" and "Usurpation d'un dirigeant ou d'un nom d'affichage" in d["danger"]
    assert d["score"] == 14.9 and d["reject_limit"] == 15.0
    assert [s["name"] for s in d["symbols"]][:3] == ["SPAMBUNTU_VIP_SPOOF", "SPAMBUNTU_AI", "R_SPF_FAIL"]
    assert d["symbols"][0]["options"] == "Jean_Dupont"
    assert d["ai"] == "Fraude au president" and d["ai_flags"] == ["bec"]
    assert d["headers"]["from"] == "Jean Dupont - PDG <jean.dupont.ceo@gmail.test>" and d["headers"]["reply_to"] == "paiements@evil.test"
    assert d["headers"]["subject"] == "Virement urgent" and d["recipients"] == ["compta@exemple.fr"]


def test_show_preview_is_plain_text_and_links_are_defanged():
    pv = quar.show("AAAAAAAAAA1", Run())["preview"]
    assert "Merci de régler la facture." in pv["text"] and "alert(1)" not in pv["text"] and "<" not in pv["text"]
    assert "hxxp://evil.test/pay?id=1" in pv["links"] and "hxxp://autre.test/x" in pv["links"]
    assert not any(link.startswith("http") for link in pv["links"])
    assert pv["attachments"] == [{"name": "facture.pdf", "type": "application/pdf", "size": 9}]


def test_show_skips_preview_of_huge_messages():
    run = Run(size=quar.PREVIEW_MAX_BYTES + 1)
    pv = quar.show("AAAAAAAAAA1", run)["preview"]
    assert pv["skipped"] and pv["text"] == ""


@pytest.mark.parametrize("bad", ["", "../x", "AAA;id", "ZZZZZZZZZZ9", "A" * 40])
def test_show_refuses_unknown_or_malformed_ids(bad):
    with pytest.raises(quar.QuarantineError):
        quar.show(bad, Run())


def test_user_detail_is_limited_and_only_for_ordinary_messages():
    class Ordinary(Run):
        def __call__(self, cmd):
            if cmd[:2] == ["postcat", "-qh"]:
                return subprocess.CompletedProcess(cmd, 0, b"From: Shop <s@shop.test>\nSubject: Promo\nX-Spamd-Result: default: True [6.00 / 15.00];\n\tBULK_HEADER(1.00)[];\n", b"")
            if cmd[:2] == ["postcat", "-qb"]:
                return subprocess.CompletedProcess(cmd, 0, b"\n" + b"Bonjour " * 200 + b"http://shop.test/x\n", b"")
            return super().__call__(cmd)

    d = quar.show_for_user("AAAAAAAAAA1", "compta@exemple.fr", Ordinary(), max_score=10)
    assert d["subject"] == "Promo" and d["from"] == "Shop <s@shop.test>" and len(d["excerpt"]) <= quar.USER_PREVIEW_CHARS
    assert set(d) == {"id", "from", "subject", "arrived", "size", "single", "excerpt"}        # aucun détail technique
    with pytest.raises(quar.QuarantineError):
        quar.show_for_user("AAAAAAAAAA1", "autre@exemple.fr", Ordinary(), max_score=10)       # pas son message
    with pytest.raises(quar.QuarantineError):
        quar.show_for_user("AAAAAAAAAA1", "compta@exemple.fr", Ordinary(), max_score=5)       # trop suspect
    with pytest.raises(quar.QuarantineError):
        quar.show_for_user("AAAAAAAAAA1", "compta@exemple.fr", Run(), max_score=20)           # classe « admin » : refusé


def test_symbol_descriptions():
    assert symbols.describe("SPAMBUNTU_LOOKALIKE")[0] == "Identité"
    assert symbols.describe("RBL_SPAMHAUS_ZEN")[0] == "Réputation"
    assert symbols.describe("SPAMBUNTU_AI_BEC")[0] == "IA"
    assert symbols.describe("UNKNOWN_THING") == ("Autre", "")
    assert all(cat in symbols.CATEGORIES for cat, _ in symbols._EXACT.values())


# ------------------------------------------------------------------ journal : filtres et trace

def rlog(stamp, sender, rcpt, ip, action, score, qid, mid, syms):
    return (f"{stamp} #1(normal) <a>; task; rspamd_task_write_log: id: <{mid}>, qid: <{qid}>, ip: {ip}, from: <{sender}>, "
            f"(default: T ({action}): [{score}/15.00] [{syms}]), len: 300, time: 12.5ms, dns req: 2, digest: <d>, rcpts: <{rcpt}>, mime_rcpts: <{rcpt}>")


@pytest.fixture
def records():
    now = time.time()
    stamp = lambda ago: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - ago))  # noqa: E731
    lines = [
        rlog(stamp(300), "ceo@gmail.test", "compta@exemple.fr", "203.0.113.9", "quarantine", "14.90", "AAAAAAAAAA1", "m1@x", "SPAMBUNTU_VIP_SPOOF(8.00){J;},R_SPF_FAIL(1.00){-all;},MIME_GOOD(-0.10){}"),
        rlog(stamp(200), "news@shop.test", "marie@exemple.fr", "198.51.100.7", "add header", "5.60", "BBBBBBBBBB2", "m2@x", "BULK_HEADER(1.50){}"),
        rlog(stamp(100), "ok@partner.test", "paul@exemple.fr", "198.51.100.8", "no action", "0.40", "CCCCCCCCCC3", "m3@x", "MIME_GOOD(-0.10){}"),
        rlog(stamp(50), "x@spam.test", "marie@exemple.fr", "192.0.2.50", "reject", "21.00", "", "m4@x", "RBL_SPAMHAUS(5.00){}"),
    ]
    return [logs.parse_line(x) for x in lines]


def names(found):
    return [r["sender"] for r in found]


def test_search_filters_combine(records):
    assert names(logs.search(records, sender="gmail")) == ["ceo@gmail.test"]
    assert names(logs.search(records, rcpt="marie")) == ["x@spam.test", "news@shop.test"]
    assert names(logs.search(records, ip="198.51.100")) == ["ok@partner.test", "news@shop.test"]
    assert names(logs.search(records, symbol="vip_spoof")) == ["ceo@gmail.test"]
    assert names(logs.search(records, symbol="MIME_GOOD")) == ["ok@partner.test", "ceo@gmail.test"]         # règle de poids < 1 aussi
    assert names(logs.search(records, min_score=5, max_score=15)) == ["news@shop.test", "ceo@gmail.test"]
    assert names(logs.search(records, action="rejected", rcpt="marie", min_score=20)) == ["x@spam.test"]
    assert names(logs.search(records, query="m3@x")) == ["ok@partner.test"]                                  # recherche par Message-ID
    assert logs.search(records, sender="gmail", rcpt="paul") == []


def test_list_records_stay_compact(records):
    assert all("sym_all" not in r and "limit" not in r for r in logs.search(records))


def test_trace_returns_all_rules_sorted_and_options(records):
    t = logs.trace(records, "AAAAAAAAAA1", 24, mail_log=None or logs.MAIL_LOG.with_name("absent.log"))
    v = t["verdicts"][0]
    assert [s["name"] for s in v["sym_all"]] == ["SPAMBUNTU_VIP_SPOOF", "R_SPF_FAIL", "MIME_GOOD"]
    assert v["sym_all"][0]["options"] == "J;" and v["limit"] == 15.0 and v["time_ms"] == 12.5
    assert logs.trace(records, "m4@x", 24, mail_log=logs.MAIL_LOG.with_name("absent.log"))["verdicts"][0]["sender"] == "x@spam.test"   # sans qid : par Message-ID
    assert logs.trace(records, "inconnu", 24)["verdicts"] == []


def test_trace_reads_postfix_delivery_steps(records, tmp_path):
    year = time.localtime().tm_year
    log = tmp_path / "mail.log"
    stamp = time.strftime("%b %d %H:%M:%S", time.localtime(time.time() - 250))
    log.write_text(f"{stamp} gw postfix/smtpd[10]: AAAAAAAAAA1: client=mx.x.test[203.0.113.9]\n"
                   f"{stamp} gw postfix/qmgr[11]: AAAAAAAAAA1: from=<ceo@gmail.test>, size=300, nrcpt=1 (queue active)\n"
                   f"{stamp} gw postfix/smtp[12]: AAAAAAAAAA1: to=<compta@exemple.fr>, relay=mail.exemple.fr[10.0.0.5]:25, delay=0.4, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 77)\n"
                   f"{stamp} gw postfix/smtp[12]: BBBBBBBBBB2: to=<autre@exemple.fr>, relay=none, status=deferred (connect refused)\n")
    t = logs.trace(records, "AAAAAAAAAA1", 24, mail_log=log)
    sent = [d for d in t["delivery"] if d["status"] == "sent"][0]
    assert sent["to"] == "compta@exemple.fr" and sent["relay"].startswith("mail.exemple.fr") and sent["dsn"] == "2.0.0"
    assert "queued as 77" in sent["detail"] and len(t["delivery"]) == 3 and all(d["to"] != "autre@exemple.fr" for d in t["delivery"])
    assert year >= 2026


def test_cli_search_validates_every_filter(capsys):
    for flag in ("--sender", "--rcpt", "--ip", "--symbol"):
        assert logs.main(["search", flag, "x;rm -rf /"]) == 1
    assert logs.main(["trace", "a b;c"]) == 1
    capsys.readouterr()


def test_postfix_iso_timestamps(tmp_path):
    log = tmp_path / "mail.log"
    log.write_text("2026-11-11T14:41:02.123456+01:00 gw postfix/smtp[12]: AAAAAAAAAA1: to=<a@b.fr>, relay=r.fr[1.2.3.4]:25, delay=1, dsn=2.0.0, status=sent (ok)\n")
    out = logs.read_delivery("AAAAAAAAAA1", 24 * 365, now=time.mktime((2026, 11, 12, 0, 0, 0, 0, 0, -1)), mail_log=log)
    assert out and out[0]["ts"] > 0 and out[0]["status"] == "sent"


# ------------------------------------------------------------------ pages de la console

import spambuntu_digest as dg  # noqa: E402
import listing  # noqa: E402
from test_mail import mailweb  # noqa: E402,F401  (fixture)
from test_webui import auth, csrf, web  # noqa: E402,F401  (fixtures)

NOW = int(time.time())


def msgs():
    base = {"size": 2048, "symbols": [], "ai": "", "ai_flags": []}
    return [
        {**base, "id": "AAAAAAAAAA1", "class": "admin", "danger": ["Hameçonnage"], "sender": "x@evil.test", "from": "Banque <x@evil.test>", "recipients": ["marie@exemple.fr"],
         "arrived": NOW - 600, "subject": "Compte suspendu", "score": 14.0, "symbols": ["PHISHED_X", "R_SPF_FAIL"]},
        {**base, "id": "BBBBBBBBBB2", "class": "admin", "danger": ["Usurpation d'identité", "Demande de paiement"], "sender": "ceo@gmail.test", "from": "PDG", "recipients": ["compta@exemple.fr", "paul@exemple.fr"],
         "arrived": NOW - 7200, "subject": "Virement urgent", "score": 9.0, "symbols": ["SPAMBUNTU_VIP_SPOOF"]},
        {**base, "id": "CCCCCCCCCC3", "class": "user", "danger": [], "sender": "news@shop.test", "from": "Shop <news@shop.test>", "recipients": ["marie@exemple.fr"],
         "arrived": NOW - 86400 * 3, "subject": "<b>Promo</b> -30%", "score": 6.0, "symbols": ["BULK_HEADER"]},
        {**base, "id": "DDDDDDDDDD4", "class": "user", "danger": [], "sender": "voyages@trip.test", "from": "Trip", "recipients": ["paul@exemple.fr"],
         "arrived": NOW - 86400 * 40, "subject": "Lisbonne", "score": 4.5, "symbols": []},
    ]


@pytest.fixture
def q(mailweb):
    mailweb.calls = []

    def runner(args):
        mailweb.calls.append(args)
        if args[0] == "list":
            return {"ok": True, "messages": msgs()}
        if args[0] == "show":
            detail = quar.show("AAAAAAAAAA1", Run())
            if "--recipient" in args:
                return {"ok": False, "error": "Ce message n'est pas accessible depuis votre espace"}
            return {"ok": True, "message": detail}
        if args[0] == "release" and "CCCCCCCCCC3" not in args and "--confirm-danger" not in args:
            return {"ok": False, "error": "Message à risque : confirmez la libération après analyse"}
        return {"ok": True, "message": "Message libéré et remis en livraison"}

    mailweb.app.config["QUARANTINE_RUNNER"] = runner
    return mailweb


def page(q, url):
    return q.client.get(url).get_data(as_text=True)


def test_quarantine_list_is_compact_with_one_row_per_message(q):
    html = page(q, "/quarantaine?vue=tout")
    assert html.count("<tr class=\"risk-") == 4 and "Analyser ce message" in html
    assert html.index("Compte suspendu") < html.index("Promo")                             # risque d'abord
    assert "&lt;b&gt;Promo&lt;/b&gt;" in html and "<b>Promo</b>" not in html              # contenu échappé
    assert "/quarantaine/message/AAAAAAAAAA1" in html


@pytest.mark.parametrize("query,present,absent", [
    ("vue=tout&q=virement", "Virement urgent", "Compte suspendu"),
    ("vue=tout&dest=paul", "Virement urgent", "Compte suspendu"),
    ("vue=tout&exp=shop.test", "Promo", "Virement urgent"),
    ("vue=risque&motif=Hameçonnage", "Compte suspendu", "Virement urgent"),
    ("vue=tout&regle=vip_spoof", "Virement urgent", "Compte suspendu"),
    ("vue=tout&smin=8", "Compte suspendu", "Promo"),
    ("vue=tout&smax=5", "Lisbonne", "Compte suspendu"),
    ("vue=tout&periode=24h", "Compte suspendu", "Promo"),
    ("vue=tout&periode=7j", "Promo", "Lisbonne"),
])
def test_quarantine_filters(q, query, present, absent):
    html = page(q, "/quarantaine?" + query)
    assert present in html and absent not in html


def test_quarantine_sort_by_score_and_empty_state(q):
    html = page(q, "/quarantaine?vue=tout&tri=score")
    assert html.index("Compte suspendu") < html.index("Virement urgent") < html.index("Promo") < html.index("Lisbonne")
    assert "Aucun message ne correspond" in page(q, "/quarantaine?q=introuvable")


def test_quarantine_filter_inputs_are_sanitized(q):
    html = page(q, "/quarantaine?vue=zzz&periode=zzz&tri=zzz&smin=abc&page=-4&q=%3Cscript%3E")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_pagination_helpers():
    items = list(range(120))
    chunk, pg = listing.paginate(items, 3)
    assert chunk[0] == 100 and pg == {"page": 3, "pages": 3, "total": 120, "first": 101, "last": 120}
    assert listing.paginate(items, 99)[1]["page"] == 3 and listing.paginate([], 1)[1]["pages"] == 1
    g = listing.gauge(14.0, {"tag": 5, "quarantine": 8, "reject": 15})
    assert 0 < g["tag"] < g["quarantine"] < g["reject"] < g["width"] and 0 < g["score"] < g["width"]


def test_quarantine_detail_shows_the_analysis_and_keeps_filters(q):
    html = page(q, "/quarantaine/message/AAAAAAAAAA1?vue=tout&q=virement")
    assert "Virement urgent" in html and "SPAMBUNTU_VIP_SPOOF" in html and "+8.00" in html and "Le nom d&#39;affichage est celui d&#39;un dirigeant" in html
    assert "Usurpation d&#39;un dirigeant ou d&#39;un nom d&#39;affichage" in html               # motifs de risque
    assert "Fraude au president" in html and "hxxp://evil.test/pay?id=1" in html and "facture.pdf" in html
    assert "<script>alert" not in html and 'href="http://evil.test' not in html                # rien d'actif, aucun lien cliquable
    assert 'name="confirm" required' in html and "Libérer après analyse" in html and "Légitime : libérer" not in html
    assert 'name="q" value="virement"' in html and "vue=tout" in html                           # retour à la liste avec les mêmes filtres
    assert q.calls[-1] == ["show", "AAAAAAAAAA1"]


def test_quarantine_detail_refuses_bad_ids(q):
    assert q.client.get("/quarantaine/message/..%2Fetc").status_code == 404
    assert q.client.get("/quarantaine/message/AAA;id").status_code == 404


def test_quarantine_actions_return_to_the_filtered_list(q):
    token = csrf(q.client, "/quarantaine")
    res = q.client.post("/quarantaine/delete", data={"queue_id": "AAAAAAAAAA1", "learn": "1", "vue": "tout", "q": "x", "csrf_token": token})
    assert res.status_code == 302 and "vue=tout" in res.headers["Location"] and "q=x" in res.headers["Location"]


def test_bulk_actions_apply_to_selected_messages(q):
    token = csrf(q.client, "/quarantaine")
    res = q.client.post("/quarantaine/lot", data={"action": "delete", "learn": "1", "queue_id": ["CCCCCCCCCC3", "DDDDDDDDDD4"], "vue": "ordinaire", "csrf_token": token},
                        follow_redirects=True)
    assert "2 message(s) supprimé(s)" in res.get_data(as_text=True)
    assert [c[:2] for c in q.calls if c[0] == "delete"] == [["delete", "CCCCCCCCCC3"], ["delete", "DDDDDDDDDD4"]]
    assert all("--learn" in c for c in q.calls if c[0] == "delete")


def test_bulk_release_cannot_override_the_danger_confirmation(q):
    token = csrf(q.client, "/quarantaine")
    res = q.client.post("/quarantaine/lot", data={"action": "release", "queue_id": ["AAAAAAAAAA1"], "csrf_token": token}, follow_redirects=True)
    assert "refusé" in res.get_data(as_text=True)
    assert not any("--confirm-danger" in c for c in q.calls)


@pytest.mark.parametrize("data", [{"action": "release"}, {"action": "format", "queue_id": "AAAAAAAAAA1"}, {"action": "delete", "queue_id": "x;y"}])
def test_bulk_rejects_bad_requests(q, data):
    token = csrf(q.client, "/quarantaine")
    res = q.client.post("/quarantaine/lot", data={**data, "csrf_token": token}, follow_redirects=True)
    assert "Sélectionnez au moins un message" in res.get_data(as_text=True)
    assert not any(c[0] in ("release", "delete") for c in q.calls)


def test_bulk_requires_csrf_and_login(q):
    assert q.client.post("/quarantaine/lot", data={"action": "delete", "queue_id": "CCCCCCCCCC3"}).status_code == 403
    anonymous = q.app.test_client()
    assert anonymous.post("/quarantaine/lot", data={}).status_code in (302, 403)
    assert anonymous.get("/quarantaine/message/AAAAAAAAAA1").status_code == 302
    assert anonymous.get("/journal/trace?id=AAAAAAAAAA1").status_code == 302


# ---- journal

@pytest.fixture
def j(mailweb):
    mailweb.stats = []

    def runner(args):
        mailweb.stats.append(args)
        if args[0] == "search":
            return {"ok": True, "records": [{"ts": NOW - 60, "category": "quarantined", "score": 14.9, "qid": "AAAAAAAAAA1", "mid": "m1@x", "ip": "203.0.113.9",
                                             "sender": "ceo@gmail.test", "rcpts": ["a@exemple.fr", "b@exemple.fr"], "symbols": ["R1", "R2", "R3", "R4"]},
                                            {"ts": NOW - 30, "category": "rejected", "score": 21.0, "qid": "", "mid": "m2@x", "ip": "192.0.2.5", "sender": "x@spam.test", "rcpts": [], "symbols": []}]}
        return {"ok": True, "verdicts": [{"ts": NOW, "category": "quarantined", "action": "quarantine", "score": 14.9, "limit": 15.0, "sender": "ceo@gmail.test", "rcpts": ["a@exemple.fr"],
                                          "ip": "203.0.113.9", "size": 300, "time_ms": 12.5, "qid": "AAAAAAAAAA1", "mid": "m1@x",
                                          "sym_all": [{"name": "SPAMBUNTU_VIP_SPOOF", "score": 8.0, "options": "Jean_Dupont"}, {"name": "MIME_GOOD", "score": 0.0, "options": ""}]}],
                "delivery": [{"ts": NOW, "component": "smtp", "to": "a@exemple.fr", "relay": "mail.exemple.fr[10.0.0.5]:25", "dsn": "2.0.0", "status": "sent", "detail": "250 ok"}]}

    mailweb.app.config["STATS_RUNNER"] = runner
    return mailweb


def test_journal_list_is_compact_and_links_to_the_trace(j):
    html = page(j, "/journal")
    assert html.count("Parcours</a>") == 2 and "/journal/trace?id=AAAAAAAAAA1" in html and "id=m2@x" in html       # sans file Postfix : par Message-ID
    assert "+1" in html and "R4" not in html.split("<tbody>")[1].split("R3")[0] and "a@exemple.fr" in html


def test_journal_advanced_filters_reach_the_runner(j):
    page(j, "/journal?q=a&action=rejected&hours=72&sender=gmail&rcpt=marie&ip=203.0.113&regle=r_spf&smin=5&smax=20")
    assert j.stats[-1] == ["search", "--hours", "72", "--limit", "500", "--q", "a", "--sender", "gmail", "--rcpt", "marie", "--ip", "203.0.113",
                           "--symbol", "r_spf", "--action", "rejected", "--min-score", "5.0", "--max-score", "20.0"]


def test_journal_rejects_unsafe_filters(j):
    for field in ("sender", "rcpt", "ip", "regle"):
        html = page(j, f"/journal?{field}=a;b|c")
        assert "Recherche invalide" in html
    assert all("a;b|c" not in " ".join(c) for c in j.stats)


def test_journal_trace_page(j):
    html = page(j, "/journal/trace?id=AAAAAAAAAA1")
    assert "SPAMBUNTU_VIP_SPOOF" in html and "+8.00" in html and "Jean_Dupont" in html and "MIME_GOOD" not in html.split("Livraison")[0].split("<tbody>")[1].split("</tbody>")[0]
    assert "mail.exemple.fr" in html and "sent" in html and j.stats[-1] == ["trace", "AAAAAAAAAA1"]
    assert j.client.get("/journal/trace?id=a b").status_code == 404
    assert j.client.get("/journal/trace").status_code == 404


# ---- espace utilisateur

@pytest.fixture
def u(q):
    q.token = lambda: dg.make_token(q.app.config["SECRET_KEY"], "-", "marie@exemple.fr", scope="l")
    return q


def test_user_list_filters_and_detail_link(u):
    client = u.app.test_client()
    html = client.get(f"/mes-messages/{u.token()}").get_data(as_text=True)
    assert "/message/" in html and "Libérer</button>" in html
    assert "Aucun message ne correspond" in client.get(f"/mes-messages/{u.token()}?q=zzz").get_data(as_text=True)
    only = client.get(f"/mes-messages/{u.token()}?q=lisbonne").get_data(as_text=True)
    assert "Lisbonne" in only and "Compte suspendu" not in only
    recent = client.get(f"/mes-messages/{u.token()}?periode=7j").get_data(as_text=True)
    assert "Lisbonne" not in recent and "Compte suspendu" in recent


def test_user_detail_is_scoped_and_never_technical(u):
    client = u.app.test_client()
    res = client.get(f"/mes-messages/{u.token()}/message/AAAAAAAAAA1")
    assert res.status_code == 302                                                       # le runner refuse : message à risque
    assert u.calls[-1][:2] == ["show", "AAAAAAAAAA1"] and "--recipient" in u.calls[-1] and "--max-score" in u.calls[-1]
    assert client.get(f"/mes-messages/{u.token()}/message/AAA;id").status_code == 404
    assert client.get("/mes-messages/forge/message/AAAAAAAAAA1").status_code == 400
