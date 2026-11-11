"""Statistiques et recherche dans le journal de Rspamd, et pages « tableau de bord » / « journal »."""
import gzip
import time

import pytest

import spambuntu_logs as logs
from test_mail import mailweb  # noqa: F401  (fixture)
from test_webui import auth, csrf, web  # noqa: F401  (fixtures)

SAMPLE = ("{stamp} #123(normal) <abc>; task; rspamd_task_write_log: id: <2026@vm>, qid: <6F8891904D5>, ip: 192.0.2.2, "
          "from: <{sender}>, (default: T (quarantine): [9.40/15.00] [QTEST(9.00){{}},MID_RHS_NOT_FQDN(0.50){{}},"
          "FROM_NO_DN(1.20){{}}]), len: 253, time: 2.5ms, dns req: 3, digest: <abc>, rcpts: <{rcpt}>, mime_rcpts: <{rcpt}>")


def line(sender="a@outside.test", rcpt="user@example.com", when=None, action="quarantine", flag="T", score="9.40"):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(when or time.time() - 60))
    text = SAMPLE.format(stamp=stamp, sender=sender, rcpt=rcpt)
    return text.replace("T (quarantine): [9.40", f"{flag} ({action}): [{score}")


def test_parse_real_line():
    rec = logs.parse_line(line())
    assert rec["category"] == "quarantined" and rec["score"] == 9.4 and rec["limit"] == 15.0
    assert rec["sender"] == "a@outside.test" and rec["rcpts"] == ["user@example.com"]
    assert rec["qid"] == "6F8891904D5" and rec["ip"] == "192.0.2.2" and rec["size"] == 253
    assert rec["symbols"] == ["QTEST", "FROM_NO_DN"]          # seules les règles pesant au moins 1 point


def test_parse_ignores_other_lines():
    assert logs.parse_line("2026-11-11 12:00:00 #1(main) <x>; main; something else") is None
    assert logs.parse_line("") is None


def test_categories():
    for action, cat in (("no action", "delivered"), ("add header", "tagged"), ("reject", "rejected"), ("soft reject", "deferred")):
        assert logs.parse_line(line(action=action))["category"] == cat


def make_log(tmp_path):
    cur = tmp_path / "rspamd.log"
    cur.write_text("\n".join([line("new@x.test", action="reject"), line("ok@y.test", action="no action", score="0.1"), "bruit"]) + "\n")
    old = tmp_path / "rspamd.log.2.gz"
    with gzip.open(old, "wt") as fh:
        fh.write(line("old@z.test", when=time.time() - 3600 * 30) + "\n")
    return cur


def test_read_rotated_and_window(tmp_path):
    cur = make_log(tmp_path)
    assert len(logs.read_records(24, log_file=cur)) == 2
    senders = {r["sender"] for r in logs.read_records(72, log_file=cur)}
    assert senders == {"new@x.test", "ok@y.test", "old@z.test"}


def test_summary_and_search(tmp_path):
    recs = logs.read_records(72, log_file=make_log(tmp_path))
    s = logs.summarize(recs, 72)
    assert s["total"] == 3 and s["counts"]["rejected"] == 1 and s["counts"]["quarantined"] == 1 and s["counts"]["delivered"] == 1
    assert sum(sum(b[c] for c in logs.CATEGORIES) for b in s["timeline"]) == 3
    assert {t["name"] for t in s["top_sender_domains"]} == {"x.test", "z.test"}
    assert [r["sender"] for r in logs.search(recs, "Z.TEST")] == ["old@z.test"]
    assert [r["category"] for r in logs.search(recs, action="rejected")] == ["rejected"]
    assert len(logs.search(recs, limit=1)) == 1


def test_cli_rejects_bad_query(capsys):
    assert logs.main(["search", "--q", "a;rm -rf /"]) == 1
    assert "invalide" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        logs.main(["search", "--action", "nimportequoi"])


def test_cli_missing_log(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(logs, "LOG_FILE", tmp_path / "absent.log")
    monkeypatch.setattr(logs, "read_records", lambda hours, **k: [])
    assert logs.main(["summary", "--hours", "99999"]) == 0
    assert '"total": 0' in capsys.readouterr().out


@pytest.fixture
def statsweb(mailweb):
    calls = mailweb.stats_calls = []

    def runner(args):
        calls.append(args)
        if args[0] == "summary":
            return {"ok": True, "total": 3, "counts": {c: 1 for c in logs.CATEGORIES}, "step": 3600,
                    "timeline": [{"start": 1700000000, **{c: 2 for c in logs.CATEGORIES}}],
                    "top_sender_domains": [{"name": "<b>evil</b>.test", "count": 2}], "top_ips": [], "top_symbols": [{"name": "QTEST", "count": 1}]}
        return {"ok": True, "records": [{"ts": 1700000000, "category": "rejected", "score": 20.0, "sender": "<script>x</script>@e.test",
                                         "rcpts": ["a@b.test"], "ip": "1.2.3.4", "symbols": ["QTEST"]}]}

    mailweb.app.config["STATS_RUNNER"] = runner
    return mailweb


def test_dashboard(statsweb):
    html = statsweb.client.get("/").get_data(as_text=True)
    assert "<rect" in html and "analysés" in html
    assert "<b>evil</b>" not in html and "&lt;b&gt;evil" in html
    assert statsweb.stats_calls[0] == ["summary", "--hours", "24"]


def test_dashboard_without_stats(statsweb):
    statsweb.app.config["STATS_RUNNER"] = lambda args: {"ok": False, "error": "x"}
    assert "Statistiques indisponibles" in statsweb.client.get("/").get_data(as_text=True)


def test_journal_page(statsweb):
    html = statsweb.client.get("/journal?q=e.test&action=rejected&hours=72").get_data(as_text=True)
    assert "<script>x" not in html and "&lt;script&gt;" in html
    assert statsweb.stats_calls[-1] == ["search", "--hours", "72", "--limit", "500", "--q", "e.test", "--action", "rejected"]


def test_journal_sanitizes_input(statsweb):
    html = statsweb.client.get("/journal?q=a;b|c&action=x&hours=99999").get_data(as_text=True)
    assert "Recherche invalide" in html
    assert statsweb.stats_calls[-1] == ["search", "--hours", "24", "--limit", "500"]


def test_journal_requires_login(web):
    assert web.client.get("/journal").status_code == 302
