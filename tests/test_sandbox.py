"""Sandbox passerelle : extraction, analyse statique, verdict, cache."""
import email.message
import io
import zipfile

import pytest

import spambuntu_sandbox as sb

CFG = sb.validate_config({"mode": "enforce"})


def mail(*attachments, body="Bonjour"):
    m = email.message.EmailMessage()
    m["From"], m["To"], m["Subject"] = "a@x.fr", "b@y.fr", "test"
    m.set_content(body)
    for name, data in attachments:
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return m.as_bytes()


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in files.items():
            z.writestr(n, d)
    return buf.getvalue()


def docm(extra=None):
    files = {"[Content_Types].xml": "<x/>", "word/document.xml": "<w/>", "word/vbaProject.bin": b"AutoOpen CreateObject WScript.Shell"}
    files.update(extra or {})
    return zipped(files)


def test_config_defaults_and_validation():
    assert sb.validate_config({})["mode"] == "off"
    for bad in ({"mode": "x"}, {"zzz": 1}, {"max_parts": 0}, {"max_parts": True}, {"eligible_types": ["nope"]},
                {"suspicious_at": 90, "malicious_at": 80}, [], {"eligible_types": "pdf"}):
        with pytest.raises(sb.SandboxError):
            sb.validate_config(bad)


def test_load_config_falls_back_to_off(tmp_path):
    assert sb.load_config(tmp_path / "absent.json")["mode"] == "off"
    p = tmp_path / "bad.json"
    p.write_text("{oops")
    assert sb.load_config(p)["mode"] == "off"


def test_off_mode_does_nothing():
    r = sb.analyze_message(mail(("a.exe", b"MZ" + b"\0" * 100)), sb.validate_config({}))
    assert r["verdict"] == "none" and r["symbols"] == []


def test_no_attachment_is_none():
    assert sb.analyze_message(mail(), CFG)["verdict"] == "none"


def test_eicar_is_malicious():
    r = sb.analyze_message(mail(("t.txt", sb.EICAR)), CFG)
    assert r["verdict"] == "malicious" and r["symbols"] == ["SPAMBUNTU_SANDBOX_MALICIOUS"]


def test_macro_document_is_suspicious_or_worse():
    r = sb.analyze_message(mail(("facture.docm", docm())), CFG)
    codes = {f["code"] for f in r["findings"]}
    assert {"macro", "autoexec", "macro_risk"} <= codes
    assert r["verdict"] == "malicious" and r["score"] >= 95


def test_plain_macro_only_is_below_malicious():
    data = zipped({"[Content_Types].xml": "<x/>", "word/document.xml": "<w/>", "word/vbaProject.bin": b"nothing"})
    r = sb.analyze_message(mail(("a.docm", data)), CFG)
    assert r["verdict"] == "none" or r["score"] < 95
    assert any(f["code"] == "macro" for f in r["findings"])


def test_clean_pdf_and_dangerous_pdf():
    assert sb.analyze_message(mail(("a.pdf", b"%PDF-1.4\n1 0 obj<<>>endobj")), CFG)["verdict"] == "clean"
    r = sb.analyze_message(mail(("a.pdf", b"%PDF-1.4\n/OpenAction /JavaScript /Launch")), CFG)
    assert r["verdict"] in ("suspicious", "malicious")


def test_extension_lies_about_content():
    r = sb.analyze_message(mail(("facture.pdf", b"MZ" + b"\0" * 200)), CFG)
    codes = {f["code"] for f in r["findings"]}
    assert "executable" in codes and "type_mismatch" in codes and r["verdict"] == "malicious"


def test_double_extension_in_zip():
    r = sb.analyze_message(mail(("a.zip", zipped({"facture.pdf.exe": b"MZ"}))), CFG)
    assert any(f["code"] == "double_extension" for f in r["findings"])
    assert r["verdict"] == "malicious"


def test_encrypted_zip_flagged():
    data = bytearray(zipped({"a.txt": b"hello"}))
    # force le drapeau de chiffrement dans l'en-tête local et central
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = data.find(sig)
        off = i + (6 if sig == b"PK\x03\x04" else 8)
        data[off] |= 1
    r = sb.analyze_message(mail(("a.zip", bytes(data))), CFG)
    assert any(f["code"] == "archive_encrypted" for f in r["findings"])


def test_script_and_lnk_and_html_smuggling():
    r = sb.analyze_message(mail(("a.js", b"var s=new ActiveXObject('WScript.Shell');")), CFG)
    assert r["verdict"] in ("suspicious", "malicious")
    html = b"<html><script>var b=new Blob([atob('AAAA')]);a.href=URL.createObjectURL(b);a.download='x.exe'</script></html>"
    r = sb.analyze_message(mail(("a.html", html)), CFG)
    assert any(f["code"] == "html_smuggling" for f in r["findings"])


def test_zip_bomb_not_opened():
    cfg = sb.validate_config({"mode": "enforce", "max_expand_mb": 1})
    r = sb.analyze_message(mail(("a.zip", zipped({"big.bin": b"\0" * 3_000_000}))), cfg)
    assert any(f["code"] == "archive_bomb" for f in r["findings"])


def test_nesting_depth_bounded():
    inner = zipped({"x.exe": b"MZ"})
    for _ in range(5):
        inner = zipped({"n.zip": inner})
    r = sb.analyze_message(mail(("a.zip", inner)), CFG)
    assert any(f["code"] == "archive_deep" for f in r["findings"])


def test_type_filter_respected():
    cfg = sb.validate_config({"mode": "enforce", "eligible_types": ["pdf"]})
    r = sb.analyze_message(mail(("a.exe", b"MZ" + b"\0" * 100)), cfg)
    assert r["verdict"] == "none"


def test_oversize_part_not_analyzed():
    cfg = sb.validate_config({"mode": "enforce", "max_file_mb": 1})
    r = sb.analyze_message(mail(("a.bin", b"MZ" + b"\0" * 1_500_000)), cfg)
    assert r["parts"][0]["analyzed"] is False and r["verdict"] == "none"


def test_part_count_truncated():
    cfg = sb.validate_config({"mode": "enforce", "max_parts": 2})
    r = sb.analyze_message(mail(*[(f"{i}.txt", b"x") for i in range(5)]), cfg)
    assert len(r["parts"]) == 2 and r["truncated"] is True


def test_urls_extracted_and_normalized():
    r = sb.analyze_message(mail(("a.pdf", b"%PDF-1.4"), body="Voir HTTP://Exemple.COM/a?b=1#frag, merci"), CFG)
    assert r["urls"] == ["http://exemple.com/a?b=1"]


def test_fuse_and_verdict():
    assert sb.fuse([]) == 0 and sb.fuse([0, 0]) == 0
    assert sb.fuse([50, 30]) == 60 and sb.fuse([95, 95, 95, 95]) == 100
    assert sb.verdict_for(60, CFG) == "suspicious" and sb.verdict_for(95, CFG) == "malicious" and sb.verdict_for(10, CFG) == "clean"


def test_cache_hit_and_ttl(tmp_path):
    cache = sb.VerdictCache(tmp_path / "c.db")
    raw = mail(("a.pdf", b"%PDF-1.4\n/JavaScript"))
    first = sb.analyze_message(raw, CFG, cache)
    second = sb.analyze_message(raw, CFG, cache)
    assert first["cached"] == 0 and second["cached"] == 1 and second["score"] == first["score"]
    cache.put("k", {"a": 1}, 1, now=1000)
    assert cache.get("k", now=1000 + 3599) == {"a": 1} and cache.get("k", now=1000 + 3600) is None


def test_cache_unusable_path_is_harmless(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    cache = sb.VerdictCache(f / "sub" / "c.db")
    assert cache.get("k") is None
    cache.put("k", 1, 1)
    assert sb.analyze_message(mail(("a.pdf", b"%PDF-1.4")), CFG, cache)["verdict"] == "clean"


def test_garbage_input_never_raises():
    for raw in (b"", b"\xff\xfe\x00garbage", b"Content-Type: multipart/mixed; boundary=x\n\n--x\n"):
        assert sb.analyze_message(raw, CFG)["verdict"] in ("none", "clean")


def test_cli(tmp_path, monkeypatch, capsys):
    cfgp = tmp_path / "s.json"
    cfgp.write_text('{"mode": "monitor"}')
    monkeypatch.setattr(sb, "CONFIG_PATH", str(cfgp))
    assert sb.main(["check"]) == 0
    cfgp.write_text('{"mode": "bad"}')
    assert sb.main(["check"]) == 1


# --------------------------------------------------------------------------- service local et installation

def test_daemon_handle_audits_without_content(tmp_path):
    import json
    import spambuntu_sandboxd as d
    log = tmp_path / "audit.jsonl"
    r = d.handle(mail(("t.txt", sb.EICAR)), "AB12-x", sb.VerdictCache(tmp_path / "c.db"), CFG, str(log))
    assert r["verdict"] == "malicious" and r["symbols"] == ["SPAMBUNTU_SANDBOX_MALICIOUS"]
    line = json.loads(log.read_text())
    assert line["queue_id"] == "AB12-x" and line["parts"][0]["sha256"] and "data" not in json.dumps(line)


def test_daemon_off_and_failure_never_block(tmp_path, monkeypatch):
    import spambuntu_sandboxd as d
    assert d.handle(mail(("a.exe", b"MZ")), cfg=sb.validate_config({}), log=str(tmp_path / "l"))["verdict"] == "none"
    monkeypatch.setattr(sb, "analyze_message", lambda *a, **k: 1 / 0)
    r = d.handle(b"x", cfg=CFG, log=str(tmp_path / "l"))
    assert r["verdict"] == "error" and r["symbols"] == ["SPAMBUNTU_SANDBOX_ERROR"]


def test_rules_and_symbols_know_the_sandbox():
    import spambuntu_rules as rules
    import spambuntu_symbols as symbols
    names = {n for items in rules.SIGNALS.values() for _, n, _ in items}
    for sym in ("SPAMBUNTU_SANDBOX_MALICIOUS", "SPAMBUNTU_SANDBOX_SUSPICIOUS", "SPAMBUNTU_SANDBOX_URL_MALICIOUS"):
        assert sym in names
    assert symbols.describe("SPAMBUNTU_SANDBOX_MALICIOUS")[0] == "Sandbox" if hasattr(symbols, "describe") else True


def test_gateway_wiring_files():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent / "appliance"
    install = (root / "install.sh").read_text()
    assert "spambuntu_sandbox.lua" in install and "spambuntu-sandboxd" in install and "install_sandboxd" in install
    unit = (root / "systemd/spambuntu-sandboxd.service").read_text()
    assert "User=spambuntu-sandboxd" in unit and "RestrictAddressFamilies=AF_INET AF_UNIX" in unit
    mig = (root / "hooks/migrations/0006-sandbox.sh").read_text()
    assert "spambuntu_sandbox.lua" in mig and '"mode": "off"' in mig
    assert "127.0.0.1:11341" in (root / "sandbox/rspamd/spambuntu_sandbox.lua").read_text()
