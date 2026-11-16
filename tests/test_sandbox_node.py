"""Rôle « sandbox » : installation, mises à jour, ISO à deux entrées, contrôles et pare-feu du nœud."""
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

import spambuntu_sandbox_node as node
from conftest import ROOT
from test_tooling import build, repo_copy, run  # noqa: F401  (fixture repo_copy)


def _extract(repo_copy, tmp_path, version="0.4.0"):
    bundle = build(repo_copy, version, tmp_path / "out")
    extract = tmp_path / "extract"
    with tarfile.open(bundle) as tar:
        tar.extractall(extract, filter="data")
    return extract / f"spambuntu-{version}" / "install.sh"


def _install(script, dest, *args, check=True):
    return run(["bash", str(script), "--no-start", *args], env={"DESTDIR": str(dest)}, check=check)


# ------------------------------------------------------------------ install.sh --role

def test_sandbox_role_installs_only_the_worker_parts(repo_copy, tmp_path):
    script = _extract(repo_copy, tmp_path)
    dest = tmp_path / "dest"
    r = _install(script, dest, "--role", "sandbox")
    assert "rôle : sandbox" in r.stdout
    assert (dest / "etc/spambuntu/role").read_text() == "sandbox\n"
    units = {p.name for p in (dest / "etc/systemd/system").iterdir()}
    assert units == {"spambuntu-sandbox-firewall.service"}                  # ni console, ni messagerie, ni IA
    assert not (dest / "etc/sudoers.d").exists() or not any((dest / "etc/sudoers.d").iterdir())   # aucun droit délégué
    assert not (dest / "etc/spambuntu/webui.json").exists()                 # pas de console, donc pas de mot de passe
    assert not (dest / "etc/spambuntu/tls").exists()
    assert (dest / "usr/local/sbin/spambuntu-sandbox").read_text().count("spambuntu_sandbox_node.py") == 1
    assert (dest / "usr/local/sbin/spambuntu-update").is_file()
    assert not (dest / "usr/local/sbin/spambuntu-mail").exists()
    assert oct((dest / "etc/spambuntu/sandbox").stat().st_mode & 0o777) == "0o700"     # clé d'appairage
    assert oct((dest / "var/lib/spambuntu/sandbox/images").stat().st_mode & 0o777) == "0o750"
    conf = (dest / "etc/spambuntu/update.conf").read_text()
    assert re.search(r"^restart_units =\s*$", conf, re.M) and "health_url = none" in conf
    assert (dest / "opt/spambuntu/current/sandbox/spambuntu_sandbox_node.py").is_file()


def test_gateway_role_is_the_default_and_is_recorded(repo_copy, tmp_path):
    script = _extract(repo_copy, tmp_path)
    dest = tmp_path / "dest"
    _install(script, dest)
    assert (dest / "etc/spambuntu/role").read_text() == "gateway\n"
    units = {p.name for p in (dest / "etc/systemd/system").iterdir()}
    assert "spambuntu-webui.service" in units and "spambuntu-sandbox-firewall.service" not in units
    assert not (dest / "usr/local/sbin/spambuntu-sandbox").exists()


def test_role_is_sticky_and_validated(repo_copy, tmp_path):
    script = _extract(repo_copy, tmp_path)
    dest = tmp_path / "dest"
    _install(script, dest, "--role", "sandbox")
    changed = _install(script, dest, "--role", "gateway", check=False)
    assert changed.returncode != 0 and "déjà installée avec le rôle" in changed.stderr
    refresh = run(["bash", str(script), "--refresh"], env={"DESTDIR": str(dest)})        # sans --role : garde le rôle installé
    assert "rôle : sandbox" in refresh.stdout
    assert {p.name for p in (dest / "etc/systemd/system").iterdir()} == {"spambuntu-sandbox-firewall.service"}
    bad = _install(script, tmp_path / "other", "--role", "pirate", check=False)
    assert bad.returncode != 0 and "rôle inconnu" in bad.stderr
    missing = run(["bash", str(script), "--role"], env={"DESTDIR": str(tmp_path / "x")}, check=False)
    assert missing.returncode == 2


def test_refresh_of_an_old_gateway_without_role_file_keeps_gateway(repo_copy, tmp_path):
    script = _extract(repo_copy, tmp_path)
    dest = tmp_path / "dest"
    _install(script, dest)
    (dest / "etc/spambuntu/role").unlink()                                        # installation antérieure à 0.4.0
    out = run(["bash", str(script), "--refresh"], env={"DESTDIR": str(dest)})
    assert "rôle : gateway" in out.stdout and (dest / "etc/spambuntu/role").read_text() == "gateway\n"
    assert (dest / "etc/sudoers.d/spambuntu-webui").is_file()


def test_each_role_has_its_own_package_list():
    gateway = (ROOT / "appliance/packages.txt").read_text()
    sandbox = (ROOT / "appliance/packages-sandbox.txt").read_text()
    assert "postfix" in gateway and "rspamd" in gateway
    for forbidden in ("postfix", "rspamd", "redis", "flask", "gunicorn"):
        assert forbidden not in sandbox
    assert "nftables" in sandbox and "cpu-checker" in sandbox


# ------------------------------------------------------------------ hooks de mise à jour

def _hook_env(tmp_path, repo_copy, role):
    new = tmp_path / f"new-{role}"
    shutil.copytree(repo_copy / "appliance", new)
    marker = tmp_path / f"marker-{role}"
    for d, name in (("migrations", "gw"), ("migrations-sandbox", "sb")):
        (new / "hooks" / d).mkdir(exist_ok=True)
        for old in (new / "hooks" / d).glob("*.sh"):
            old.unlink()
        (new / "hooks" / d / f"0001-{name}.sh").write_text(f'echo {name} >> "{marker}"\n')
    dest = tmp_path / f"dest-{role}"
    (dest / "etc/spambuntu").mkdir(parents=True)
    if role:
        (dest / "etc/spambuntu/role").write_text(role + "\n")
    (new / "VERSION").write_text("0.4.0\n")
    env = {"DESTDIR": str(dest), "SPAMBUNTU_NEW_DIR": str(new)}
    return new, dest, marker, env


@pytest.mark.parametrize("role,expected", [("sandbox", "sb"), ("gateway", "gw"), ("", "gw")])
def test_post_update_runs_the_migrations_of_the_installed_role(repo_copy, tmp_path, role, expected):
    new, dest, marker, env = _hook_env(tmp_path, repo_copy, role)
    run(["bash", str(new / "hooks/post-update.sh")], env=env)
    assert marker.read_text().split() == [expected]
    assert f"0001-{'sb' if expected == 'sb' else 'gw'}.sh" in (dest / "var/lib/spambuntu/migrations.done").read_text()


def test_pre_update_checks_the_sandbox_package_file_for_a_sandbox_node(repo_copy, tmp_path):
    new, dest, marker, env = _hook_env(tmp_path, repo_copy, "sandbox")
    run(["bash", str(new / "hooks/pre-update.sh")], env=env)           # DESTDIR : aucune installation de paquet, syntaxe seulement
    text = (ROOT / "appliance/hooks/pre-update.sh").read_text()
    assert "packages-sandbox.txt" in text


# ------------------------------------------------------------------ ISO : un seul fichier, deux installations

def test_sandbox_seed_is_safe_and_selects_the_sandbox_role():
    text = (ROOT / "iso" / "user-data-sandbox").read_text(encoding="utf-8")
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(text)["autoinstall"]
    assert data["interactive-sections"] == ["identity", "network"]     # compte et adresse saisis à l'installation
    assert "password:" not in text and "passwd" not in text
    cmds = " ".join(str(c) for c in data["late-commands"])
    assert "--role sandbox" in cmds and "install.sh" in cmds
    gateway = yaml.safe_load((ROOT / "iso" / "user-data").read_text(encoding="utf-8"))["autoinstall"]
    assert "--role sandbox" not in " ".join(str(c) for c in gateway["late-commands"])
    assert data["storage"] == gateway["storage"]


def test_build_iso_declares_both_entries_and_never_adds_sandbox_to_ci_isos():
    script = (ROOT / "tools" / "build-iso.sh").read_text(encoding="utf-8")
    assert "spambuntu-autoinstall-sandbox" in script and "Installer Spambuntu Sandbox" in script
    assert 'WITH_SANDBOX=0' in script and '[ "$CI_TEST" -eq 0 ] || WITH_SANDBOX=0' in script
    assert "packages-sandbox.txt" in script                              # les paquets du worker sont embarqués aussi


def test_iso_debs_merges_the_package_lists(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("iso_debs", ROOT / "tools" / "iso_debs.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("# x\npostfix\nsudo\n")
    b.write_text("sudo\nnftables\n")
    seen = {}
    monkeypatch.setattr(mod, "installed_set", lambda m: {f"p{i}": (f"p{i}", "1") for i in range(400)})
    monkeypatch.setattr(mod, "plan", lambda status, pk: seen.setdefault("pk", list(pk)) and [])
    with pytest.raises(SystemExit):                                       # « aucun paquet à embarquer » : plan vide dans ce test
        monkeypatch.setattr("sys.argv", ["iso_debs.py", str(a), "--packages", str(a), str(b), "--out", str(tmp_path / "o")])
        mod.main()
    assert seen["pk"] == ["postfix", "sudo", "nftables"]


# ------------------------------------------------------------------ contrôles du nœud

def _fake_root(tmp_path, flags="fpu vmx hypervisor", kvm=True):
    root = tmp_path / "root"
    (root / "proc").mkdir(parents=True)
    (root / "proc/cpuinfo").write_text(f"processor : 0\nflags : {flags}\n")
    if kvm:
        (root / "dev").mkdir()
        (root / "dev/kvm").write_text("")
    return root


def _by_id(checks):
    return {c.id: c for c in checks}


def test_checks_pass_with_nested_virtualization(tmp_path):
    root = _fake_root(tmp_path)
    (root / "opt/spambuntu/sandbox/bin").mkdir(parents=True)
    fc = root / "opt/spambuntu/sandbox/bin/firecracker"
    fc.write_text("#!/bin/sh\n")
    fc.chmod(0o755)
    res = _by_id(node.run_checks(node.Paths(root)))
    assert res["cpu_virt"].level == "ok" and res["kvm"].level == "ok" and res["firecracker"].level == "ok"


def test_checks_explain_how_to_enable_nested_virtualization_on_vmware(tmp_path):
    res = _by_id(node.run_checks(node.Paths(_fake_root(tmp_path, flags="fpu hypervisor", kvm=False))))
    assert res["cpu_virt"].level == "error" and "vhv.enable" in res["cpu_virt"].hint
    assert res["kvm"].level == "error"
    bare = _by_id(node.run_checks(node.Paths(_fake_root(tmp_path / "b", flags="fpu", kvm=False))))
    assert "BIOS" in bare["cpu_virt"].hint


def test_image_manifest_is_verified_by_sha256(tmp_path):
    import hashlib
    root = _fake_root(tmp_path)
    images = root / "var/lib/spambuntu/sandbox/images"
    images.mkdir(parents=True)
    (images / "vmlinux").write_bytes(b"kernel")
    (images / "rootfs.ext4").write_bytes(b"rootfs")
    manifest = {"kernel": {"file": "vmlinux", "sha256": hashlib.sha256(b"kernel").hexdigest()},
                "rootfs": {"file": "rootfs.ext4", "sha256": hashlib.sha256(b"rootfs").hexdigest()}}
    (images / "manifest.json").write_text(json.dumps(manifest))
    paths = node.Paths(root)
    assert _by_id(node.run_checks(paths))["images"].level == "ok"
    (images / "rootfs.ext4").write_bytes(b"alteree")
    bad = _by_id(node.run_checks(paths))["images"]
    assert bad.level == "error" and "SHA-256" in bad.message
    manifest["kernel"]["file"] = "../../etc/passwd"                      # pas d'échappement hors du répertoire des images
    (images / "manifest.json").write_text(json.dumps(manifest))
    assert _by_id(node.run_checks(paths))["images"].level == "error"
    (images / "manifest.json").write_text("{pas du json")
    assert _by_id(node.run_checks(paths))["images"].level == "error"


def test_status_reports_role_pairing_and_readiness(tmp_path):
    root = _fake_root(tmp_path)
    paths = node.Paths(root)
    (root / "etc/spambuntu").mkdir(parents=True)
    (root / "etc/spambuntu/role").write_text("sandbox\n")
    (root / "opt/spambuntu/current").mkdir(parents=True)
    (root / "opt/spambuntu/current/VERSION").write_text("0.4.0\n")
    st = node.status(paths)
    assert st["role"] == "sandbox" and st["version"] == "0.4.0" and st["paired"] is False and st["ready"] is False
    (root / "etc/spambuntu/sandbox").mkdir()
    (root / "etc/spambuntu/sandbox/worker.json").write_text("{}")
    assert node.status(paths)["ready"] is True
    (root / "etc/spambuntu/role").write_text("n'importe quoi\n")
    assert node.read_role(paths) == "gateway"                              # valeur inconnue : jamais un rôle inventé


def test_cli_check_exit_code_and_json(tmp_path, capsys, monkeypatch):
    real = node.Paths
    monkeypatch.setattr(node, "Paths", lambda: real(_fake_root(tmp_path, flags="fpu", kvm=False)))
    rc = node.main(["check", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and any(c["id"] == "kvm" and c["level"] == "error" for c in out)


# ------------------------------------------------------------------ pare-feu

def test_firewall_denies_everything_except_ssh_and_the_gateway():
    text = node.render_firewall("10.0.0.5", 8444, ["10.0.1.0/24"], ["10.0.0.1:udp:123"])
    assert text.count("policy drop") == 3
    assert "ip daddr 10.0.0.5 tcp dport 8444 accept" in text
    assert "ip saddr 10.0.1.0/24 tcp dport 22 accept" in text
    assert "ip daddr 10.0.0.1 udp dport 123 accept" in text
    forward = text.split("chain forward")[1].split("}")[0]
    assert "accept" not in forward                                          # le trafic des microVM n'est jamais routé par défaut
    assert "flush ruleset" not in text                                      # ne touche que sa propre table
    v6 = node.render_firewall("2001:db8::5")
    assert "ip6 daddr 2001:db8::5 tcp dport 8444 accept" in v6


@pytest.mark.parametrize("gateway,port,ssh,extra", [
    ("pas-une-ip", 8444, None, None), ("10.0.0.5", 0, None, None), ("10.0.0.5", 70000, None, None),
    ("10.0.0.5", "abc", None, None), ("10.0.0.5", 8444, ["x"], None), ("10.0.0.5", 8444, None, ["10.0.0.1:icmp:1"]),
    ("10.0.0.5", 8444, None, ["10.0.0.1:udp"]), ("10.0.0.5; drop", 8444, None, None),
    ("10.0.0.5", 8444, None, ["10.0.0.1:tcp:80 accept; flush ruleset"]),
])
def test_firewall_rejects_injected_or_invalid_values(gateway, port, ssh, extra):
    with pytest.raises(ValueError):
        node.render_firewall(gateway, port, ssh, extra)


@pytest.mark.skipif(shutil.which("nft") is None, reason="nft absent")
def test_firewall_syntax_is_accepted_by_nft(tmp_path):
    f = tmp_path / "r.nft"
    f.write_text(node.render_firewall("10.0.0.5", 8444, ["10.0.1.0/24"], ["10.0.0.1:udp:123"]))
    r = subprocess.run(["nft", "-c", "-f", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_apply_writes_a_private_file_without_loading(tmp_path):
    paths = node.Paths(tmp_path)
    out = node.apply_firewall(node.render_firewall("10.0.0.5"), paths, load=False)
    assert out == paths.nft_conf and oct(out.stat().st_mode & 0o777) == "0o600"
    assert not list(out.parent.glob("*.tmp"))


def test_firewall_unit_is_conditional_on_the_rules_file():
    unit = (ROOT / "appliance/systemd/spambuntu-sandbox-firewall.service").read_text()
    assert "ConditionPathExists=/etc/spambuntu/sandbox/nftables.conf" in unit
    assert "ExecStart=/usr/sbin/nft -f /etc/spambuntu/sandbox/nftables.conf" in unit
    assert "Before=network-pre.target" in unit


def test_sandbox_motd_has_no_console_link(tmp_path):
    motd = (ROOT / "appliance/motd/90-spambuntu").read_text()
    assert "nœud SANDBOX" in motd and "spambuntu-sandbox status" in motd
