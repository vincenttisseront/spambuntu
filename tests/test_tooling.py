"""Scripts de release et d'installation : exécutés pour de vrai, dans des copies jetables du dépôt."""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

import spambuntu_update as upd
from conftest import ROOT, sign

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}


def run(cmd, cwd=None, env=None, check=True):
    full_env = {**os.environ, **(env or {})}
    r = subprocess.run(cmd, cwd=cwd, env=full_env, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise AssertionError(f"{cmd} a échoué ({r.returncode})\n{r.stdout}\n{r.stderr}")
    return r


@pytest.fixture
def repo_copy(tmp_path):
    """Copie jetable du dépôt (les scripts se calent sur leur propre emplacement)."""
    dest = tmp_path / "repo"
    dest.mkdir()
    shutil.copytree(ROOT / "appliance", dest / "appliance", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(ROOT / "tools", dest / "tools")
    for name in ("VERSION", "MIN_FROM_VERSION", "CHANGELOG.md"):
        shutil.copy(ROOT / name, dest / name)
    (dest / "appliance" / "etc" / "update-pubkey.pem").unlink(missing_ok=True)   # les tests ne dépendent pas de la vraie clé
    return dest


def build(repo, version, out):
    (repo / "VERSION").write_text(version + "\n")
    return Path(run([str(repo / "tools" / "build-bundle.sh"), str(out)]).stdout.strip().splitlines()[-1])


# ------------------------------------------------------------------ build-bundle.sh

def test_bundle_structure(repo_copy, tmp_path):
    bundle = build(repo_copy, "0.4.2", tmp_path / "out")
    assert bundle.name == "spambuntu-0.4.2.tar.gz"
    with tarfile.open(bundle) as tar:
        names = tar.getnames()
        manifest = json.load(tar.extractfile("spambuntu-0.4.2/manifest.json"))
        version = tar.extractfile("spambuntu-0.4.2/VERSION").read().decode().strip()
    assert version == "0.4.2"
    assert manifest["version"] == "0.4.2" and manifest["min_from_version"] == "0.0.0"
    for expected in ("install.sh", "updater/spambuntu_update.py", "webui/app.py", "webui/static/update.js",
                     "hooks/pre-update.sh", "hooks/post-update.sh", "systemd/spambuntu-webui.service",
                     "sudoers/spambuntu-webui", "packages.txt"):
        assert f"spambuntu-0.4.2/{expected}" in names, expected
    assert not [n for n in names if "__pycache__" in n or n.startswith("spambuntu-0.4.2/tests")]
    assert all(n.split("/")[0] == "spambuntu-0.4.2" for n in names)


def test_bundle_is_reproducible(repo_copy, tmp_path):
    digests = set()
    for i in range(2):
        bundle = build(repo_copy, "0.4.2", tmp_path / f"out{i}")
        digests.add(hashlib.sha256(bundle.read_bytes()).hexdigest())
    assert len(digests) == 1


def test_bundle_min_from_version_is_propagated(repo_copy, tmp_path):
    (repo_copy / "MIN_FROM_VERSION").write_text("0.3.0\n")
    bundle = build(repo_copy, "0.4.2", tmp_path / "out")
    with tarfile.open(bundle) as tar:
        assert json.load(tar.extractfile("spambuntu-0.4.2/manifest.json"))["min_from_version"] == "0.3.0"


def test_build_refuses_private_key_and_bad_version(repo_copy, tmp_path):
    (repo_copy / "appliance" / "etc" / "oops.pem").write_text("-----BEGIN PRIVATE KEY-----\nabc\n")
    r = run([str(repo_copy / "tools" / "build-bundle.sh"), str(tmp_path / "o")], check=False)
    assert r.returncode != 0 and "clé privée" in r.stderr
    (repo_copy / "appliance" / "etc" / "oops.pem").unlink()
    (repo_copy / "VERSION").write_text("pas-une-version\n")
    r = run([str(repo_copy / "tools" / "build-bundle.sh"), str(tmp_path / "o")], check=False)
    assert r.returncode != 0 and "VERSION invalide" in r.stderr


# ------------------------------------------------------------------ gen-signing-key.sh

def test_gen_signing_key(repo_copy, tmp_path):
    keydir = tmp_path / "keys"
    run([str(repo_copy / "tools" / "gen-signing-key.sh")], env={"SPAMBUNTU_KEY_DIR": str(keydir)})
    key, pub = keydir / "update-signing-key.pem", repo_copy / "appliance" / "etc" / "update-pubkey.pem"
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    assert "PRIVATE" not in pub.read_text()
    data = tmp_path / "data.bin"
    data.write_bytes(b"hello")
    signature = tmp_path / "data.sig"
    run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(data), "-out", str(signature)])
    assert "Verified" in run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-rawin",
                              "-in", str(data), "-sigfile", str(signature)]).stdout
    again = run([str(repo_copy / "tools" / "gen-signing-key.sh")], env={"SPAMBUNTU_KEY_DIR": str(keydir)}, check=False)
    assert again.returncode != 0 and "n'est pas écrasée" in again.stderr


# ------------------------------------------------------------------ release.sh

def test_release_script(repo_copy, tmp_path):
    keydir = tmp_path / "keys"
    run([str(repo_copy / "tools" / "gen-signing-key.sh")], env={"SPAMBUNTU_KEY_DIR": str(keydir)})
    (repo_copy / ".gitignore").write_text("*.pem\n!appliance/etc/update-pubkey.pem\n")
    run(["git", "init", "-q", "-b", "main"], cwd=repo_copy)
    run(["git", "add", "-A"], cwd=repo_copy)
    run(["git", "commit", "-q", "-m", "init"], cwd=repo_copy, env=GIT_ENV)
    release = [str(repo_copy / "tools" / "release.sh")]

    r = run(release + ["0.3.0"], cwd=repo_copy, env=GIT_ENV, check=False)
    assert r.returncode != 0 and "CHANGELOG" in r.stderr           # notes obligatoires
    for bad in ("abc", "0.0.9", "0.2.0"):
        assert run(release + [bad], cwd=repo_copy, env=GIT_ENV, check=False).returncode != 0

    changelog = repo_copy / "CHANGELOG.md"
    changelog.write_text(changelog.read_text() + "\n## [0.3.0] - 2026-12-01\n\n- Nouveauté\n")
    run(["git", "commit", "-qam", "notes"], cwd=repo_copy, env=GIT_ENV)
    run(release + ["0.3.0"], cwd=repo_copy, env=GIT_ENV)
    assert (repo_copy / "VERSION").read_text().strip() == "0.3.0"
    assert "v0.3.0" in run(["git", "tag"], cwd=repo_copy).stdout
    assert run(release + ["0.3.0"], cwd=repo_copy, env=GIT_ENV, check=False).returncode != 0  # tag déjà là

    (repo_copy / "appliance" / "etc" / "update-pubkey.pem").unlink()
    run(["git", "commit", "-qam", "sans clé"], cwd=repo_copy, env=GIT_ENV)
    changelog.write_text(changelog.read_text() + "\n## [0.4.0] - 2026-12-02\n\n- Autre\n")
    run(["git", "commit", "-qam", "notes 0.4"], cwd=repo_copy, env=GIT_ENV)
    r = run(release + ["0.4.0"], cwd=repo_copy, env=GIT_ENV, check=False)
    assert r.returncode != 0 and "clé publique" in r.stderr


def test_release_workflow_notes_extraction_matches_changelog(tmp_path):
    """Même commande awk que le workflow : elle doit isoler la section de la version."""
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("# Changelog\n\n## [0.2.0] - x\n\n- B\n\n## [0.1.0] - y\n\n- A\n")
    script = ("awk -v v=\"$1\" '$0 ~ \"^## \\\\[\" v \"\\\\]\" {f=1; next} /^## \\[/ {f=0} f' " + str(changelog))
    notes = run(["bash", "-c", script, "_", "0.1.0"]).stdout
    assert "- A" in notes and "- B" not in notes
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    assert "$0 ~ \"^## \\\\[\" v \"\\\\]\" {f=1; next} /^## \\[/ {f=0} f" in workflow
    real = run(["bash", "-c", script.replace(str(changelog), str(ROOT / "CHANGELOG.md")), "_", "0.1.0"]).stdout
    assert "console web" in real


# ------------------------------------------------------------------ install.sh (DESTDIR)

def test_fresh_install_into_destdir_then_login(repo_copy, tmp_path):
    bundle = build(repo_copy, "0.2.0", tmp_path / "out")
    extract = tmp_path / "extract"
    with tarfile.open(bundle) as tar:
        tar.extractall(extract, filter="data")
    dest = tmp_path / "dest"
    r = run(["bash", str(extract / "spambuntu-0.2.0" / "install.sh"), "--no-start"], env={"DESTDIR": str(dest)})

    assert (dest / "opt/spambuntu/current").resolve() == (dest / "opt/spambuntu/releases/0.2.0").resolve()
    assert (dest / "opt/spambuntu/current/VERSION").read_text().strip() == "0.2.0"
    for unit in ("spambuntu-webui.service", "spambuntu-update-check.timer", "spambuntu-update-apply.service",
                 "spambuntu-update-rollback.service", "spambuntu-update-check.service"):
        assert (dest / "etc/systemd/system" / unit).is_file(), unit
    sudoers = dest / "etc/sudoers.d/spambuntu-webui"
    assert oct(sudoers.stat().st_mode & 0o777) == "0o440"
    assert "NOPASSWD: SPAMBUNTU_UPDATE" in sudoers.read_text()
    allowed = re.findall(r"/usr/bin/systemctl start --no-block (\S+?)\.service", sudoers.read_text())
    assert allowed == ["spambuntu-update-apply", "spambuntu-update-rollback", "spambuntu-mail-apply"]   # exactement ces unités
    commands = re.findall(r"^\s+(/\S+)", sudoers.read_text(), re.M)
    assert set(commands) == {"/usr/bin/systemctl", "/usr/local/sbin/spambuntu-quarantine", "/usr/local/sbin/spambuntu-mailstats"}    # rien d'autre
    assert "spambuntu-quarantine list," in sudoers.read_text().replace("\\\n", "")
    assert "NOPASSWD: ALL" not in sudoers.read_text()
    wrapper = (dest / "usr/local/sbin/spambuntu-update").read_text()
    assert "/opt/spambuntu/current/updater/spambuntu_update.py" in wrapper
    webui_json = dest / "etc/spambuntu/webui.json"
    assert oct(webui_json.stat().st_mode & 0o777) == "0o640"
    assert oct((dest / "etc/spambuntu/update.conf").stat().st_mode & 0o777) == "0o640"
    assert oct((dest / "var/lib/spambuntu/backups").stat().st_mode & 0o777) == "0o700"
    assert "AVERTISSEMENT" in r.stderr            # pas de clé publique dans ce dépôt de test

    # Console servie en HTTPS : certificat auto-signé, clé protégée, cookies réservés à HTTPS
    tls = dest / "etc/spambuntu/tls"
    assert oct((tls / "console.key").stat().st_mode & 0o777) == "0o640"
    cert = run(["openssl", "x509", "-in", str(tls / "console.crt"), "-noout", "-text"]).stdout
    assert "DNS:localhost" in cert and "IP Address:127.0.0.1" in cert
    env_file = (dest / "etc/spambuntu/webui.env").read_text()
    assert "SPAMBUNTU_BIND=0.0.0.0:8443" in env_file and "--certfile=/etc/spambuntu/tls/console.crt" in env_file
    assert json.loads(webui_json.read_text())["cookie_secure"] is True
    assert (dest / "etc/update-motd.d/90-spambuntu").stat().st_mode & 0o111
    assert "ExecStart=/usr/bin/gunicorn" in (dest / "etc/systemd/system/spambuntu-webui.service").read_text()

    # Le mot de passe affiché à l'installation ouvre vraiment la console
    password = re.search(r"Mot de passe .*: (\S+)", r.stdout).group(1)
    import app as webapp
    application = webapp.create_app(str(webui_json))
    client = application.test_client()
    token = re.search(r'name="csrf-token" content="([0-9a-f]+)"', client.get("/login").get_data(as_text=True)).group(1)
    ok = client.post("/login", data={"username": "admin", "password": password, "csrf_token": token})
    assert ok.status_code == 302

    # Une seconde installation ne régénère ni mot de passe ni configuration
    before = webui_json.read_text()
    again = run(["bash", str(extract / "spambuntu-0.2.0" / "install.sh"), "--no-start"], env={"DESTDIR": str(dest)})
    assert webui_json.read_text() == before and "Mot de passe" not in again.stdout


def test_install_can_store_initial_password_in_a_file(repo_copy, tmp_path):
    bundle = build(repo_copy, "0.2.0", tmp_path / "out")
    extract = tmp_path / "extract"
    with tarfile.open(bundle) as tar:
        tar.extractall(extract, filter="data")
    dest = tmp_path / "dest"
    r = run(["bash", str(extract / "spambuntu-0.2.0" / "install.sh"), "--no-start"],
            env={"DESTDIR": str(dest), "SPAMBUNTU_PASSWORD_FILE": "/root/spambuntu-console-password.txt"})
    pw_file = dest / "root/spambuntu-console-password.txt"
    assert oct(pw_file.stat().st_mode & 0o777) == "0o600"
    content = pw_file.read_text()
    password = re.search(r"Mot de passe : (\S+)", content).group(1)
    assert password not in r.stdout and password not in r.stderr        # jamais affiché dans le journal d'installation
    import app as webapp
    client = webapp.create_app(str(dest / "etc/spambuntu/webui.json")).test_client()
    token = re.search(r'name="csrf-token" content="([0-9a-f]+)"', client.get("/login").get_data(as_text=True)).group(1)
    assert client.post("/login", data={"username": "admin", "password": password, "csrf_token": token}).status_code == 302


def test_motd_is_silent_outside_an_appliance():
    motd = ROOT / "appliance" / "motd" / "90-spambuntu"
    r = run(["sh", str(motd)])          # hors appliance : n'affiche rien et ne plante pas
    assert r.stdout == ""


def test_install_refuses_raw_checkout_and_unknown_option(repo_copy):
    r = run(["bash", str(repo_copy / "appliance" / "install.sh")], env={"DESTDIR": str(repo_copy / "d")}, check=False)
    assert r.returncode != 0 and "VERSION introuvable" in r.stderr
    r = run(["bash", str(repo_copy / "appliance" / "install.sh"), "--nope"], check=False)
    assert r.returncode == 2


# ------------------------------------------------------------------ mise à jour de bout en bout avec une vraie archive

def publish_real(env, repo, version, signed_with=None):
    bundle = build(repo, version, env.tmp / f"out-{version}")
    data = bundle.read_bytes()
    env.github.add(version, data, sign(data, signed_with or env.priv, env.tmp))


def test_real_bundle_update_end_to_end(env, repo_copy, monkeypatch):
    dest = env.tmp / "destdir"
    monkeypatch.setenv("DESTDIR", str(dest))
    publish_real(env, repo_copy, "0.2.0")
    assert env.apply() == 0
    assert env.current() == "0.2.0"
    assert (dest / "etc/systemd/system/spambuntu-webui.service").is_file()        # post-update.sh -> install.sh --refresh
    assert (dest / "var/lib/spambuntu/migrations.done").exists()
    assert "0001-messagerie.sh" in (dest / "var/lib/spambuntu/migrations.done").read_text()
    assert (dest / "var/lib/spambuntu/mail/user").is_dir()                                 # créé par install.sh --refresh
    assert (dest / "usr/local/sbin/spambuntu-quarantine").is_file()
    assert (dest / "etc/systemd/system/spambuntu-mail-apply.service").is_file()
    log = env.log.read_text()
    assert "Contrôles préalables réussis" in log and "Rafraîchissement de la version 0.2.0 terminé" in log
    assert not (env.tmp / "var").exists()                                          # rien n'a fuité hors du DESTDIR


def test_real_bundle_with_broken_code_is_stopped_by_pre_update_hook(env, repo_copy, monkeypatch):
    monkeypatch.setenv("DESTDIR", str(env.tmp / "destdir"))
    (repo_copy / "appliance" / "webui" / "app.py").write_text("def broken(:\n")
    publish_real(env, repo_copy, "0.2.0")
    assert env.apply() == 1
    assert "pre-update.sh" in env.status()["message"]
    assert env.current() == "0.1.0" and env.release_dirs() == ["0.1.0"]
    assert env.previous() is None


def test_real_bundle_migration_runs_once(env, repo_copy, monkeypatch):
    dest = env.tmp / "destdir"
    monkeypatch.setenv("DESTDIR", str(dest))
    marker = env.tmp / "migration-ran"
    (repo_copy / "appliance/hooks/migrations/0001-demo.sh").write_text(f'echo run >> "{marker}"\n')
    publish_real(env, repo_copy, "0.2.0")
    assert env.apply() == 0
    publish_real(env, repo_copy, "0.3.0")
    assert env.apply() == 0
    assert marker.read_text().splitlines() == ["run"]


def test_real_bundle_failing_migration_rolls_back(env, repo_copy, monkeypatch):
    monkeypatch.setenv("DESTDIR", str(env.tmp / "destdir"))
    (repo_copy / "appliance/hooks/migrations/0001-boom.sh").write_text("echo boom >&2\nexit 7\n")
    publish_real(env, repo_copy, "0.2.0")
    assert env.apply() == 1
    assert env.status()["state"] == "rolled_back"
    assert env.current() == "0.1.0"
    assert upd.read_status(env.cfg())["state"] == "rolled_back"


# ------------------------------------------------------------------ dépôt

def test_gitignore_does_not_hide_source_files():
    """Garde-fou : aucun fichier source ne doit être ignoré par erreur par .gitignore.

    --no-index évalue les règles sans tenir compte de l'index : un fichier déjà suivi ne masque pas le problème.
    """
    if not (ROOT / ".git").exists():
        pytest.skip("pas un dépôt git")
    files = [p.relative_to(ROOT).as_posix()
             for d in ("appliance", "tools", "tests", ".github") for p in (ROOT / d).rglob("*")
             if p.is_file() and not {"__pycache__", ".pytest_cache"} & set(p.parts)]
    files += ["VERSION", "MIN_FROM_VERSION", "CHANGELOG.md", "README.md", ".gitignore"]
    assert "tools/gen-signing-key.sh" in files
    r = subprocess.run(["git", "check-ignore", "--no-index", "--stdin"], cwd=ROOT, input="\n".join(files),
                       capture_output=True, text=True)
    assert r.stdout.strip() == "", f"fichiers ignorés par erreur : {r.stdout}"


# --- ISO ---------------------------------------------------------------------------------------

def _load_tool(name):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_iso_manifest_parsing_applies_additions_and_removals(tmp_path):
    mod = _load_tool("iso_debs")
    first = tmp_path / "a.manifest"
    second = tmp_path / "b.manifest"
    first.write_text("--- a\n+++ b\n+libssl3t64:amd64\t3.0.1\n+sudo\t1.9\n+gone\t1\n", encoding="utf-8")
    second.write_text("--- a\n+++ b\n-gone\t1\n+python3\t3.12\n", encoding="utf-8")
    inst = mod.installed_set([first, second])
    assert set(inst) == {"libssl3t64", "sudo", "python3"}
    assert inst["libssl3t64"] == ("libssl3t64:amd64", "3.0.1")
    status = tmp_path / "status"
    mod.write_status(inst, status)
    text = status.read_text(encoding="utf-8")
    assert "Package: libssl3t64\nStatus: install ok installed\nArchitecture: amd64\nVersion: 3.0.1" in text
    assert "Package: sudo\nStatus: install ok installed\nArchitecture: all" in text


def test_iso_seed_is_safe_by_default():
    text = (ROOT / "iso" / "user-data").read_text(encoding="utf-8")
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load(text)["autoinstall"]
    assert data["interactive-sections"] == ["identity"]          # pas de mot de passe codé en dur
    assert "password:" not in text and "passwd" not in text           # ni mot de passe ni condensat dans l'ISO
    assert any("install.sh" in str(c) for c in data["late-commands"])


def test_ci_seed_is_throwaway_and_never_the_default(tmp_path):
    seed = tmp_path / "user-data"
    shutil.copy(ROOT / "iso" / "user-data", seed)
    subprocess.run(["python3", "-B", str(ROOT / "tools" / "iso_citest.py"), str(seed)], check=True)
    text = seed.read_text(encoding="utf-8")
    assert "identity:" in text and "interactive-sections" not in text and "poweroff" in text
    original = (ROOT / "iso" / "user-data").read_text(encoding="utf-8")
    assert "identity:" not in original and "poweroff" not in original


def test_build_iso_refuses_without_public_key(repo_copy, tmp_path):
    for pem in (repo_copy / "appliance" / "etc").glob("*.pem"):
        pem.unlink()
    result = subprocess.run(["bash", str(repo_copy / "tools" / "build-iso.sh"), "--output", str(tmp_path / "x.iso")],
                            capture_output=True, text=True, cwd=repo_copy)
    assert result.returncode != 0
    assert "clé publique" in result.stderr


def test_build_iso_refuses_private_key_as_pubkey(repo_copy, tmp_path):
    priv = tmp_path / "priv.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)], check=True, capture_output=True)
    result = subprocess.run(["bash", str(repo_copy / "tools" / "build-iso.sh"), "--pubkey", str(priv)],
                            capture_output=True, text=True, cwd=repo_copy)
    assert result.returncode != 0
    assert "n'est pas une clé publique" in result.stderr


def test_build_iso_refuses_tampered_base_iso(repo_copy, tmp_path):
    """Une somme SHA-256 qui ne correspond pas à SHA256SUMS signé doit bloquer la construction."""
    cache = Path("/home/claude/iso-cache")
    if not (cache / "SHA256SUMS.gpg").exists():
        pytest.skip("cache ISO absent")
    pub = tmp_path / "pub.pem"
    priv = tmp_path / "priv.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(priv)], check=True, capture_output=True)
    pub.write_bytes(subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout"], check=True, capture_output=True).stdout)
    fake = tmp_path / "ubuntu-24.04.5-live-server-amd64.iso"
    fake.write_bytes(b"pas une iso")
    shutil.copy(cache / "SHA256SUMS", tmp_path)
    shutil.copy(cache / "SHA256SUMS.gpg", tmp_path)
    result = subprocess.run(["bash", str(repo_copy / "tools" / "build-iso.sh"), "--pubkey", str(pub), "--base", str(fake)],
                            capture_output=True, text=True, cwd=repo_copy, env={**os.environ, "ISO_CACHE": str(tmp_path)})
    assert result.returncode != 0
    assert "SHA-256" in result.stderr


def test_verify_accepts_a_real_signed_release_without_installing_it(env, repo_copy):
    publish_real(env, repo_copy, "0.2.0")
    before = env.current()
    result = upd.verify_release(env.cfg())
    assert result["version"] == "0.2.0" and result["signature"] == "valide"
    assert result["newer_than_current"] is True and result["installable_from_current"] is True
    assert env.current() == before                                                     # rien n'est installé
    assert not (env.cfg().releases_dir / "0.2.0").exists()


def test_verify_rejects_a_release_signed_with_another_key(env, repo_copy, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    from conftest import gen_keypair
    other_priv, _ = gen_keypair(other)
    publish_real(env, repo_copy, "0.2.0", signed_with=other_priv)
    with pytest.raises(upd.UpdateError, match="[Ss]ignature"):
        upd.verify_release(env.cfg())


def test_verify_refuses_without_public_key(env, repo_copy):
    publish_real(env, repo_copy, "0.2.0")
    cfg = env.cfg()
    cfg.pubkey.unlink()
    with pytest.raises(upd.UpdateError, match="Clé publique"):
        upd.verify_release(cfg)
