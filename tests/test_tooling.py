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

    r = run(release + ["0.2.0"], cwd=repo_copy, env=GIT_ENV, check=False)
    assert r.returncode != 0 and "CHANGELOG" in r.stderr           # notes obligatoires
    for bad in ("abc", "0.0.9", "0.1.0"):
        assert run(release + [bad], cwd=repo_copy, env=GIT_ENV, check=False).returncode != 0

    changelog = repo_copy / "CHANGELOG.md"
    changelog.write_text(changelog.read_text() + "\n## [0.2.0] - 2026-12-01\n\n- Nouveauté\n")
    run(["git", "commit", "-qam", "notes"], cwd=repo_copy, env=GIT_ENV)
    run(release + ["0.2.0"], cwd=repo_copy, env=GIT_ENV)
    assert (repo_copy / "VERSION").read_text().strip() == "0.2.0"
    assert "v0.2.0" in run(["git", "tag"], cwd=repo_copy).stdout
    assert run(release + ["0.2.0"], cwd=repo_copy, env=GIT_ENV, check=False).returncode != 0  # tag déjà là

    (repo_copy / "appliance" / "etc" / "update-pubkey.pem").unlink()
    run(["git", "commit", "-qam", "sans clé"], cwd=repo_copy, env=GIT_ENV)
    changelog.write_text(changelog.read_text() + "\n## [0.3.0] - 2026-12-02\n\n- Autre\n")
    run(["git", "commit", "-qam", "notes 0.3"], cwd=repo_copy, env=GIT_ENV)
    r = run(release + ["0.3.0"], cwd=repo_copy, env=GIT_ENV, check=False)
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
    assert allowed == ["spambuntu-update-apply", "spambuntu-update-rollback"]   # exactement ces deux unités
    assert "NOPASSWD: ALL" not in sudoers.read_text()
    wrapper = (dest / "usr/local/sbin/spambuntu-update").read_text()
    assert "/opt/spambuntu/current/updater/spambuntu_update.py" in wrapper
    webui_json = dest / "etc/spambuntu/webui.json"
    assert oct(webui_json.stat().st_mode & 0o777) == "0o640"
    assert oct((dest / "etc/spambuntu/update.conf").stat().st_mode & 0o777) == "0o640"
    assert oct((dest / "var/lib/spambuntu/backups").stat().st_mode & 0o777) == "0o700"
    assert "AVERTISSEMENT" in r.stderr            # pas de clé publique dans ce dépôt de test

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


def test_install_refuses_raw_checkout_and_unknown_option(repo_copy):
    r = run(["bash", str(repo_copy / "appliance" / "install.sh")], env={"DESTDIR": str(repo_copy / "d")}, check=False)
    assert r.returncode != 0 and "VERSION introuvable" in r.stderr
    r = run(["bash", str(repo_copy / "appliance" / "install.sh"), "--nope"], check=False)
    assert r.returncode == 2


# ------------------------------------------------------------------ mise à jour de bout en bout avec une vraie archive

def publish_real(env, repo, version):
    bundle = build(repo, version, env.tmp / f"out-{version}")
    data = bundle.read_bytes()
    env.github.add(version, data, sign(data, env.priv, env.tmp))


def test_real_bundle_update_end_to_end(env, repo_copy, monkeypatch):
    dest = env.tmp / "destdir"
    monkeypatch.setenv("DESTDIR", str(dest))
    publish_real(env, repo_copy, "0.2.0")
    assert env.apply() == 0
    assert env.current() == "0.2.0"
    assert (dest / "etc/systemd/system/spambuntu-webui.service").is_file()        # post-update.sh -> install.sh --refresh
    assert (dest / "var/lib/spambuntu/migrations.done").exists()
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
