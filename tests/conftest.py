"""Fixtures communes : faux GitHub, faux systemctl, faux service de santé, appliance factice."""
import http.server
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "appliance" / "updater"))
sys.path.insert(0, str(ROOT / "appliance" / "webui"))
sys.path.insert(0, str(ROOT / "appliance" / "mail"))

import spambuntu_update as upd  # noqa: E402

HOOK = """#!/bin/bash
echo "{name} from=$SPAMBUNTU_FROM to=$SPAMBUNTU_TO rollback=$SPAMBUNTU_ROLLBACK" >> "$TEST_MARKER"
[ "$TEST_FAIL_HOOK" = "{name}" ] && exit 3
exit 0
"""


def make_bundle(version, *, hooks=True, min_from=None, evil_member=None, symlink=None, manifest_version=None):
    buf = io.BytesIO()
    top = f"spambuntu-{version}"
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(name, data, mode=0o644):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            tar.addfile(info, io.BytesIO(data))

        add(f"{top}/VERSION", f"{version}\n".encode())
        manifest = {"version": manifest_version or version}
        if min_from:
            manifest["min_from_version"] = min_from
        add(f"{top}/manifest.json", json.dumps(manifest).encode())
        if hooks:
            add(f"{top}/hooks/pre-update.sh", HOOK.format(name="pre").encode())
            add(f"{top}/hooks/post-update.sh", HOOK.format(name="post").encode())
        if evil_member:
            add(evil_member, b"pwned")
        if symlink:
            info = tarfile.TarInfo(f"{top}/{symlink[0]}")
            info.type = tarfile.SYMTYPE
            info.linkname = symlink[1]
            tar.addfile(info)
    return buf.getvalue()


def sign(data: bytes, key: Path, workdir: Path) -> bytes:
    f = workdir / "to-sign.bin"
    f.write_bytes(data)
    out = workdir / "sig.bin"
    subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(f), "-out", str(out)],
                   check=True, capture_output=True)
    return out.read_bytes()


def gen_keypair(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    priv, pub = directory / "priv.pem", directory / "pub.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(priv)], check=True, capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", str(priv), "-pubout", "-out", str(pub)], check=True, capture_output=True)
    return priv, pub


class FakeGitHub(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _GitHubHandler)
        self.releases = []
        self.blobs = {}
        self.requests = []
        self.use_redirect = False
        self.fail_releases = False

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server_address[1]}"

    def add(self, version, bundle, sig, *, prerelease=False, draft=False, with_sig=True, body=""):
        n = len(self.blobs)
        self.blobs[n] = bundle
        self.blobs[n + 1] = sig
        self.releases.append(dict(version=version, a=n, s=n + 1, pre=prerelease, draft=draft, with_sig=with_sig,
                                  size=len(bundle), body=body))

    def releases_json(self):
        prefix = "redir" if self.use_redirect else "assets"
        out = []
        for r in self.releases:
            v = r["version"]
            assets = [{"name": f"spambuntu-{v}.tar.gz", "url": f"{self.base}/{prefix}/{r['a']}",
                       "size": r["size"], "state": "uploaded"}]
            if r["with_sig"]:
                assets.append({"name": f"spambuntu-{v}.tar.gz.sig", "url": f"{self.base}/{prefix}/{r['s']}",
                               "size": len(self.blobs[r["s"]]), "state": "uploaded"})
            out.append({"tag_name": f"v{v}", "name": f"Version {v}", "body": r["body"], "draft": r["draft"],
                        "prerelease": r["pre"], "published_at": "2026-11-01T10:00:00Z",
                        "html_url": f"https://example.invalid/r/{v}", "assets": assets})
        return out


class _GitHubHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/octet-stream", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        srv = self.server
        srv.requests.append((self.headers.get("Host"), self.path, self.headers.get("Authorization")))
        if self.path.startswith("/repos/o/r/releases"):
            if srv.fail_releases:
                return self._send(500, b"{}", "application/json")
            return self._send(200, json.dumps(srv.releases_json()).encode(), "application/json")
        if self.path.startswith("/redir/"):
            n = self.path.rsplit("/", 1)[1]
            return self._send(302, b"", headers={"Location": f"http://localhost:{srv.server_address[1]}/assets/{n}"})
        if self.path.startswith("/assets/"):
            blob = srv.blobs.get(int(self.path.rsplit("/", 1)[1]))
            if blob is None:
                return self._send(404, b"")
            return self._send(200, blob)
        self._send(404, b"")


class FakeHealth(http.server.ThreadingHTTPServer):
    """Se comporte comme la console web : annonce la version du lien « current »."""
    daemon_threads = True

    def __init__(self, opt_dir: Path):
        super().__init__(("127.0.0.1", 0), _HealthHandler)
        self.opt_dir = opt_dir
        self.broken_versions = set()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/healthz"


class _HealthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        version = (self.server.opt_dir / "current" / "VERSION").read_text().strip()
        if version in self.server.broken_versions:
            body, code = b'{"status":"error"}', 500
        else:
            body, code = json.dumps({"status": "ok", "version": version}).encode(), 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Env:
    def __init__(self, tmp: Path, github: FakeGitHub, health: FakeHealth):
        self.tmp, self.github, self.health = tmp, github, health
        self.opt = tmp / "opt"
        self.state = tmp / "state"
        self.backups = tmp / "backups"
        self.etc = tmp / "etc"
        self.log = tmp / "log" / "update.log"
        self.pubkey = tmp / "pubkey.pem"
        self.marker = tmp / "hooks.log"
        self.calls = tmp / "systemctl.calls"
        self.conf = tmp / "update.conf"
        self.priv, pub = gen_keypair(tmp / "keys")
        self.other_priv, _ = gen_keypair(tmp / "other-keys")
        self.pubkey.write_bytes(pub.read_bytes())
        self.extra_conf = {}

        self.etc.mkdir()
        (self.etc / "settings.txt").write_text("hello")
        self._install_initial("0.1.0")

        fake = tmp / "fake-systemctl"
        fake.write_text(f'#!/bin/sh\necho "$@" >> "{self.calls}"\n'
                        f'[ -f "{tmp}/systemctl.fail" ] && [ "$2" = "spambuntu-webui.service" ] && exit 1\nexit 0\n')
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        self.fake_systemctl = fake

    def _install_initial(self, version):
        rel = self.opt / "releases" / version
        (rel / "hooks").mkdir(parents=True)
        (rel / "VERSION").write_text(version + "\n")
        (rel / "hooks" / "post-update.sh").write_text(HOOK.format(name="post"))
        (self.opt / "current").symlink_to(f"releases/{version}")

    def write_conf(self, **overrides):
        values = dict(repo="o/r", api_base=self.github.base, opt_dir=self.opt, state_dir=self.state,
                      backup_dir=self.backups, config_dir=self.etc, log_file=self.log, pubkey=self.pubkey,
                      health_url=self.health.url, health_timeout=5, systemctl=self.fake_systemctl,
                      allow_nonroot="yes", keep_releases=3)
        values.update(self.extra_conf)
        values.update(overrides)
        self.conf.write_text("[update]\n" + "".join(f"{k} = {v}\n" for k, v in values.items()))
        return self.conf

    def cfg(self, **overrides):
        return upd.Config.load(str(self.write_conf(**overrides)))

    def publish(self, version, *, signed_with=None, prerelease=False, draft=False, with_sig=True, **bundle_kwargs):
        bundle = make_bundle(version, **bundle_kwargs)
        sig = sign(bundle, signed_with or self.priv, self.tmp)
        self.github.add(version, bundle, sig, prerelease=prerelease, draft=draft, with_sig=with_sig)

    def apply(self, **kwargs):
        return upd.apply_update(self.cfg(), **kwargs)

    def status(self):
        return json.loads((self.state / "status.json").read_text())

    def current(self):
        return (self.opt / "current" / "VERSION").read_text().strip()

    def previous(self):
        link = self.opt / "previous"
        return (link / "VERSION").read_text().strip() if link.exists() else None

    def release_dirs(self):
        return sorted(p.name for p in (self.opt / "releases").iterdir())

    def hook_log(self):
        return self.marker.read_text().splitlines() if self.marker.exists() else []

    def systemctl_calls(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []


@pytest.fixture
def env(tmp_path, monkeypatch):
    github = FakeGitHub()
    health = FakeHealth(tmp_path / "opt")
    for srv in (github, health):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("TEST_MARKER", str(tmp_path / "hooks.log"))
    monkeypatch.delenv("TEST_FAIL_HOOK", raising=False)
    monkeypatch.delenv("SPAMBUNTU_TOKEN", raising=False)
    e = Env(tmp_path, github, health)
    yield e
    for srv in (github, health):
        srv.shutdown()
        srv.server_close()
