#!/usr/bin/env python3
"""Moteur de mise à jour de l'appliance Spambuntu (bibliothèque standard uniquement).

Commandes :
    check      interroge les releases GitHub et écrit le résultat (utilisateur non privilégié)
    apply      télécharge, vérifie, installe et active une version (root)
    rollback   revient à la version précédente (root)
    status     affiche l'état courant
    version    affiche la version installée

Principes de sécurité :
  * une release n'est installée que si son archive porte une signature Ed25519 valide
    (clé publique locale) : sans clé publique, la mise à jour est refusée ;
  * l'archive est extraite avec des contrôles anti-traversée de chemin ;
  * l'activation est atomique (bascule du lien symbolique « current ») ;
  * si les hooks, le redémarrage ou le contrôle de santé échouent, retour arrière automatique.
"""
from __future__ import annotations

import argparse
import configparser
import contextlib
import fcntl
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

DEFAULT_CONF = "/etc/spambuntu/update.conf"
USER_AGENT = "spambuntu-updater"
MAX_BUNDLE_BYTES = 1024**3
MAX_EXTRACTED_BYTES = 2 * 1024**3
REQUEST_MAX_AGE = 600  # secondes : une demande plus ancienne n'est plus exécutée
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class UpdateError(Exception):
    """Erreur attendue, message lisible destiné à l'administrateur."""


# --------------------------------------------------------------------------- versions

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def normalize(text: str) -> str:
    text = text.strip()
    return text[1:] if text.startswith("v") else text


def version_key(text: str):
    """Clé de tri SemVer : une préversion est antérieure à la version finale."""
    m = _SEMVER.match(text.strip())
    if not m:
        raise ValueError(f"version invalide : {text!r}")
    major, minor, patch, pre = m.groups()
    if pre is None:
        pre_key = (1,)
    else:
        pre_key = (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")))
    return (int(major), int(minor), int(patch), pre_key)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- fichiers

def read_json(path: Path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json_atomic(path: Path, obj, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def set_link(link: Path, target: str) -> None:
    """Crée ou remplace un lien symbolique de façon atomique."""
    tmp = link.with_name(f".{link.name}.tmp")
    with contextlib.suppress(FileNotFoundError):
        tmp.unlink()
    tmp.symlink_to(target)
    os.replace(tmp, link)


# --------------------------------------------------------------------------- configuration

@dataclass
class Config:
    repo: str = "vincenttisseront/spambuntu"
    channel: str = "stable"
    token: str = ""
    api_base: str = "https://api.github.com"
    opt_dir: Path = Path("/opt/spambuntu")
    state_dir: Path = Path("/var/lib/spambuntu/update")
    backup_dir: Path = Path("/var/lib/spambuntu/backups")
    config_dir: Path = Path("/etc/spambuntu")
    log_file: Path = Path("/var/log/spambuntu/update.log")
    pubkey: Path = Path("/etc/spambuntu/update-pubkey.pem")
    health_url: str = "auto"
    health_timeout: int = 60
    restart_units: list = field(default_factory=lambda: ["spambuntu-webui.service"])
    keep_releases: int = 3
    systemctl: list = field(default_factory=lambda: ["systemctl"])
    allow_nonroot: bool = False

    @property
    def releases_dir(self) -> Path:
        return self.opt_dir / "releases"

    @property
    def current_link(self) -> Path:
        return self.opt_dir / "current"

    @property
    def previous_link(self) -> Path:
        return self.opt_dir / "previous"

    @property
    def user_dir(self) -> Path:
        """Répertoire inscriptible par la console web (jamais lu en confiance par root)."""
        return self.state_dir / "user"

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        path = path or os.environ.get("SPAMBUNTU_CONF", DEFAULT_CONF)
        cp = configparser.ConfigParser(interpolation=None)
        cp.read(path, encoding="utf-8")
        sec = cp["update"] if cp.has_section("update") else {}
        cfg = cls()

        def val(key):
            v = sec.get(key)
            return v.strip() if v and v.strip() else None

        for key in ("repo", "channel", "api_base", "health_url"):
            if val(key):
                setattr(cfg, key, val(key))
        for key in ("opt_dir", "state_dir", "backup_dir", "config_dir", "log_file", "pubkey"):
            if val(key):
                setattr(cfg, key, Path(val(key)))
        for key in ("health_timeout", "keep_releases"):
            if val(key):
                try:
                    setattr(cfg, key, int(val(key)))
                except ValueError:
                    raise UpdateError(f"{key} doit être un entier") from None
        if sec.get("restart_units") is not None:
            cfg.restart_units = sec.get("restart_units").replace(",", " ").split()
        if val("systemctl"):
            cfg.systemctl = shlex.split(val("systemctl"))
        cfg.allow_nonroot = (val("allow_nonroot") or "").lower() in ("1", "true", "yes")

        cfg.token = val("token") or ""
        if not cfg.token and val("token_file"):
            with contextlib.suppress(OSError):
                cfg.token = Path(val("token_file")).read_text().strip()
        cfg.token = cfg.token or os.environ.get("SPAMBUNTU_TOKEN", "")

        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.channel not in ("stable", "beta"):
            raise UpdateError("channel doit valoir « stable » ou « beta »")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", self.repo):
            raise UpdateError("repo doit avoir la forme « propriétaire/dépôt »")
        parsed = urllib.parse.urlparse(self.api_base)
        if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS):
            raise UpdateError("api_base doit utiliser https")

    def resolve_health_url(self):
        """URL du contrôle de santé, ou None si désactivé."""
        url = self.health_url
        if url.lower() == "none":
            return None
        if url != "auto":
            if urllib.parse.urlparse(url).scheme not in ("http", "https"):
                raise UpdateError("health_url doit être une URL http(s)")
            return url
        bind = "127.0.0.1:8080"
        try:
            for line in (self.config_dir / "webui.env").read_text().splitlines():
                m = re.match(r"\s*SPAMBUNTU_BIND\s*=\s*(\S+)", line)
                if m:
                    bind = m.group(1).strip("\"'")
        except OSError:
            pass
        host, _, port = bind.rpartition(":")
        if host in ("", "0.0.0.0", "::", "[::]"):
            host = "127.0.0.1"
        return f"http://{host}:{port}/healthz"


# --------------------------------------------------------------------------- versions installées

def current_dir(cfg: Config):
    link = cfg.current_link
    return link.resolve() if link.exists() else None


def current_version(cfg: Config) -> str:
    d = current_dir(cfg)
    if d:
        with contextlib.suppress(OSError, ValueError):
            v = (d / "VERSION").read_text().strip()
            version_key(v)
            return v
    return "0.0.0"


def previous_dir(cfg: Config):
    link = cfg.previous_link
    return link.resolve() if link.is_symlink() and link.exists() else None


# --------------------------------------------------------------------------- journal / progression

class Progress:
    """Écrit status.json (consulté par la console web) et le journal."""

    def __init__(self, cfg: Config, action: str, from_version: str, to_version: str):
        self.cfg = cfg
        self._last = 0.0
        self.data = {
            "action": action,
            "state": "running",
            "step": "start",
            "percent": 0,
            "message": "",
            "from": from_version,
            "to": to_version,
            "pid": os.getpid(),
            "started_at": now_iso(),
            "finished_at": None,
        }
        self._flush()

    def _flush(self) -> None:
        self._last = time.monotonic()
        with contextlib.suppress(OSError):
            write_json_atomic(self.cfg.state_dir / "status.json", self.data)

    def log(self, message: str) -> None:
        print(message, flush=True)
        with contextlib.suppress(OSError):
            self.cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cfg.log_file, "a", encoding="utf-8") as fh:
                fh.write(f"{now_iso()} {message}\n")

    def step(self, step: str, percent: float, message: str) -> None:
        self.data.update(step=step, percent=int(percent), message=message)
        self.log(message)
        self._flush()

    def progress(self, percent: float) -> None:
        if time.monotonic() - self._last >= 0.5:
            self.data["percent"] = int(percent)
            self._flush()

    def finish(self, state: str, message: str) -> None:
        self.data.update(
            state=state,
            message=message,
            finished_at=now_iso(),
            percent=100 if state == "success" else self.data["percent"],
        )
        self.log(message)
        self._flush()


def _pid_alive(pid) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_status(cfg: Config):
    st = read_json(cfg.state_dir / "status.json", None)
    if isinstance(st, dict) and st.get("state") == "running" and not _pid_alive(st.get("pid")):
        st = {**st, "state": "failed", "message": "Opération interrompue (le processus s'est arrêté)"}
    return st


def log_tail(cfg: Config, lines: int = 40) -> list:
    try:
        with open(cfg.log_file, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 65536))
            data = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    return data.splitlines()[-lines:]


# --------------------------------------------------------------------------- réseau / GitHub

class _DropAuthOnCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Ne transmet jamais le jeton à un autre hôte (ex. stockage des assets GitHub)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            new.headers.pop("Authorization", None)
        return new


_OPENER = urllib.request.build_opener(_DropAuthOnCrossHostRedirect())
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _DropAuthOnCrossHostRedirect())


def _opener_for(url: str):
    host = urllib.parse.urlparse(url).hostname
    return _LOCAL_OPENER if host in LOOPBACK_HOSTS else _OPENER


def http_open(cfg: Config, url: str, accept: str = "application/vnd.github+json"):
    headers = {"User-Agent": USER_AGENT, "Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
    if cfg.token:
        headers["Authorization"] = f"Bearer {cfg.token}"
    try:
        return _opener_for(url).open(urllib.request.Request(url, headers=headers), timeout=30)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            hint = "" if cfg.token else " (dépôt privé : renseignez un jeton en lecture dans update.conf)"
            raise UpdateError(f"Dépôt ou ressource introuvable{hint}") from None
        if exc.code in (401, 403):
            raise UpdateError(f"Accès refusé par GitHub (HTTP {exc.code}) : jeton invalide ou limite d'API atteinte") from None
        raise UpdateError(f"Erreur HTTP {exc.code} lors de l'appel à GitHub") from None
    except (urllib.error.URLError, OSError) as exc:
        raise UpdateError(f"Connexion impossible à GitHub : {getattr(exc, 'reason', exc)}") from None


def parse_release(rel: dict):
    """Transforme une release GitHub en dictionnaire exploitable, ou None si inutilisable."""
    if not isinstance(rel, dict) or rel.get("draft"):
        return None
    tag = str(rel.get("tag_name") or "")
    try:
        version_key(tag)
    except ValueError:
        return None
    version = normalize(tag)
    assets = {a.get("name"): a for a in rel.get("assets") or [] if isinstance(a, dict)}
    bundle = assets.get(f"spambuntu-{version}.tar.gz")
    sig = assets.get(f"spambuntu-{version}.tar.gz.sig")
    if not bundle or not sig:
        return None
    if any(a.get("state", "uploaded") != "uploaded" for a in (bundle, sig)):
        return None
    return {
        "version": version,
        "tag": tag,
        "name": rel.get("name") or tag,
        "notes": rel.get("body") or "",
        "published_at": rel.get("published_at"),
        "html_url": rel.get("html_url"),
        "prerelease": bool(rel.get("prerelease")),
        "size": int(bundle.get("size") or 0),
        "asset_url": bundle.get("url"),
        "sig_url": sig.get("url"),
    }


def find_release(cfg: Config, version: str | None = None):
    url = f"{cfg.api_base.rstrip('/')}/repos/{cfg.repo}/releases?per_page=30"
    with http_open(cfg, url) as resp:
        try:
            payload = json.load(resp)
        except ValueError:
            raise UpdateError("Réponse GitHub illisible") from None
    if not isinstance(payload, list):
        raise UpdateError("Réponse GitHub inattendue")
    candidates = [r for r in map(parse_release, payload) if r]
    if version:
        wanted = normalize(version)
        return next((r for r in candidates if r["version"] == wanted), None)
    if cfg.channel == "stable":
        candidates = [r for r in candidates if not r["prerelease"]]
    return max(candidates, key=lambda r: version_key(r["version"]), default=None)


def read_check(cfg: Config) -> dict:
    """Dernier résultat de recherche, avec la disponibilité recalculée par rapport à la version installée."""
    data = read_json(cfg.user_dir / "check.json", None)
    current = current_version(cfg)
    if not isinstance(data, dict):
        return {"checked_at": None, "current": current, "latest": None, "update_available": False, "error": None}
    latest = data.get("latest")
    available = False
    if isinstance(latest, dict):
        with contextlib.suppress(ValueError, KeyError):
            available = version_key(latest["version"]) > version_key(current)
    return {**data, "current": current, "update_available": available}


def check(cfg: Config) -> dict:
    current = current_version(cfg)
    old = read_json(cfg.user_dir / "check.json", None)
    result = {**(old if isinstance(old, dict) else {})}
    result.update(checked_at=now_iso(), current=current, channel=cfg.channel, repo=cfg.repo, error=None)
    try:
        latest = find_release(cfg)
        result["latest"] = latest
        result["update_available"] = bool(latest) and version_key(latest["version"]) > version_key(current)
    except UpdateError as exc:
        result["error"] = str(exc)
        result["update_available"] = False
    try:
        write_json_atomic(cfg.user_dir / "check.json", result)
    except OSError as exc:
        print(f"Avertissement : impossible d'écrire check.json ({exc})", file=sys.stderr)
    return read_check(cfg) | {"error": result["error"], "checked_at": result["checked_at"]}


# --------------------------------------------------------------------------- téléchargement / vérification

def download(cfg: Config, url: str, dest: Path, on_progress=None, expected_size: int = 0) -> None:
    done = 0
    with http_open(cfg, url, "application/octet-stream") as resp, open(dest, "wb") as out:
        total = int(resp.headers.get("Content-Length") or expected_size or 0)
        while True:
            chunk = resp.read(1 << 16)
            if not chunk:
                break
            done += len(chunk)
            if done > MAX_BUNDLE_BYTES:
                raise UpdateError("Archive anormalement volumineuse")
            out.write(chunk)
            if on_progress and total:
                on_progress(done / total)
    if expected_size and done != expected_size:
        raise UpdateError(f"Téléchargement incomplet ({done} octets reçus sur {expected_size})")


def verify_signature(cfg: Config, bundle: Path, sig: Path) -> None:
    if not cfg.pubkey.is_file():
        raise UpdateError(f"Clé publique de signature absente ({cfg.pubkey}) : mise à jour refusée")
    cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(cfg.pubkey),
           "-rawin", "-in", str(bundle), "-sigfile", str(sig)]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateError(f"Vérification de signature impossible : {exc}") from None
    if r.returncode != 0 or "Verified" not in r.stdout:
        raise UpdateError("Signature invalide : l'archive n'a pas été signée par la clé de confiance, installation refusée")


def safe_extract(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True)
    total = 0
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            p = PurePosixPath(m.name)
            if p.is_absolute() or ".." in p.parts:
                raise UpdateError(f"Chemin dangereux dans l'archive : {m.name}")
            if m.isdev() or m.isfifo() or m.islnk():
                raise UpdateError(f"Type de fichier interdit dans l'archive : {m.name}")
            if m.issym():
                if PurePosixPath(m.linkname).is_absolute():
                    raise UpdateError(f"Lien symbolique absolu interdit : {m.name}")
                resolved = os.path.normpath(os.path.join(os.path.dirname(m.name), m.linkname))
                if resolved.startswith(".."):
                    raise UpdateError(f"Lien symbolique sortant de l'archive : {m.name}")
            total += max(m.size, 0)
            if total > MAX_EXTRACTED_BYTES:
                raise UpdateError("Archive trop volumineuse une fois extraite")
        try:
            tar.extractall(dest, members=members, filter="data")
        except TypeError:  # Python < 3.12 sans backport du paramètre filter
            tar.extractall(dest, members=members)


def read_manifest(top: Path, version: str) -> dict:
    manifest = read_json(top / "manifest.json", None)
    if not isinstance(manifest, dict):
        raise UpdateError("manifest.json manquant ou illisible dans l'archive")
    try:
        file_version = (top / "VERSION").read_text().strip()
    except OSError:
        raise UpdateError("Fichier VERSION manquant dans l'archive") from None
    if normalize(str(manifest.get("version", ""))) != version or file_version != version:
        raise UpdateError("Le contenu de l'archive ne correspond pas à la version annoncée")
    return manifest


# --------------------------------------------------------------------------- étapes d'installation

def run_hook(p: Progress, release: Path, name: str, env_extra: dict) -> None:
    script = release / "hooks" / name
    if not script.is_file():
        return
    p.log(f"Exécution du hook {name}")
    try:
        r = subprocess.run(["/bin/bash", str(script)], env={**os.environ, **env_extra},
                           capture_output=True, text=True, timeout=900, cwd=str(release))
    except subprocess.TimeoutExpired:
        raise UpdateError(f"Le hook {name} a dépassé le délai de 15 minutes") from None
    for line in (r.stdout + r.stderr).splitlines():
        p.log(f"  {line}")
    if r.returncode != 0:
        raise UpdateError(f"Le hook {name} a échoué (code {r.returncode})")


def backup_config(cfg: Config, old: str, new: str) -> Path:
    cfg.backup_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(cfg.backup_dir, 0o700)
    dest = cfg.backup_dir / f"config-{old}-to-{new}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh, tarfile.open(fileobj=fh, mode="w:gz") as tar:
        if cfg.config_dir.is_dir():
            tar.add(cfg.config_dir, arcname="etc-spambuntu")
    backups = sorted(cfg.backup_dir.glob("config-*.tar.gz"), key=lambda f: f.stat().st_mtime)
    for stale in backups[:-5]:
        stale.unlink(missing_ok=True)
    return dest


def restart_services(cfg: Config, p: Progress, strict: bool = True) -> None:
    for unit in cfg.restart_units:
        p.log(f"Redémarrage de {unit}")
        error = None
        try:
            r = subprocess.run([*cfg.systemctl, "restart", unit], capture_output=True, text=True, timeout=180)
            if r.returncode != 0:
                error = (r.stderr or r.stdout).strip() or f"code {r.returncode}"
        except (OSError, subprocess.TimeoutExpired) as exc:
            error = str(exc)
        if error:
            message = f"Le redémarrage de {unit} a échoué : {error}"
            if strict:
                raise UpdateError(message)
            p.log(f"AVERTISSEMENT : {message}")


def wait_healthy(cfg: Config, p: Progress, version: str) -> None:
    url = cfg.resolve_health_url()
    if not url:
        p.log("Contrôle de santé désactivé")
        return
    opener = _opener_for(url)
    deadline = time.monotonic() + cfg.health_timeout
    last = "aucune réponse"
    while True:
        try:
            with opener.open(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), timeout=5) as resp:
                data = json.load(resp)
            if data.get("status") == "ok" and data.get("version") == version:
                p.log(f"Le service répond correctement en version {version}")
                return
            last = f"le service annonce la version {data.get('version')!r}"
        except (OSError, ValueError) as exc:
            last = str(exc)
        if time.monotonic() >= deadline:
            raise UpdateError(f"Le service ne répond pas correctement après {cfg.health_timeout} s ({last})")
        time.sleep(1.0)


def prune_releases(cfg: Config, p: Progress) -> None:
    keep = {d for d in (current_dir(cfg), previous_dir(cfg)) if d}
    dirs = []
    for d in cfg.releases_dir.iterdir():
        if d.is_dir() and not d.name.startswith("."):
            with contextlib.suppress(ValueError):
                dirs.append((version_key(d.name), d))
    spare = max(cfg.keep_releases - len(keep), 0)
    for _, d in sorted(dirs, key=lambda t: t[0], reverse=True):
        if d.resolve() in keep:
            continue
        if spare > 0:
            spare -= 1
            continue
        p.log(f"Suppression de l'ancienne version {d.name}")
        shutil.rmtree(d, ignore_errors=True)


def acquire_lock(cfg: Config):
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    fh = open(cfg.state_dir / "apply.lock", "a+")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise UpdateError("Une opération de mise à jour est déjà en cours") from None
    return fh


def require_root(cfg: Config) -> None:
    if os.geteuid() != 0 and not cfg.allow_nonroot:
        raise UpdateError("Cette commande doit être exécutée en root")


def read_request(cfg: Config) -> str:
    """Lit (et consomme) la demande déposée par la console web. Seule une version SemVer stricte est acceptée."""
    path = cfg.user_dir / "apply-request.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            if time.time() - os.fstat(fh.fileno()).st_mtime > REQUEST_MAX_AGE:
                raise ValueError("demande périmée")
            data = json.loads(fh.read(1024))
        version = normalize(str(data["version"]))
        version_key(version)
        return version
    except (OSError, ValueError, KeyError, TypeError):
        raise UpdateError("Demande de mise à jour absente ou invalide") from None
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


# --------------------------------------------------------------------------- retour arrière

def rollback_to(cfg: Config, p: Progress, target: Path, restore_previous, failed_dir=None) -> None:
    version = (target / "VERSION").read_text().strip()
    p.step("rollback", 95, f"Retour à la version {version}…")
    set_link(cfg.current_link, os.path.relpath(target, cfg.opt_dir))
    if restore_previous:
        set_link(cfg.previous_link, os.path.relpath(restore_previous, cfg.opt_dir))
    else:
        with contextlib.suppress(FileNotFoundError):
            cfg.previous_link.unlink()
    env = {"SPAMBUNTU_FROM": "", "SPAMBUNTU_TO": version, "SPAMBUNTU_NEW_DIR": str(target),
           "SPAMBUNTU_OLD_DIR": "", "SPAMBUNTU_ROLLBACK": "1"}
    try:
        run_hook(p, target, "post-update.sh", env)
    except UpdateError as exc:
        p.log(f"AVERTISSEMENT : {exc}")
    restart_services(cfg, p, strict=False)
    wait_healthy(cfg, p, version)
    if failed_dir and failed_dir.exists():
        shutil.rmtree(failed_dir, ignore_errors=True)


# --------------------------------------------------------------------------- commandes

def apply_update(cfg: Config, requested: str | None = None, from_request: bool = False, force: bool = False) -> int:
    require_root(cfg)
    lock = acquire_lock(cfg)
    current = current_version(cfg)
    old_dir = current_dir(cfg)
    prev_before = previous_dir(cfg)
    p = Progress(cfg, "update", current, requested or "?")
    staging = final = None
    swapped = False
    try:
        if from_request:
            requested = read_request(cfg)
            p.data["to"] = requested
        p.step("lookup", 2, "Recherche de la version à installer…")
        release = find_release(cfg, requested)
        if not release:
            raise UpdateError(f"Version {requested} introuvable" if requested else "Aucune version publiée")
        target = release["version"]
        p.data["to"] = target
        if version_key(target) <= version_key(current) and not force:
            p.finish("success", f"Déjà à jour (version {current})")
            return 0
        if target == current:
            raise UpdateError(f"La version {target} est déjà installée")

        p.step("preflight", 5, f"Préparation de la mise à jour {current} → {target}…")
        if not cfg.pubkey.is_file():
            raise UpdateError(f"Clé publique de signature absente ({cfg.pubkey}) : mise à jour refusée")
        cfg.releases_dir.mkdir(parents=True, exist_ok=True)
        needed = release["size"] * 3 + 200 * 1024 * 1024
        free = shutil.disk_usage(cfg.releases_dir).free
        if free < needed:
            raise UpdateError(f"Espace disque insuffisant ({free // 2**20} Mo libres, {needed // 2**20} Mo requis)")

        dl = cfg.state_dir / "download"
        shutil.rmtree(dl, ignore_errors=True)
        dl.mkdir(parents=True)
        bundle = dl / f"spambuntu-{target}.tar.gz"
        sig = dl / f"{bundle.name}.sig"
        p.step("download", 8, f"Téléchargement de la version {target}…")
        download(cfg, release["asset_url"], bundle, lambda f: p.progress(8 + 52 * f), release["size"])
        download(cfg, release["sig_url"], sig)

        p.step("verify", 62, "Vérification de la signature…")
        verify_signature(cfg, bundle, sig)
        p.log("Signature valide")

        p.step("extract", 68, "Extraction de l'archive…")
        staging = cfg.releases_dir / f".staging-{target}-{os.getpid()}"
        safe_extract(bundle, staging)
        top = staging / f"spambuntu-{target}"
        if not top.is_dir():
            raise UpdateError("Structure d'archive inattendue")
        manifest = read_manifest(top, target)
        min_from = manifest.get("min_from_version")
        if min_from and version_key(current) < version_key(str(min_from)):
            raise UpdateError(f"Cette version exige d'abord la version {min_from} (installée : {current})")

        p.step("backup", 72, "Sauvegarde de la configuration…")
        p.log(f"Sauvegarde : {backup_config(cfg, current, target)}")
        env = {"SPAMBUNTU_FROM": current, "SPAMBUNTU_TO": target, "SPAMBUNTU_NEW_DIR": str(top),
               "SPAMBUNTU_OLD_DIR": str(old_dir or ""), "SPAMBUNTU_ROLLBACK": ""}
        run_hook(p, top, "pre-update.sh", env)

        p.step("install", 78, "Installation de la nouvelle version…")
        final = cfg.releases_dir / target
        if final.exists():
            if old_dir and final.resolve() == old_dir:
                raise UpdateError(f"La version {target} est déjà active")
            shutil.rmtree(final)
        os.rename(top, final)
        if old_dir:
            set_link(cfg.previous_link, os.path.relpath(old_dir, cfg.opt_dir))
        set_link(cfg.current_link, f"releases/{target}")
        swapped = True

        env["SPAMBUNTU_NEW_DIR"] = str(final)
        p.step("migrate", 84, "Migrations et mise à jour des unités système…")
        run_hook(p, final, "post-update.sh", env)
        p.step("restart", 90, "Redémarrage des services…")
        restart_services(cfg, p)
        p.step("health", 94, "Contrôle de santé…")
        wait_healthy(cfg, p, target)

        prune_releases(cfg, p)
        p.finish("success", f"Mise à jour vers la version {target} terminée")
        return 0
    except Exception as exc:  # noqa: BLE001 - toute erreur doit déclencher le retour arrière
        message = str(exc) if isinstance(exc, UpdateError) else f"{type(exc).__name__} : {exc}"
        p.log(f"ERREUR : {message}")
        if swapped and old_dir:
            try:
                rollback_to(cfg, p, old_dir, prev_before, failed_dir=final)
                p.finish("rolled_back", f"Échec de la mise à jour ({message}). Retour automatique à la version {current}.")
            except Exception as rb_exc:  # noqa: BLE001
                p.finish("failed", f"Échec ({message}) puis échec du retour arrière ({rb_exc}) : intervention manuelle requise")
        else:
            p.finish("failed", message)
        return 1
    finally:
        for path in (staging, cfg.state_dir / "download"):
            if path:
                shutil.rmtree(path, ignore_errors=True)
        lock.close()


def manual_rollback(cfg: Config) -> int:
    require_root(cfg)
    lock = acquire_lock(cfg)
    try:
        cur, prev = current_dir(cfg), previous_dir(cfg)
        if not prev or not cur:
            raise UpdateError("Aucune version précédente disponible")
        prev_v = (prev / "VERSION").read_text().strip()
        p = Progress(cfg, "rollback", current_version(cfg), prev_v)
        try:
            rollback_to(cfg, p, prev, restore_previous=cur)
            p.finish("success", f"Retour à la version {prev_v} effectué")
            return 0
        except Exception as exc:  # noqa: BLE001
            p.finish("failed", f"Échec du retour arrière : {exc}")
            return 1
    finally:
        lock.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-update", description=__doc__.split("\n\n")[0])
    ap.add_argument("--conf", help=f"fichier de configuration (défaut : {DEFAULT_CONF})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="rechercher une nouvelle version")
    c.add_argument("--json", action="store_true")
    a = sub.add_parser("apply", help="installer une version (root)")
    a.add_argument("--version", help="version précise (défaut : la plus récente du canal)")
    a.add_argument("--from-request", action="store_true", help="version demandée par la console web")
    a.add_argument("--force", action="store_true", help="autoriser une version identique ou antérieure")
    sub.add_parser("rollback", help="revenir à la version précédente (root)")
    s = sub.add_parser("status", help="afficher l'état")
    s.add_argument("--json", action="store_true")
    sub.add_parser("version", help="afficher la version installée")
    args = ap.parse_args(argv)

    try:
        cfg = Config.load(args.conf)
        if args.cmd == "version":
            print(current_version(cfg))
        elif args.cmd == "check":
            result = check(cfg)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            elif result["error"]:
                print(f"Erreur : {result['error']}", file=sys.stderr)
            elif result["update_available"]:
                print(f"Mise à jour disponible : {result['current']} → {result['latest']['version']}")
            else:
                print(f"À jour (version {result['current']})")
            return 1 if result["error"] else 0
        elif args.cmd == "status":
            out = {"current": current_version(cfg), "check": read_check(cfg), "apply": read_status(cfg)}
            print(json.dumps(out, ensure_ascii=False, indent=2) if args.json else
                  f"Version installée : {out['current']}\nDernière opération : {(out['apply'] or {}).get('message', 'aucune')}")
        elif args.cmd == "apply":
            return apply_update(cfg, args.version, args.from_request, args.force)
        elif args.cmd == "rollback":
            return manual_rollback(cfg)
    except UpdateError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
