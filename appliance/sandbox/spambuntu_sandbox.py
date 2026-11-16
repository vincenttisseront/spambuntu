#!/usr/bin/env python3
"""Sandbox de la passerelle Spambuntu : extraction des pièces jointes et des liens, analyse statique, verdict.

Premier niveau (sans détonation) de la défense des pièces jointes : il tourne dans le service local
`spambuntu-sandboxd`, appelé par Rspamd. Les niveaux suivants (détonation dans un worker isolé, analyse IA du
rapport) viennent s'ajouter à ce verdict sans le remplacer.

  spambuntu-sandboxctl analyze [--mode MODE] < message.eml    verdict JSON d'un message (sans cache)
  spambuntu-sandboxctl show                                    configuration active
  spambuntu-sandboxctl check                                   la configuration est-elle valide ?

Principes
  * le message est une entrée hostile : tailles, nombre de parties, profondeur d'archives et expansion sont bornés,
    rien n'est jamais exécuté, aucun fichier n'est écrit sur le disque (tout se passe en mémoire) ;
  * le verdict est déterministe et explicable (liste de constats avec leurs points) ;
  * mode « monitor » : le verdict est calculé et journalisé sans effet sur la livraison ;
  * une panne ne bloque jamais le courrier : la réponse est « erreur », le moteur de règles décide de la suite.
Bibliothèque standard uniquement.
"""
from __future__ import annotations

import argparse
import email
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import time
import zipfile
from pathlib import Path

CONFIG_PATH = "/etc/spambuntu-sandbox/sandbox.json"
CACHE_PATH = "/var/lib/spambuntu/sandbox/cache.db"
ANALYSIS_VERSION = 1            # à incrémenter quand les heuristiques changent (invalide le cache)

MODES = ("off", "monitor", "enforce")
GROUPS = {
    "office": "Documents Office (macros, DDE, modèles distants)",
    "pdf": "PDF (JavaScript, actions automatiques)",
    "archive": "Archives (zip, rar, 7z...) et leur contenu",
    "script": "Scripts (js, vbs, hta, ps1, bat...)",
    "lnk": "Raccourcis Windows (.lnk)",
    "iso": "Images disque (iso, img, vhd)",
    "html": "Pages HTML et SVG en pièce jointe",
    "executable": "Exécutables (exe, dll, elf...)",
    "rtf": "Documents RTF",
}
DEFAULTS = {
    "mode": "off",
    "eligible_types": list(GROUPS),
    "max_file_mb": 20,
    "max_parts": 30,
    "max_archive_depth": 2,
    "max_archive_members": 200,
    "max_expand_mb": 100,
    "suspicious_at": 60,
    "malicious_at": 95,
    "cache_ttl_hours": 24,
}
LIMITS = {"max_file_mb": (1, 100), "max_parts": (1, 100), "max_archive_depth": (0, 3), "max_archive_members": (1, 1000),
          "max_expand_mb": (1, 500), "suspicious_at": (1, 100), "malicious_at": (1, 100), "cache_ttl_hours": (1, 168)}

SYMBOLS = {
    "malicious": "SPAMBUNTU_SANDBOX_MALICIOUS",
    "suspicious": "SPAMBUNTU_SANDBOX_SUSPICIOUS",
    "clean": "SPAMBUNTU_SANDBOX_CLEAN",
    "error": "SPAMBUNTU_SANDBOX_ERROR",
}
URL_SYMBOLS = {"malicious": "SPAMBUNTU_SANDBOX_URL_MALICIOUS", "suspicious": "SPAMBUNTU_SANDBOX_URL_SUSPICIOUS"}


class SandboxError(Exception):
    """Configuration invalide (message destiné à l'administrateur)."""


# --------------------------------------------------------------------------- configuration

def validate_config(raw) -> dict:
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise SandboxError("Configuration du sandbox : objet JSON attendu")
    unknown = set(raw) - set(DEFAULTS)
    if unknown:
        raise SandboxError(f"Réglage inconnu : {sorted(unknown)[0]!r}")
    cfg = dict(DEFAULTS)
    cfg["eligible_types"] = list(DEFAULTS["eligible_types"])
    if "mode" in raw:
        if raw["mode"] not in MODES:
            raise SandboxError("Mode invalide (off, monitor ou enforce)")
        cfg["mode"] = raw["mode"]
    if "eligible_types" in raw:
        types = raw["eligible_types"]
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise SandboxError("Types analysés : liste attendue")
        bad = [t for t in types if t not in GROUPS]
        if bad:
            raise SandboxError(f"Type inconnu : {bad[0][:30]!r}")
        cfg["eligible_types"] = [g for g in GROUPS if g in types]            # ordre stable, sans doublon
    for key, (low, high) in LIMITS.items():
        if key in raw:
            value = raw[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise SandboxError(f"{key} : entier entre {low} et {high} attendu")
            cfg[key] = value
    if cfg["suspicious_at"] >= cfg["malicious_at"]:
        raise SandboxError("Le seuil « suspect » doit être inférieur au seuil « malveillant »")
    return cfg


def load_config(path: str | os.PathLike = CONFIG_PATH) -> dict:
    """Configuration active ; en cas de fichier absent ou invalide : sandbox désactivé (jamais d'erreur côté courrier)."""
    try:
        return validate_config(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, SandboxError):
        return validate_config({})


def _fingerprint(cfg: dict) -> str:
    keys = {k: cfg[k] for k in ("eligible_types", "max_file_mb", "max_archive_depth", "max_archive_members", "max_expand_mb")}
    return hashlib.sha256((json.dumps(keys, sort_keys=True) + f"|{ANALYSIS_VERSION}").encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- nature des fichiers

_EXT_GROUP = {}
for _group, _exts in {
    "office": "doc docx docm dot dotm xls xlsx xlsm xlsb xlt xltm xla xlam ppt pptx pptm pps ppsm ppsx pot potm odt ods odp one",
    "pdf": "pdf",
    "rtf": "rtf",
    "archive": "zip rar 7z gz tgz tar bz2 xz cab arj lzh ace z zst",
    "script": "js jse vbs vbe wsf wsh hta ps1 psm1 bat cmd sh py pl rb jar sct",
    "lnk": "lnk url scf",
    "iso": "iso img vhd vhdx dmg udf",
    "html": "html htm xhtml shtml svg mht mhtml",
    "executable": "exe dll scr com pif cpl msi msp sys drv ocx elf bin appx msix",
}.items():
    for _e in _exts.split():
        _EXT_GROUP[_e] = _group
_BENIGN_EXT = set("txt csv jpg jpeg png gif bmp tif tiff webp ico mp3 mp4 wav avi mov log json xml md ics vcf eml".split())
_EXEC_EXT = set("exe scr js jse vbs vbe wsf wsh hta lnk iso img vhd vhdx jar bat cmd ps1 msi dll com pif cpl reg sct msp appx".split())
_DOC_EXT = set("pdf doc docx xls xlsx ppt pptx txt rtf jpg jpeg png gif csv odt ods".split())


def clean_name(name: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f<>\"]", "", name or "")[:80]


def ext_of(name: str) -> str:
    base = (name or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return base.rpartition(".")[2] if "." in base else ""


def sniff(data: bytes, filename: str = "") -> str:
    """Groupe de contenu d'après les premiers octets (le nom ne sert qu'à départager) :
    office, pdf, rtf, archive, script, lnk, iso, html, executable, ooxml (interne), image, other."""
    head = data[:4096]
    ext = ext_of(filename)
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except (zipfile.BadZipFile, OSError, ValueError):
            names = []
        if "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
            return "office"
        return "archive"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "office"
    if data[:5] == b"%PDF-" or b"%PDF-" in head[:1024]:
        return "pdf"
    if data[:5] == b"{\\rtf" or data[:4] == b"{\\rt":
        return "rtf"
    if data[:2] == b"MZ" or data[:4] == b"\x7fELF" or data[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "executable"
    if data[:4] == b"L\x00\x00\x00" and data[4:20] == b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00F":
        return "lnk"
    if data[:6] in (b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c") or data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00" \
            or data[:4] == b"MSCF" or (len(data) > 262 and data[257:262] == b"ustar"):
        return "archive"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if data[:8] == b"conectix" or data[:8] == b"vhdxfile":
        return "iso"
    if data[:3] == b"\xff\xd8\xff" or data[:8] == b"\x89PNG\r\n\x1a\n" or data[:6] in (b"GIF87a", b"GIF89a"):
        return "image"
    group = _EXT_GROUP.get(ext)
    text = head[:2048].lstrip().lower()
    if group in ("script", "html", "lnk") or text.startswith((b"<html", b"<!doctype html", b"<svg", b"<?xml", b"<script", b"<head", b"<body")):
        if group == "script":
            return "script"
        if text.startswith((b"<html", b"<!doctype html", b"<svg", b"<script", b"<head", b"<body")) or group == "html":
            return "html"
    if group in ("script", "html"):
        return group
    if group and group not in ("office", "pdf", "archive", "executable", "iso", "rtf", "lnk"):
        return group
    return "other"


# --------------------------------------------------------------------------- analyse statique

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_AUTOEXEC = (b"autoopen", b"auto_open", b"document_open", b"workbook_open", b"autoexec", b"document_new", b"auto_close")
_VBA_RISK = (b"createobject", b"wscript.shell", b"shell(", b"powershell", b"urldownloadtofile", b"environ(", b"xmlhttp",
             b"adodb.stream", b"cmd.exe", b"mshta", b"regsvr32", b"certutil")
_SCRIPT_RISK = (b"wscript.shell", b"activexobject", b"-encodedcommand", b"-enc ", b"invoke-expression", b"iex(", b"iex (",
                b"downloadstring", b"downloadfile", b"frombase64string", b"certutil -urlcache", b"bitsadmin", b"mshta", b"net.webclient",
                b"start-process", b"scripting.filesystemobject", b"wscript.sleep")
_LNK_RISK = (b"powershell", b"cmd.exe", b"mshta", b"wscript", b"cscript", b"rundll32", b"regsvr32", b"-enc", b"bitsadmin", b"certutil")


def _has(data: bytes, needles) -> list[bytes]:
    low = data.lower()
    low16 = low.replace(b"\x00", b"")           # texte UTF-16 « aplati » : suffisant pour des mots-clés ASCII
    return [n for n in needles if n in low or n in low16]


def _f(code: str, points: int, text: str, part: str) -> dict:
    return {"code": code, "points": points, "text": text, "part": part}


def _analyze_office(data: bytes, part: str, ooxml: bool) -> list[dict]:
    out = []
    if ooxml:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = zf.namelist()
        except (zipfile.BadZipFile, OSError, ValueError):
            return [_f("malformed", 30, "Document Office illisible (archive corrompue)", part)]
        vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
        if vba:
            out.append(_f("macro", 45, "Contient des macros VBA", part))
            try:
                blob = zf.read(vba[0])[:2_000_000]
            except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                blob = b""
            if _has(blob, _AUTOEXEC):
                out.append(_f("autoexec", 20, "Les macros se lancent à l'ouverture du document", part))
            if _has(blob, _VBA_RISK):
                out.append(_f("macro_risk", 30, "Les macros appellent des commandes système ou du réseau", part))
        if any("/macrosheets/" in n.lower() for n in names):
            out.append(_f("xlm_macro", 60, "Contient des feuilles de macros Excel 4.0 (XLM)", part))
        if any(n.lower().startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")) for n in names):
            out.append(_f("embedded_object", 40, "Contient un objet incorporé", part))
        for n in names:
            low = n.lower()
            if low.endswith(".rels") and "word/_rels" in low or low.endswith(".rels") and "_rels/" in low:
                try:
                    rel = zf.read(n)[:200_000].lower()
                except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                    continue
                if b"targetmode=\"external\"" in rel and (b"attachedtemplate" in rel or b"oleobject" in rel or b"frame" in rel):
                    out.append(_f("remote_template", 55, "Charge un modèle ou un objet distant (injection de modèle)", part))
                    break
        for n in names:
            if n.lower() in ("word/document.xml", "xl/sharedstrings.xml"):
                try:
                    body = zf.read(n)[:5_000_000].lower()
                except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
                    continue
                if b"ddeauto" in body or re.search(rb"instrtext[^>]*>\s*dde", body):
                    out.append(_f("dde", 70, "Utilise DDE pour lancer une commande", part))
                    break
        return out
    # OLE (.doc/.xls/.ppt anciens)
    if _has(data, (b"_vba_project", b"vba/")) or b"V\x00B\x00A\x00" in data[:2_000_000]:
        out.append(_f("macro", 45, "Contient des macros VBA", part))
        if _has(data, _AUTOEXEC):
            out.append(_f("autoexec", 20, "Les macros se lancent à l'ouverture du document", part))
        if _has(data, _VBA_RISK):
            out.append(_f("macro_risk", 30, "Les macros appellent des commandes système ou du réseau", part))
    if b"ddeauto" in data.lower():
        out.append(_f("dde", 70, "Utilise DDE pour lancer une commande", part))
    return out


def _analyze_pdf(data: bytes, part: str) -> list[dict]:
    out = []
    low = data.lower()
    if b"/launch" in low:
        out.append(_f("pdf_launch", 70, "Le PDF peut lancer un programme", part))
    if b"/javascript" in low or re.search(rb"/js\b", low):
        out.append(_f("pdf_js", 40, "Le PDF contient du JavaScript", part))
    if b"/openaction" in low or b"/aa" in low:
        out.append(_f("pdf_auto", 20, "Une action se déclenche à l'ouverture du PDF", part))
    if b"/embeddedfile" in low:
        out.append(_f("pdf_embedded", 30, "Le PDF contient un fichier incorporé", part))
    if re.search(rb"/[a-z]*#[0-9a-f]{2}[a-z#0-9a-f]*", low) and re.search(rb"/j#|/js#|/javascr|/open#|/launch#", low):
        out.append(_f("pdf_obfuscated", 30, "Mots-clés du PDF dissimulés (codage #xx)", part))
    return out


def _analyze_html(data: bytes, part: str) -> list[dict]:
    out = []
    low = data[:2_000_000].lower()
    if b"new blob(" in low and (b"atob(" in low or b"uint8array" in low) and (b"createobjecturl" in low or b"msSaveOrOpenBlob".lower() in low or b"download=" in low):
        out.append(_f("html_smuggling", 70, "Page HTML qui reconstruit et télécharge un fichier (« HTML smuggling »)", part))
    if b"type=\"password\"" in low.replace(b"'", b'"').replace(b" ", b"") or b"type=password" in low.replace(b" ", b""):
        if b"<form" in low:
            out.append(_f("html_credentials", 55, "Formulaire de saisie de mot de passe dans une pièce jointe HTML", part))
    if low.count(b"unescape(") + low.count(b"string.fromcharcode") + low.count(b"eval(") >= 4:
        out.append(_f("html_obfuscated", 30, "Code JavaScript fortement obscurci", part))
    return out


def _analyze_script(data: bytes, part: str) -> list[dict]:
    out = [_f("script", 60, "Script exécutable en pièce jointe", part)]
    if _has(data, _SCRIPT_RISK):
        out.append(_f("script_risk", 35, "Le script télécharge ou exécute des commandes", part))
    return out


def _analyze_archive(data: bytes, part: str, cfg: dict, depth: int, cache_ctx) -> list[dict]:
    out = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, OSError, ValueError):
        return out                      # rar, 7z, tar... : contenu non inspecté à ce niveau (le worker s'en chargera)
    if len(infos) > cfg["max_archive_members"]:
        out.append(_f("archive_many", 40, f"Archive de plus de {cfg['max_archive_members']} fichiers", part))
        infos = infos[: cfg["max_archive_members"]]
    expand = sum(i.file_size for i in infos)
    comp = max(1, sum(i.compress_size for i in infos))
    if expand > cfg["max_expand_mb"] * 1024 * 1024 or (expand > 50 * 1024 * 1024 and expand / comp > 200):
        out.append(_f("archive_bomb", 60, "Taille décompressée anormale (bombe de décompression possible) : contenu non ouvert", part))
        return out
    encrypted = [i for i in infos if i.flag_bits & 0x1]
    if encrypted:
        out.append(_f("archive_encrypted", 40, "Archive protégée par mot de passe : contenu invisible pour les filtres", part))
    worst = None
    for info in infos:
        if info.is_dir():
            continue
        inner = f"{part}/{clean_name(info.filename)}"
        name = info.filename
        ext = ext_of(name)
        chain = name.lower().rsplit("/", 1)[-1].split(".")
        if len(chain) >= 3 and chain[-1] in _EXEC_EXT and chain[-2] in _DOC_EXT:
            out.append(_f("double_extension", 90, f"Double extension trompeuse : {clean_name(name.rsplit('/', 1)[-1])}", inner))
        elif ext in _EXEC_EXT:
            out.append(_f("archive_exec", 55, f"L'archive contient un fichier exécutable ou un script ({ext})", inner))
        if info.flag_bits & 0x1 or info.file_size > cfg["max_file_mb"] * 1024 * 1024:
            continue
        if depth >= cfg["max_archive_depth"]:
            if ext_of(name) in ("zip", "rar", "7z", "gz", "iso", "img"):
                worst = worst or _f("archive_deep", 25, "Archive imbriquée au-delà de la profondeur analysée", part)
            continue
        try:
            inner_data = zf.open(info).read(cfg["max_file_mb"] * 1024 * 1024 + 1)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError, ValueError):
            continue
        if len(inner_data) > cfg["max_file_mb"] * 1024 * 1024:
            continue
        if depth + 1 and ext in ("zip", "rar", "7z"):
            out.append(_f("archive_nested", 25, "Archive dans une archive", inner))
        out.extend(analyze_content(inner_data, name, inner, cfg, depth + 1, cache_ctx))
    if worst:
        out.append(worst)
    return out


def analyze_content(data: bytes, filename: str, part: str, cfg: dict, depth: int = 0, cache_ctx=None) -> list[dict]:
    """Constats pour un fichier (et son contenu s'il s'agit d'une archive). Rien n'est exécuté."""
    if EICAR in data[:2048]:
        return [_f("eicar", 100, "Fichier de test antivirus EICAR", part)]
    kind = sniff(data, filename)
    claimed = ext_of(filename)
    out: list[dict] = []
    if kind not in cfg["eligible_types"] and kind not in ("image", "other"):
        return out
    if kind == "office":
        out = _analyze_office(data, part, ooxml=data[:2] == b"PK")
    elif kind == "pdf":
        out = _analyze_pdf(data, part)
    elif kind == "rtf":
        low = data[:3_000_000].lower()
        if b"\\objdata" in low or b"\\objupdate" in low:
            out = [_f("rtf_object", 60, "Document RTF avec objet OLE incorporé", part)]
    elif kind == "archive":
        out = _analyze_archive(data, part, cfg, depth, cache_ctx)
    elif kind == "script":
        out = _analyze_script(data, part)
    elif kind == "lnk":
        out = [_f("lnk", 70, "Raccourci Windows en pièce jointe", part)]
        if _has(data, _LNK_RISK):
            out.append(_f("lnk_risk", 30, "Le raccourci lance un interpréteur de commandes", part))
    elif kind == "iso":
        out = [_f("disk_image", 50, "Image disque en pièce jointe (contourne le marquage « téléchargé d'Internet »)", part)]
    elif kind == "html":
        out = _analyze_html(data, part)
    elif kind == "executable":
        out = [_f("executable", 90, "Programme exécutable en pièce jointe", part)]
    # extension qui ment sur la nature réelle du fichier
    if claimed in _DOC_EXT and kind in ("executable", "script", "lnk", "iso"):
        out.append(_f("type_mismatch", 70, f"L'extension .{claimed} ne correspond pas au contenu réel ({kind})", part))
    return out


# --------------------------------------------------------------------------- extraction du message

_URL_RE = re.compile(r"https?://[^\s<>\"'\\^`{}|]+", re.I)


def normalize_url(url: str) -> str:
    url = url.strip().rstrip(".,;:!?)]'\"")
    url = url.split("#", 1)[0]
    m = re.match(r"(?i)(https?)://([^/?]+)(.*)", url)
    if not m:
        return ""
    return f"{m.group(1).lower()}://{m.group(2).lower()}{m.group(3)}"[:500]


def extract(raw: bytes, cfg: dict) -> dict:
    """{"parts": [{filename, content_type, data, size}], "urls": [...], "truncated": bool}"""
    msg = email.message_from_bytes(raw)
    parts, urls, truncated = [], [], False
    limit = cfg["max_file_mb"] * 1024 * 1024

    def walk(m, depth=0):
        nonlocal truncated
        if depth > 6:
            return
        if m.is_multipart():
            for sub in m.get_payload():
                if hasattr(sub, "is_multipart"):
                    walk(sub, depth + 1)
            return
        ctype = m.get_content_type()
        if ctype == "message/rfc822":
            payload = m.get_payload()
            for sub in payload if isinstance(payload, list) else []:
                walk(sub, depth + 1)
            return
        name = m.get_filename() or ""
        disp = (m.get("Content-Disposition") or "").lower()
        is_text = ctype in ("text/plain", "text/html")
        if is_text and not name and "attachment" not in disp:
            try:
                text = m.get_payload(decode=True) or b""
            except Exception:
                return
            for url in _URL_RE.findall(text[:2_000_000].decode("utf-8", "replace")):
                norm = normalize_url(url)
                if norm and norm not in urls and len(urls) < 50:
                    urls.append(norm)
            return
        if ctype.startswith(("image/", "audio/", "video/")) and "attachment" not in disp and not name:
            return                                          # image en ligne : sans risque à ce niveau
        try:
            data = m.get_payload(decode=True)
        except Exception:
            return
        if not isinstance(data, (bytes, bytearray)) or not data:
            return
        if len(parts) >= cfg["max_parts"]:
            truncated = True
            return
        parts.append({"filename": clean_name(name) or f"partie-{len(parts) + 1}", "content_type": ctype, "data": bytes(data), "size": len(data)})

    walk(msg)
    for p in parts:
        p["oversize"] = p["size"] > limit
    return {"parts": parts, "urls": urls, "truncated": truncated}


# --------------------------------------------------------------------------- cache

class VerdictCache:
    """Cache SQLite des analyses par empreinte SHA-256 (une campagne n'est analysée qu'une fois)."""

    def __init__(self, path: str | os.PathLike = CACHE_PATH):
        self.path = str(path)

    def _conn(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, expires INTEGER NOT NULL, value TEXT NOT NULL)")
        return conn

    def get(self, key: str, now: float | None = None):
        try:
            with self._conn() as conn:
                row = conn.execute("SELECT value FROM cache WHERE key = ? AND expires > ?", (key, int(now or time.time()))).fetchone()
            return json.loads(row[0]) if row else None
        except (sqlite3.Error, ValueError, OSError):
            return None

    def put(self, key: str, value, ttl_hours: int, now: float | None = None) -> None:
        now = int(now or time.time())
        try:
            with self._conn() as conn:
                conn.execute("INSERT OR REPLACE INTO cache VALUES (?, ?, ?)", (key, now + ttl_hours * 3600, json.dumps(value)))
                if now % 17 == 0:
                    conn.execute("DELETE FROM cache WHERE expires <= ?", (now,))
        except (sqlite3.Error, OSError):
            pass


# --------------------------------------------------------------------------- verdict

def verdict_for(score: int, cfg: dict) -> str:
    if score >= cfg["malicious_at"]:
        return "malicious"
    if score >= cfg["suspicious_at"]:
        return "suspicious"
    return "clean"


def fuse(part_scores: list[int]) -> int:
    """Score du message : la pièce la plus dangereuse, plus 10 points par autre pièce à risque (plafonné à 100)."""
    risky = sorted((s for s in part_scores if s > 0), reverse=True)
    if not risky:
        return 0
    return min(100, risky[0] + 10 * (len(risky) - 1))


def symbols_for(verdict: str) -> list[str]:
    return [SYMBOLS[verdict]] if verdict in SYMBOLS else []


def explain(findings: list[dict], verdict: str) -> str:
    if not findings:
        return "Aucune pièce jointe à risque."
    top = sorted(findings, key=lambda f: -f["points"])[:3]
    return " ; ".join(f"{f['text']} ({f['part']})" if f["part"] else f["text"] for f in top)[:300]


def analyze_message(raw: bytes, cfg: dict | None = None, cache: VerdictCache | None = None) -> dict:
    """Verdict statique d'un message complet.

    {"mode", "verdict": none|clean|suspicious|malicious, "score", "symbols", "explanation", "findings", "parts", "urls", "cached"}
    """
    cfg = cfg or load_config()
    if cfg["mode"] == "off":
        return {"mode": "off", "verdict": "none", "score": 0, "symbols": [], "explanation": "", "findings": [], "parts": [], "urls": [], "cached": 0}
    ex = extract(raw, cfg)
    fp = _fingerprint(cfg)
    findings, parts_out, scores, cached = [], [], [], 0
    for p in ex["parts"]:
        data, name = p.pop("data"), p["filename"]
        digest = hashlib.sha256(data).hexdigest()
        entry = {"filename": name, "sha256": digest, "size": p["size"], "content_type": p["content_type"][:80],
                 "kind": sniff(data, name), "analyzed": False}
        if p["oversize"]:
            entry["note"] = f"plus grand que {cfg['max_file_mb']} Mo : non analysé"
            parts_out.append(entry)
            continue
        key = f"{digest}:{fp}"
        found = cache.get(key) if cache else None
        if found is None:
            found = analyze_content(data, name, name, cfg)
            if cache:
                cache.put(key, found, cfg["cache_ttl_hours"])
        else:
            cached += 1
        entry["analyzed"] = entry["kind"] in cfg["eligible_types"]
        part_score = min(100, sum(f["points"] for f in found))
        entry["score"] = part_score
        scores.append(part_score)
        findings.extend({**f, "part": f["part"].replace(name, name, 1)} for f in found)
        parts_out.append(entry)
    score = fuse(scores)
    verdict = verdict_for(score, cfg) if ex["parts"] else "none"
    if verdict == "clean" and not any(e["analyzed"] for e in parts_out):
        verdict = "none"
    return {"mode": cfg["mode"], "verdict": verdict, "score": score, "symbols": symbols_for(verdict),
            "explanation": explain(findings, verdict), "findings": findings, "parts": parts_out, "urls": ex["urls"], "cached": cached,
            "truncated": ex["truncated"]}


# --------------------------------------------------------------------------- ligne de commande

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-sandboxctl", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze")
    an.add_argument("--mode", choices=["monitor", "enforce"], default=None, help="force le mode (sinon : configuration active)")
    sub.add_parser("show")
    sub.add_parser("check")
    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        cfg = load_config()
        if args.mode:
            cfg = {**cfg, "mode": args.mode}
        json.dump(analyze_message(sys.stdin.buffer.read(), cfg), sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    if args.cmd == "show":
        json.dump(load_config(), sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    try:
        validate_config(json.loads(Path(CONFIG_PATH).read_text(encoding="utf-8")))
    except FileNotFoundError:
        print("Aucune configuration : le sandbox est désactivé (mode off).")
        return 0
    except (OSError, ValueError, SandboxError) as exc:
        print(f"Configuration invalide : {exc}", file=sys.stderr)
        return 1
    print("Configuration valide.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
