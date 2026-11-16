#!/usr/bin/env python3
"""Service local du sandbox : reçoit le message de Rspamd (127.0.0.1 uniquement) et répond avec le verdict en JSON.

Configuration relue à chaque requête. Toute panne se traduit par un verdict « error » : le courrier n'est jamais bloqué.
Un journal d'audit (une ligne JSON par message analysé, sans contenu) est écrit dans /var/log/spambuntu/sandbox/.
"""
from __future__ import annotations

import http.server
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # exécuté avec python3 -I
import spambuntu_sandbox as sb  # noqa: E402

BIND = ("127.0.0.1", 11341)
MAX_BODY = 60 * 1024 * 1024
LOG_PATH = "/var/log/spambuntu/sandbox/audit.jsonl"


def audit(entry: dict, path: str = LOG_PATH) -> None:
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass


def handle(raw: bytes, queue_id: str = "", cache: sb.VerdictCache | None = None, cfg: dict | None = None, log: str = LOG_PATH) -> dict:
    """Verdict public (sans contenu des pièces) ; ne lève jamais."""
    cfg = cfg or sb.load_config()
    started = time.time()
    try:
        r = sb.analyze_message(raw, cfg, cache or sb.VerdictCache())
    except Exception as exc:                        # noqa: BLE001 - jamais de blocage du courrier
        return {"ok": True, "mode": cfg["mode"], "verdict": "error", "symbols": [sb.SYMBOLS["error"]] if cfg["mode"] != "off" else [],
                "score": 0, "explanation": f"erreur d'analyse ({type(exc).__name__})", "reason": "error"}
    if r["mode"] != "off" and r["verdict"] != "none":
        audit({"t": int(started), "queue_id": queue_id[:40], "mode": r["mode"], "verdict": r["verdict"], "score": r["score"],
               "parts": [{"filename": p["filename"], "sha256": p["sha256"], "kind": p["kind"], "score": p.get("score", 0)} for p in r["parts"]],
               "findings": [{"code": f["code"], "points": f["points"]} for f in r["findings"]],
               "cached": r["cached"], "ms": int((time.time() - started) * 1000)}, log)
    return {"ok": True, "mode": r["mode"], "verdict": r["verdict"], "symbols": r["symbols"], "score": r["score"],
            "explanation": r["explanation"], "urls": r["urls"][:20]}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "spambuntu-sandboxd"

    def log_message(self, *args):
        pass

    def _reply(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._reply(200, {"status": "ok"}) if self.path == "/ping" else self._reply(404, {"ok": False})

    def do_POST(self):
        if self.path != "/analyze":
            return self._reply(404, {"ok": False})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._reply(400, {"ok": False, "error": "longueur manquante"})
        if not 0 < length <= MAX_BODY:
            return self._reply(413, {"ok": False, "error": "message trop gros"})
        raw = self.rfile.read(length)
        queue_id = "".join(c for c in self.headers.get("X-Queue-Id", "") if c.isalnum() or c in "-_")
        self._reply(200, handle(raw, queue_id))


def serve(bind=BIND) -> None:
    http.server.ThreadingHTTPServer.daemon_threads = True
    http.server.ThreadingHTTPServer(bind, Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(serve() or 0)
