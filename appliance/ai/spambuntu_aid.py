#!/usr/bin/env python3
"""Service local d'analyse IA : reçoit un message de Rspamd (127.0.0.1 uniquement) et répond en JSON.

Fonctionne sous un utilisateur dédié sans privilège ; la configuration et le jeton sont relus à chaque
requête (un changement est donc pris en compte sans redémarrage). Toute panne se traduit par une réponse
« non utilisé » : le courrier n'est jamais bloqué ni retardé par l'IA au-delà du délai configuré.
"""
from __future__ import annotations

import http.server
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # exécuté avec python3 -I
import spambuntu_ai as ai  # noqa: E402

BIND = ("127.0.0.1", 11340)
MAX_BODY = 4 * 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "spambuntu-aid"

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
        try:
            score = float(self.headers.get("X-Score", ""))
        except ValueError:
            score = None
        symbols = [s for s in (self.headers.get("X-Symbols", "")).split(",") if re.fullmatch(r"[A-Z0-9_]{2,60}", s)]
        try:
            result = ai.analyze(raw, ai.load_config(), score, symbols, ai.read_token())
        except ai.AIError as exc:
            result = {"used": False, "points": 0.0, "symbols": [], "reason": str(exc)}
        self._reply(200, {"ok": True, "used": result["used"], "points": result["points"], "symbols": result["symbols"],
                          "explanation": result.get("explanation", ""), "reason": result.get("reason", "")})


def serve(bind=BIND) -> None:
    http.server.ThreadingHTTPServer.daemon_threads = True
    http.server.ThreadingHTTPServer(bind, Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(serve() or 0)
