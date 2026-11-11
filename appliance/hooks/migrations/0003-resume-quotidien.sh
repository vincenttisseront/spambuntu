#!/bin/bash
# 0.3.0 : résumé quotidien de quarantaine (désactivé tant que l'administrateur ne l'a pas activé). Idempotent.
set -euo pipefail

[ -z "${DESTDIR:-}" ] || exit 0
install -d -m 0755 -o spambuntu -g spambuntu /var/lib/spambuntu/mail/user
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now spambuntu-digest.timer
fi
