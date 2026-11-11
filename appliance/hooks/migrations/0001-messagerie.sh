#!/bin/bash
# 0.2.0 : arrivée de la passerelle de messagerie (Postfix + Rspamd). Crée la configuration par défaut
# (aucun domaine : rien n'est relayé) et active les services. Idempotent.
set -euo pipefail

[ -z "${DESTDIR:-}" ] || exit 0
/usr/local/sbin/spambuntu-mail init --no-reload
if [ -d /run/systemd/system ]; then
    systemctl enable redis-server.service rspamd.service postfix.service
    systemctl restart redis-server.service rspamd.service postfix.service
fi
