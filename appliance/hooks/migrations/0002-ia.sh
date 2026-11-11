#!/bin/bash
# 0.3.0 : analyse IA des messages ambigus (service local + règle Rspamd). IA désactivée par défaut. Idempotent.
set -euo pipefail

[ -z "${DESTDIR:-}" ] || exit 0
id spambuntu-ai >/dev/null 2>&1 ||
    useradd --system --home-dir /var/lib/spambuntu/ai --no-create-home --shell /usr/sbin/nologin spambuntu-ai
install -d -m 0750 -o spambuntu-ai -g spambuntu-ai /var/lib/spambuntu/ai /var/log/spambuntu/ai
install -D -m 0644 /opt/spambuntu/current/ai/rspamd/spambuntu_ai.lua /etc/rspamd/local.d/rspamd.lua
[ -s /etc/spambuntu/ai.json ] || { echo '{"mode": "off"}' > /etc/spambuntu/ai.json; chown root:spambuntu-ai /etc/spambuntu/ai.json; chmod 0640 /etc/spambuntu/ai.json; }
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
    systemctl enable --now spambuntu-ai.service
    systemctl reload-or-restart rspamd.service
fi
