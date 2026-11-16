#!/bin/bash
# 0.4.0 : sandbox des pièces jointes (premier niveau). Crée le compte et les répertoires du service, installe le module Rspamd
# et le déclare avant le moteur de règles, installe la configuration par défaut (désactivé). Idempotent.
set -euo pipefail

[ -z "${DESTDIR:-}" ] || exit 0
id spambuntu-sandboxd >/dev/null 2>&1 ||
    useradd --system --home-dir /var/lib/spambuntu/sandbox --no-create-home --shell /usr/sbin/nologin spambuntu-sandboxd
install -d -m 0750 -o spambuntu-sandboxd -g spambuntu-sandboxd /var/lib/spambuntu/sandbox /var/log/spambuntu/sandbox
install -d -m 0755 /etc/rspamd/spambuntu /etc/spambuntu-sandbox
install -m 0644 /opt/spambuntu/current/sandbox/rspamd/spambuntu_sandbox.lua /etc/rspamd/spambuntu/spambuntu_sandbox.lua
printf '%s\n' '-- Géré par Spambuntu : ne pas modifier' \
    'dofile("/etc/rspamd/spambuntu/spambuntu_identity.lua")' \
    'dofile("/etc/rspamd/spambuntu/spambuntu_sandbox.lua")' \
    'dofile("/etc/rspamd/spambuntu/spambuntu_rules.lua")' > /etc/rspamd/rspamd.local.lua
chmod 0644 /etc/rspamd/rspamd.local.lua
[ -s /etc/spambuntu-sandbox/sandbox.json ] || echo '{"mode": "off"}' > /etc/spambuntu-sandbox/sandbox.json
chmod 0644 /etc/spambuntu-sandbox/sandbox.json
cat > /usr/local/sbin/spambuntu-sandboxctl <<'WRAP'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/sandbox/spambuntu_sandbox.py "$@"
WRAP
chmod 0755 /usr/local/sbin/spambuntu-sandboxctl
install -m 0644 /opt/spambuntu/current/systemd/spambuntu-sandboxd.service /etc/systemd/system/spambuntu-sandboxd.service
systemctl daemon-reload || true
systemctl enable --now spambuntu-sandboxd.service || true
systemctl reload rspamd.service || systemctl restart rspamd.service || true
