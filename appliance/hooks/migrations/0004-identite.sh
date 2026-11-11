#!/bin/bash
# 0.3.0 : protection d'identité (dirigeants, domaines imitateurs, homoglyphes) et action DMARC. Idempotent.
# Attention : l'action par défaut pour un échec DMARC « reject » devient le rejet immédiat (réglable dans « Messagerie »).
set -euo pipefail

[ -z "${DESTDIR:-}" ] || exit 0
install -d -m 0755 /etc/rspamd/spambuntu
install -m 0644 /opt/spambuntu/current/mail/rspamd/identity_lib.lua /etc/rspamd/spambuntu/identity_lib.lua
install -m 0644 /opt/spambuntu/current/mail/rspamd/spambuntu_identity.lua /etc/rspamd/spambuntu/spambuntu_identity.lua
printf '%s\n' '-- Géré par Spambuntu : ne pas modifier' 'dofile("/etc/rspamd/spambuntu/spambuntu_identity.lua")' > /etc/rspamd/rspamd.local.lua
chmod 0644 /etc/rspamd/rspamd.local.lua
# Rend les nouveaux fichiers à partir de la configuration existante, puis recharge Rspamd et Postfix.
/usr/local/sbin/spambuntu-mail apply
