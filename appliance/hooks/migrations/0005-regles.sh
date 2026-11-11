#!/bin/bash
# 0.3.0 : moteur de règles de filtrage (page « Règles »). Installe les fichiers Lua, déclare le moteur dans Rspamd
# (après la protection d'identité) et rend la configuration des règles à partir de la configuration existante. Idempotent.
# Les règles par défaut reproduisent les seuils de « Messagerie » ; l'ancien réglage « action DMARC » devient la règle inbound_dmarc.
set -euo pipefail

[ -z "${DESTDIR:-}" ] || exit 0
install -d -m 0755 /etc/rspamd/spambuntu
for lua in identity_lib spambuntu_identity rules_lib spambuntu_rules; do
    install -m 0644 "/opt/spambuntu/current/mail/rspamd/$lua.lua" "/etc/rspamd/spambuntu/$lua.lua"
done
printf '%s\n' '-- Géré par Spambuntu : ne pas modifier' \
    'dofile("/etc/rspamd/spambuntu/spambuntu_identity.lua")' \
    'dofile("/etc/rspamd/spambuntu/spambuntu_rules.lua")' > /etc/rspamd/rspamd.local.lua
chmod 0644 /etc/rspamd/rspamd.local.lua
# Un ancien réglage dmarc_action de mail.json reste accepté : il fixe la règle inbound_dmarc tant que les règles n'ont pas été modifiées.
/usr/local/sbin/spambuntu-mail apply
