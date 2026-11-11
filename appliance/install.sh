#!/usr/bin/env bash
# Installe ou rafraîchit Spambuntu à partir du répertoire de release qui contient ce script.
#
#   sudo ./install.sh              installation complète (Ubuntu : paquets, utilisateur, services)
#   sudo ./install.sh --refresh    réinstalle seulement unités, sudoers et wrappers (utilisé par
#                                  les mises à jour, rien n'est créé ni redémarré)
#   --no-start                     n'active pas / ne démarre pas les services (construction d'ISO)
#   DESTDIR=/chemin ./install.sh   installe dans une arborescence sans toucher au système
#                                  (ni paquets, ni utilisateur, ni systemctl) : ISO et tests
#   SPAMBUNTU_PASSWORD_FILE=/root/spambuntu-console-password.txt
#                                  écrit le mot de passe initial de la console dans ce fichier
#                                  (0600) au lieu de l'afficher : installation depuis l'ISO
set -euo pipefail

MODE=fresh
START=1
for arg in "$@"; do
    case "$arg" in
        --refresh) MODE=refresh ;;
        --no-start) START=0 ;;
        -h | --help) sed -n '2,14p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "Option inconnue : $arg" >&2; exit 2 ;;
    esac
done

die() { echo "Erreur : $*" >&2; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "$SRC/VERSION" ] || die "VERSION introuvable : lancez ce script depuis une release (archive spambuntu-X.Y.Z), pas depuis un clone brut du dépôt"
VERSION="$(tr -d '[:space:]' < "$SRC/VERSION")"

D="${DESTDIR:-}"
if [ -z "$D" ] && [ "$(id -u)" -ne 0 ]; then
    die "ce script doit être exécuté en root"
fi

OPT="$D/opt/spambuntu"
ETC="$D/etc/spambuntu"
VAR="$D/var/lib/spambuntu"
LOG="$D/var/log/spambuntu"
SBIN="$D/usr/local/sbin"
UNITS="$D/etc/systemd/system"
SUDOERS="$D/etc/sudoers.d"

own() { [ -n "$D" ] || chown "$@"; }                     # pas de chown dans un DESTDIR
mkd() { install -d -m "$1" "$3"; own "$2" "$3"; }         # mkd MODE USER:GROUP CHEMIN
have_systemd() { [ -z "$D" ] && [ -d /run/systemd/system ]; }

install_packages() {
    [ -z "$D" ] || return 0
    [ -z "${SKIP_PACKAGES:-}" ] || return 0
    export DEBIAN_FRONTEND=noninteractive
    mapfile -t packages < <(grep -vE '^\s*(#|$)' "$SRC/packages.txt")
    if [ -f "$SRC/debconf.preseed" ] && command -v debconf-set-selections >/dev/null 2>&1; then
        debconf-set-selections "$SRC/debconf.preseed"
    fi
    if [ -f "$SRC/debs/Packages" ]; then
        # Dépôt apt embarqué (ISO) : installation possible sans accès à internet.
        # Seule cette source est consultée ; les paquets déjà installés ne sont pas rétrogradés.
        local list
        list="$(mktemp)"
        echo "deb [trusted=yes] file:$SRC/debs ./" > "$list"
        local opts=(-o "Dir::Etc::sourcelist=$list" -o "Dir::Etc::sourceparts=-" -o "APT::Get::List-Cleanup=0" -o "APT::Sandbox::User=root")
        apt-get "${opts[@]}" update -q
        apt-get "${opts[@]}" install -y -q --no-install-recommends "${packages[@]}"
        rm -f "$list"
    else
        apt-get update -q
        apt-get install -y -q --no-install-recommends "${packages[@]}"
    fi
}

create_user() {
    [ -z "$D" ] || return 0
    id spambuntu >/dev/null 2>&1 ||
        useradd --system --home-dir /var/lib/spambuntu --no-create-home --shell /usr/sbin/nologin spambuntu
    # Service d'analyse IA : compte distinct, seul à pouvoir lire le jeton du serveur LLM.
    id spambuntu-ai >/dev/null 2>&1 ||
        useradd --system --home-dir /var/lib/spambuntu/ai --no-create-home --shell /usr/sbin/nologin spambuntu-ai
}

setup_dirs() {
    mkd 0755 root:root "$OPT"
    mkd 0755 root:root "$OPT/releases"
    mkd 0750 root:spambuntu "$ETC"
    mkd 0755 root:root "$VAR"
    mkd 0755 root:root "$VAR/update"
    mkd 0755 spambuntu:spambuntu "$VAR/update/user"   # seul répertoire inscriptible par la console
    mkd 0700 root:root "$VAR/backups"
    mkd 0755 root:root "$VAR/mail"
    mkd 0755 spambuntu:spambuntu "$VAR/mail/user"       # demandes de la console (messagerie)
    mkd 0755 root:root "$LOG"
    mkd 0750 spambuntu-ai:spambuntu-ai "$VAR/ai"
    mkd 0755 spambuntu:spambuntu "$VAR/aiconf"              # demandes de la console (IA)
    mkd 0750 spambuntu-ai:spambuntu-ai "$LOG/ai"             # journal d'audit des envois au LLM
}

install_release() {
    local dest="$OPT/releases/$VERSION"
    if [ "$(realpath "$SRC")" != "$(realpath -m "$dest")" ]; then
        rm -rf "$dest"
        mkdir -p "$dest"
        cp -a "$SRC/." "$dest/"
        rm -rf "$dest/debs"     # dépôt apt de l'ISO : inutile dans la release installée
    fi
    ln -sfn "releases/$VERSION" "$OPT/current"
}

install_wrappers() {
    mkdir -p "$SBIN"
    cat > "$SBIN/spambuntu-update" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/updater/spambuntu_update.py "$@"
EOF
    cat > "$SBIN/spambuntu-passwd" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/bin/spambuntu-passwd "$@"
EOF
    cat > "$SBIN/spambuntu-mail" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/mail/spambuntu_mail.py "$@"
EOF
    cat > "$SBIN/spambuntu-quarantine" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/mail/spambuntu_quarantine.py "$@"
EOF
    cat > "$SBIN/spambuntu-mailstats" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/mail/spambuntu_logs.py "$@"
EOF
    cat > "$SBIN/spambuntu-digest" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/mail/spambuntu_digest.py "$@"
EOF
    cat > "$SBIN/spambuntu-ai" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 -I /opt/spambuntu/current/ai/spambuntu_ai.py "$@"
EOF
    chmod 0755 "$SBIN/spambuntu-update" "$SBIN/spambuntu-passwd" "$SBIN/spambuntu-mail" "$SBIN/spambuntu-quarantine" "$SBIN/spambuntu-mailstats" "$SBIN/spambuntu-ai" "$SBIN/spambuntu-digest"
}

install_units() {
    mkdir -p "$UNITS"
    local f
    for f in "$SRC"/systemd/*; do
        install -m 0644 "$f" "$UNITS/$(basename "$f")"
    done
    if have_systemd; then systemctl daemon-reload; fi
}

install_sudoers() {
    mkdir -p "$SUDOERS"
    local tmp
    tmp="$(mktemp)"
    cp "$SRC/sudoers/spambuntu-webui" "$tmp"
    if [ -z "$D" ] && command -v visudo >/dev/null 2>&1; then
        visudo -cf "$tmp" >/dev/null || { rm -f "$tmp"; die "fichier sudoers invalide"; }
    fi
    install -m 0440 "$tmp" "$SUDOERS/spambuntu-webui"
    rm -f "$tmp"
}

install_pubkey() {
    if [ -f "$SRC/etc/update-pubkey.pem" ]; then
        install -m 0644 "$SRC/etc/update-pubkey.pem" "$ETC/update-pubkey.pem"
    elif [ ! -f "$ETC/update-pubkey.pem" ]; then
        echo "AVERTISSEMENT : aucune clé publique de signature installée, les mises à jour en ligne seront refusées" >&2
    fi
}

install_tls() {
    # Certificat auto-signé pour la console (HTTPS). Jamais écrasé s'il existe déjà.
    local dir="$ETC/tls"
    [ ! -f "$dir/console.crt" ] || return 0
    command -v openssl >/dev/null 2>&1 || die "openssl est requis pour générer le certificat de la console"
    mkd 0750 root:spambuntu "$dir"
    local host
    host="$(tr -d '[:space:]' < /etc/hostname 2>/dev/null || true)"
    host="${host:-spambuntu}"
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
        -subj "/CN=$host" -addext "subjectAltName=DNS:$host,DNS:localhost,IP:127.0.0.1" \
        -keyout "$dir/console.key" -out "$dir/console.crt" 2>/dev/null
    chmod 0640 "$dir/console.key"
    chmod 0644 "$dir/console.crt"
    own root:spambuntu "$dir/console.key"
}

install_motd() {
    mkdir -p "$D/etc/update-motd.d"
    install -m 0755 "$SRC/motd/90-spambuntu" "$D/etc/update-motd.d/90-spambuntu"
}

install_config() {
    if [ ! -f "$ETC/update.conf" ]; then
        install -m 0640 "$SRC/etc/update.conf.example" "$ETC/update.conf"
        own root:spambuntu "$ETC/update.conf"
    fi
    if [ ! -f "$ETC/webui.env" ]; then
        install -m 0644 "$SRC/etc/webui.env.example" "$ETC/webui.env"
    fi
    if [ ! -f "$ETC/webui.json" ]; then
        local args=(--random --secure-cookies)
        if [ -n "${SPAMBUNTU_PASSWORD_FILE:-}" ]; then
            args+=(--password-file "$D$SPAMBUNTU_PASSWORD_FILE")
        fi
        SPAMBUNTU_WEBUI_CONF="$ETC/webui.json" python3 "$SRC/bin/spambuntu-passwd" "${args[@]}"
    fi
}

install_mail() {
    # Configuration initiale de la passerelle : aucun domaine, donc rien n'est relayé tant que
    # l'administrateur n'en a pas déclaré (jamais de relais ouvert). Sans accès à systemd (ISO, DESTDIR).
    [ -z "$D" ] || return 0
    [ -x "$SBIN/spambuntu-mail" ] || return 0
    "$SBIN/spambuntu-mail" init --no-reload
}

install_identity() {
    # Règles Rspamd de protection d'identité et moteur de règles de filtrage (fichiers gérés par Spambuntu ;
    # la configuration est rendue par spambuntu-mail). Le moteur de règles passe en dernier : il lit les résultats des autres.
    [ -z "$D" ] || return 0
    install -d -m 0755 /etc/rspamd/spambuntu
    for lua in identity_lib spambuntu_identity rules_lib spambuntu_rules; do
        install -m 0644 "$SRC/mail/rspamd/$lua.lua" "/etc/rspamd/spambuntu/$lua.lua"
    done
    printf '%s\n' '-- Géré par Spambuntu : ne pas modifier' \
        'dofile("/etc/rspamd/spambuntu/spambuntu_identity.lua")' \
        'dofile("/etc/rspamd/spambuntu/spambuntu_rules.lua")' > /etc/rspamd/rspamd.local.lua
    chmod 0644 /etc/rspamd/rspamd.local.lua
}

install_ai() {
    # Règle Rspamd (fichier géré par Spambuntu) et configuration par défaut : IA désactivée.
    [ -z "$D" ] || return 0
    install -D -m 0644 "$SRC/ai/rspamd/spambuntu_ai.lua" /etc/rspamd/local.d/rspamd.lua
    install -d -m 0755 -o root -g root /etc/spambuntu-ai
    [ -s /etc/spambuntu-ai/ai.json ] || echo '{"mode": "off"}' > /etc/spambuntu-ai/ai.json
    chmod 0644 /etc/spambuntu-ai/ai.json
}

enable_services() {
    have_systemd || [ -z "$D" ] || return 0
    systemctl enable spambuntu-webui.service spambuntu-update-check.timer spambuntu-digest.timer || true
    systemctl enable redis-server.service rspamd.service postfix.service spambuntu-ai.service || true
    if [ "$START" -eq 1 ] && have_systemd; then
        systemctl restart spambuntu-webui.service
        systemctl start spambuntu-update-check.timer spambuntu-digest.timer
        systemctl restart spambuntu-ai.service redis-server.service rspamd.service postfix.service || true
    fi
}

if [ "$MODE" = refresh ]; then
    setup_dirs
    install_wrappers
    install_units
    install_sudoers
    install_pubkey
    install_motd
    echo "Rafraîchissement de la version $VERSION terminé"
else
    install_packages
    create_user
    setup_dirs
    install_release
    install_wrappers
    install_units
    install_sudoers
    install_tls
    install_config
    install_pubkey
    install_motd
    install_identity
    install_mail
    install_ai
    enable_services
    echo "Spambuntu $VERSION installé. Console : https://<adresse-ip>:8443 (certificat auto-signé)"
fi
