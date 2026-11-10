#!/usr/bin/env bash
# Installe ou rafraîchit Spambuntu à partir du répertoire de release qui contient ce script.
#
#   sudo ./install.sh              installation complète (Ubuntu : paquets, utilisateur, services)
#   sudo ./install.sh --refresh    réinstalle seulement unités, sudoers et wrappers (utilisé par
#                                  les mises à jour, rien n'est créé ni redémarré)
#   --no-start                     n'active pas / ne démarre pas les services (construction d'ISO)
#   DESTDIR=/chemin ./install.sh   installe dans une arborescence sans toucher au système
#                                  (ni paquets, ni utilisateur, ni systemctl) : ISO et tests
set -euo pipefail

MODE=fresh
START=1
for arg in "$@"; do
    case "$arg" in
        --refresh) MODE=refresh ;;
        --no-start) START=0 ;;
        -h | --help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
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
    apt-get update -q
    mapfile -t packages < <(grep -vE '^\s*(#|$)' "$SRC/packages.txt")
    apt-get install -y -q --no-install-recommends "${packages[@]}"
}

create_user() {
    [ -z "$D" ] || return 0
    id spambuntu >/dev/null 2>&1 ||
        useradd --system --home-dir /var/lib/spambuntu --no-create-home --shell /usr/sbin/nologin spambuntu
}

setup_dirs() {
    mkd 0755 root:root "$OPT"
    mkd 0755 root:root "$OPT/releases"
    mkd 0750 root:spambuntu "$ETC"
    mkd 0755 root:root "$VAR"
    mkd 0755 root:root "$VAR/update"
    mkd 0755 spambuntu:spambuntu "$VAR/update/user"   # seul répertoire inscriptible par la console
    mkd 0700 root:root "$VAR/backups"
    mkd 0755 root:root "$LOG"
}

install_release() {
    local dest="$OPT/releases/$VERSION"
    if [ "$(realpath "$SRC")" != "$(realpath -m "$dest")" ]; then
        rm -rf "$dest"
        mkdir -p "$dest"
        cp -a "$SRC/." "$dest/"
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
    chmod 0755 "$SBIN/spambuntu-update" "$SBIN/spambuntu-passwd"
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

install_config() {
    if [ ! -f "$ETC/update.conf" ]; then
        install -m 0640 "$SRC/etc/update.conf.example" "$ETC/update.conf"
        own root:spambuntu "$ETC/update.conf"
    fi
    if [ ! -f "$ETC/webui.env" ]; then
        install -m 0644 "$SRC/etc/webui.env.example" "$ETC/webui.env"
    fi
    if [ ! -f "$ETC/webui.json" ]; then
        SPAMBUNTU_WEBUI_CONF="$ETC/webui.json" python3 "$SRC/bin/spambuntu-passwd" --random
    fi
}

enable_services() {
    have_systemd || [ -z "$D" ] || return 0
    systemctl enable spambuntu-webui.service spambuntu-update-check.timer || true
    if [ "$START" -eq 1 ] && have_systemd; then
        systemctl restart spambuntu-webui.service
        systemctl start spambuntu-update-check.timer
    fi
}

if [ "$MODE" = refresh ]; then
    setup_dirs
    install_wrappers
    install_units
    install_sudoers
    install_pubkey
    echo "Rafraîchissement de la version $VERSION terminé"
else
    install_packages
    create_user
    setup_dirs
    install_release
    install_wrappers
    install_units
    install_sudoers
    install_config
    install_pubkey
    enable_services
    echo "Spambuntu $VERSION installé. Console : voir SPAMBUNTU_BIND dans /etc/spambuntu/webui.env (défaut http://127.0.0.1:8080)"
fi
