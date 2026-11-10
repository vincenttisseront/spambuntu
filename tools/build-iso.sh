#!/usr/bin/env bash
# Construit l'ISO d'installation de Spambuntu à partir de l'ISO officielle Ubuntu Server 24.04.
#
#   tools/build-iso.sh [--base ISO] [--output FICHIER.iso] [--work RÉPERTOIRE]
#                      [--pubkey FICHIER.pem] [--online-install] [--ci-test]
#
# L'ISO produite est l'ISO Ubuntu inchangée, plus :
#   /spambuntu/                 la release Spambuntu (bundle + dépôt apt embarqué des paquets manquants)
#   /spambuntu-autoinstall/     la configuration d'installation (autoinstall, voir iso/user-data)
#   et une entrée de menu GRUB « Installer Spambuntu » par défaut.
# Au démarrage, l'installateur Ubuntu demande confirmation avant d'effacer le disque et crée le compte
# administrateur ; Spambuntu est ensuite installé (sans accès à internet si l'ISO embarque ses paquets).
#
# Prérequis (Ubuntu 24.04) : xorriso, gnupg, curl, python3, dpkg-dev, apt (accès aux dépôts Ubuntu).
#
# La clé publique de signature (appliance/etc/update-pubkey.pem) est OBLIGATOIRE : sans elle,
# une appliance installée refuserait toute mise à jour. --pubkey permet d'utiliser une autre clé
# (tests uniquement : le nom de l'ISO porte alors le suffixe « -TEST »).
#   --online-install  n'embarque pas les paquets : l'installation exige alors un accès aux dépôts Ubuntu
#   --ci-test         ajoute « autoinstall » au noyau et un compte jetable : installation SANS question,
#                     pour les tests automatisés. NE JAMAIS DISTRIBUER (suffixe « -CITEST »).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

UBUNTU_ISO_VERSION="${UBUNTU_ISO_VERSION:-24.04.5}"
UBUNTU_ISO_BASE_URL="${UBUNTU_ISO_BASE_URL:-https://releases.ubuntu.com/${UBUNTU_ISO_VERSION%.*}}"
CACHE="${ISO_CACHE:-$ROOT/.iso-cache}"
BASE=""
OUTPUT=""
WORK=""
PUBKEY="$ROOT/appliance/etc/update-pubkey.pem"
CUSTOM_PUBKEY=0
EMBED_DEBS=1
CI_TEST=0

die() { echo "Erreur : $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --base) BASE="${2:?}"; shift 2 ;;
        --output) OUTPUT="${2:?}"; shift 2 ;;
        --work) WORK="${2:?}"; shift 2 ;;
        --pubkey) PUBKEY="${2:?}"; CUSTOM_PUBKEY=1; shift 2 ;;
        --online-install) EMBED_DEBS=0; shift ;;
        --ci-test) CI_TEST=1; shift ;;
        -h | --help) sed -n '2,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "option inconnue : $1" ;;
    esac
done

[ -f "$PUBKEY" ] || die "clé publique de signature introuvable ($PUBKEY). Générez-la avec tools/gen-signing-key.sh puis commitez appliance/etc/update-pubkey.pem"
grep -q 'BEGIN PUBLIC KEY' "$PUBKEY" || die "$PUBKEY n'est pas une clé publique PEM"
if grep -q 'PRIVATE KEY' "$PUBKEY"; then die "$PUBKEY contient une clé PRIVÉE : abandon"; fi

for tool in xorriso gpg curl python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "outil manquant : $tool"
done
[ "$EMBED_DEBS" -eq 0 ] || command -v dpkg-scanpackages >/dev/null 2>&1 || die "outil manquant : dpkg-scanpackages (paquet dpkg-dev)"

VERSION="$(tr -d '[:space:]' < VERSION)"
SUFFIX=""
[ "$CUSTOM_PUBKEY" -eq 0 ] || SUFFIX="-TEST"
[ "$CI_TEST" -eq 0 ] || SUFFIX="-CITEST"
OUTPUT="${OUTPUT:-$ROOT/dist/spambuntu-${VERSION}${SUFFIX}-amd64.iso}"
mkdir -p "$(dirname "$OUTPUT")" "$CACHE"

# --- 1. ISO Ubuntu de base, vérifiée (signature GPG de la liste des sommes, puis SHA-256) ---------
ISO_NAME="ubuntu-${UBUNTU_ISO_VERSION}-live-server-amd64.iso"
if [ -z "$BASE" ]; then
    BASE="$CACHE/$ISO_NAME"
    for f in SHA256SUMS SHA256SUMS.gpg; do
        [ -f "$CACHE/$f" ] || curl -fsSL -o "$CACHE/$f" "$UBUNTU_ISO_BASE_URL/$f"
    done
    [ -f "$BASE" ] || { echo "Téléchargement de $ISO_NAME ..."; curl -fL -o "$BASE.part" "$UBUNTU_ISO_BASE_URL/$ISO_NAME"; mv "$BASE.part" "$BASE"; }
fi
[ -f "$BASE" ] || die "ISO de base introuvable : $BASE"

KEYRING="${UBUNTU_KEYRING:-/usr/share/keyrings/ubuntu-archive-keyring.gpg}"
[ -f "$CACHE/SHA256SUMS" ] && [ -f "$CACHE/SHA256SUMS.gpg" ] || die "SHA256SUMS(.gpg) absents de $CACHE"
# La clé de signature des images Ubuntu (« Ubuntu CD Image Automatic Signing Key (2012) ») est dans le trousseau Ubuntu.
status="$(gpg --no-default-keyring --keyring "$KEYRING" --status-fd 1 --verify "$CACHE/SHA256SUMS.gpg" "$CACHE/SHA256SUMS" 2>/dev/null || true)"
echo "$status" | grep -q '^\[GNUPG:\] VALIDSIG ' || die "signature de SHA256SUMS invalide ou clé Ubuntu absente ($KEYRING)"
expected="$(awk -v n="*$(basename "$BASE")" '$2 == n {print $1}' "$CACHE/SHA256SUMS")"
[ -n "$expected" ] || die "$(basename "$BASE") absent de SHA256SUMS (mauvais UBUNTU_ISO_VERSION ?)"
actual="$(sha256sum "$BASE" | awk '{print $1}')"
[ "$expected" = "$actual" ] || die "somme SHA-256 de l'ISO de base incorrecte"
echo "ISO de base vérifiée : $(basename "$BASE")"

# --- 2. Espace de travail ----------------------------------------------------------------------------
if [ -z "$WORK" ]; then
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
else
    [ ! -e "$WORK" ] || [ -z "$(ls -A "$WORK" 2>/dev/null)" ] || die "$WORK n'est pas vide"
    mkdir -p "$WORK"
fi
PAYLOAD="$WORK/payload"
SEED="$WORK/seed"
mkdir -p "$PAYLOAD" "$SEED" "$WORK/extract"

# --- 3. Release Spambuntu (même archive que celle de la release GitHub) ---------------------------------
"$ROOT/tools/build-bundle.sh" "$WORK/bundle" >/dev/null
tar -xzf "$WORK/bundle/spambuntu-$VERSION.tar.gz" -C "$WORK/extract"
cp -a "$WORK/extract/spambuntu-$VERSION/." "$PAYLOAD/"
if [ "$CUSTOM_PUBKEY" -eq 1 ]; then
    install -m 0644 "$PUBKEY" "$PAYLOAD/etc/update-pubkey.pem"
fi
cmp -s "$PUBKEY" "$PAYLOAD/etc/update-pubkey.pem" || die "clé publique de la release différente de celle de l'ISO"

# --- 4. Paquets Ubuntu manquants (dépôt apt embarqué) ---------------------------------------------------
if [ "$EMBED_DEBS" -eq 1 ]; then
    xorriso -osirrox on -indev "$BASE" \
        -extract /casper/ubuntu-server-minimal.manifest "$WORK/minimal.manifest" \
        -extract /casper/ubuntu-server-minimal.ubuntu-server.manifest "$WORK/server.manifest" >/dev/null 2>&1 \
        || die "manifestes introuvables dans l'ISO de base"
    python3 -B "$ROOT/tools/iso_debs.py" "$WORK/minimal.manifest" "$WORK/server.manifest" \
        --packages "$ROOT/appliance/packages.txt" --out "$PAYLOAD/debs"
fi

# --- 5. Configuration d'installation et GRUB ----------------------------------------------------------
cp "$ROOT/iso/meta-data" "$SEED/meta-data"
cp "$ROOT/iso/user-data" "$SEED/user-data"
KERNEL_ARGS='ds=nocloud\;s=/cdrom/spambuntu-autoinstall/'
if [ "$CI_TEST" -eq 1 ]; then
    KERNEL_ARGS="autoinstall console=ttyS0,115200n8 $KERNEL_ARGS"
    python3 -B "$ROOT/tools/iso_citest.py" "$SEED/user-data"
fi

xorriso -osirrox on -indev "$BASE" -extract /boot/grub/grub.cfg "$WORK/grub.orig" >/dev/null 2>&1 || die "grub.cfg introuvable dans l'ISO"
chmod u+w "$WORK/grub.orig"
{
    echo "set timeout=${GRUB_TIMEOUT:-10}"
    echo 'set default=0'
    echo 'loadfont unicode'
    echo 'set menu_color_normal=white/black'
    echo 'set menu_color_highlight=black/light-gray'
    echo
    echo "menuentry \"Installer Spambuntu $VERSION\" {"
    echo '    set gfxpayload=keep'
    echo "    linux /casper/vmlinuz $KERNEL_ARGS ---"
    echo '    initrd /casper/initrd'
    echo '}'
    echo
    # Le reste du menu d'origine (noyau HWE, firmware, mémoire ...) est conservé tel quel.
    sed -e '/^set timeout=/d' -e '/^loadfont unicode/d' -e '/^set menu_color_/d' "$WORK/grub.orig"
} > "$WORK/grub.cfg"
grep -q 'ds=nocloud' "$WORK/grub.cfg" || die "grub.cfg généré invalide"

# --- 6. md5sum.txt (utilisé par « vérifier le disque ») ----------------------------------------------
xorriso -osirrox on -indev "$BASE" -extract /md5sum.txt "$WORK/md5sum.orig" >/dev/null 2>&1 || true
if [ -f "$WORK/md5sum.orig" ]; then
    chmod u+w "$WORK/md5sum.orig"
    {
        grep -v -F -e ' ./boot/grub/grub.cfg' "$WORK/md5sum.orig"
        (cd "$WORK" && md5sum ./grub.cfg | sed 's| \./grub.cfg| ./boot/grub/grub.cfg|')
        (cd "$PAYLOAD" && find . -type f -print0 | sort -z | xargs -0 md5sum | sed 's| \./| ./spambuntu/|')
        (cd "$SEED" && find . -type f -print0 | sort -z | xargs -0 md5sum | sed 's| \./| ./spambuntu-autoinstall/|')
    } > "$WORK/md5sum.txt"
fi

# --- 7. Reconstruction de l'ISO (secteurs de démarrage BIOS + UEFI d'origine rejoués) ---------------
rm -f "$OUTPUT"
VOLID="SPAMBUNTU_${VERSION//[^0-9A-Za-z]/_}"
args=(-indev "$BASE" -outdev "$OUTPUT" -volid "${VOLID:0:32}" -boot_image any replay
      -map "$WORK/grub.cfg" /boot/grub/grub.cfg
      -map "$PAYLOAD" /spambuntu
      -map "$SEED" /spambuntu-autoinstall)
[ ! -f "$WORK/md5sum.txt" ] || args+=(-map "$WORK/md5sum.txt" /md5sum.txt)
xorriso "${args[@]}" -commit >"$WORK/xorriso.log" 2>&1 || { tail -20 "$WORK/xorriso.log" >&2; die "échec de xorriso"; }

( cd "$(dirname "$OUTPUT")" && sha256sum "$(basename "$OUTPUT")" > "$(basename "$OUTPUT").sha256" )
echo "ISO générée : $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
cat "$OUTPUT.sha256"
