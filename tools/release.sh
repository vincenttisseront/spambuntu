#!/usr/bin/env bash
# Prépare une release : met à jour VERSION, committe et crée le tag. La publication elle-même
# (archive signée + release GitHub) est faite par le workflow « Release » quand le tag est poussé.
#   usage : tools/release.sh 0.2.0        (ou 0.2.0-rc.1 pour une préversion)
set -euo pipefail

die() { echo "Erreur : $*" >&2; exit 1; }

cd "$(dirname "${BASH_SOURCE[0]}")/.."
NEW="${1:-}"
[ -n "$NEW" ] || die "usage : tools/release.sh X.Y.Z"
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "version invalide : $NEW"
[ -z "$(git status --porcelain)" ] || die "des modifications ne sont pas committées"
git rev-parse "v$NEW" >/dev/null 2>&1 && die "le tag v$NEW existe déjà"
grep -qF "## [$NEW]" CHANGELOG.md || die "ajoutez d'abord une section « ## [$NEW] » dans CHANGELOG.md (elle est affichée dans la console web)"
[ -f appliance/etc/update-pubkey.pem ] || die "clé publique absente : lancez tools/gen-signing-key.sh"

CURRENT="$(tr -d '[:space:]' < VERSION)"
python3 -B - "$CURRENT" "$NEW" <<'PY' || die "la version $NEW doit être supérieure à $CURRENT"
import sys

sys.path.insert(0, "appliance/updater")
from spambuntu_update import version_key

sys.exit(0 if version_key(sys.argv[2]) > version_key(sys.argv[1]) else 1)
PY

printf '%s\n' "$NEW" > VERSION
git add VERSION
git commit -q -m "release: v$NEW"
git tag -a "v$NEW" -m "Spambuntu $NEW"

echo "Release v$NEW préparée. Pour la publier :"
echo "  git push origin main --follow-tags"
