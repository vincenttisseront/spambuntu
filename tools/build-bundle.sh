#!/usr/bin/env bash
# Construit dist/spambuntu-X.Y.Z.tar.gz à partir de appliance/ et de VERSION.
# L'archive est reproductible : deux builds du même commit donnent le même fichier.
#   usage : tools/build-bundle.sh [répertoire-de-sortie]
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
OUT="${1:-dist}"

VERSION="$(tr -d '[:space:]' < VERSION)"
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "VERSION invalide : « $VERSION » (attendu X.Y.Z ou X.Y.Z-rc.1)" >&2
    exit 1
fi
MIN_FROM="0.0.0"
if [ -f MIN_FROM_VERSION ]; then
    MIN_FROM="$(tr -d '[:space:]' < MIN_FROM_VERSION)"
fi

# Garde-fou : une clé privée ne doit jamais finir dans une archive publique
if grep -rIl "PRIVATE KEY" appliance >/dev/null 2>&1; then
    echo "Une clé privée a été trouvée dans appliance/ : build annulé" >&2
    exit 1
fi

NAME="spambuntu-$VERSION"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME" "$OUT"

cp -a appliance/. "$STAGE/$NAME/"
find "$STAGE/$NAME" -name '__pycache__' -prune -exec rm -rf {} +
printf '%s\n' "$VERSION" > "$STAGE/$NAME/VERSION"

COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
python3 - "$STAGE/$NAME/manifest.json" "$VERSION" "$MIN_FROM" "$COMMIT" <<'PY'
import json
import sys

path, version, min_from, commit = sys.argv[1:]
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"version": version, "min_from_version": min_from, "commit": commit}, fh, indent=2)
    fh.write("\n")
PY

EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - "$NAME" |
    gzip -n -9 > "$OUT/$NAME.tar.gz"

echo "$OUT/$NAME.tar.gz"
