#!/bin/bash
# Exécuté AVANT l'activation d'une nouvelle version, depuis la version décompressée.
# Tout échec ici annule la mise à jour sans rien avoir modifié.
# Variables : SPAMBUNTU_FROM, SPAMBUNTU_TO, SPAMBUNTU_NEW_DIR, SPAMBUNTU_OLD_DIR
set -euo pipefail

NEW="${SPAMBUNTU_NEW_DIR:?SPAMBUNTU_NEW_DIR manquant}"

echo "Contrôle de la syntaxe des composants"
python3 - "$NEW/webui/app.py" "$NEW/updater/spambuntu_update.py" <<'PY'
import ast
import sys

for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as fh:
        ast.parse(fh.read(), path)
PY
bash -n "$NEW/install.sh"

# Dépendances système déclarées par la nouvelle version (ignorées avec DESTDIR, comme install.sh)
if [ -z "${DESTDIR:-}" ] && [ -f "$NEW/packages.txt" ]; then
    mapfile -t packages < <(grep -vE '^\s*(#|$)' "$NEW/packages.txt")
    missing=()
    for pkg in "${packages[@]}"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Installation des paquets manquants : ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -q
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends "${missing[@]}"
    fi
fi

echo "Contrôles préalables réussis"
