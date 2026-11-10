#!/usr/bin/env bash
# Génère la paire de clés Ed25519 qui signe les releases.
#   clé privée  : ~/.spambuntu-signing/update-signing-key.pem  (hors dépôt, secrète)
#   clé publique: appliance/etc/update-pubkey.pem              (à committer, embarquée dans l'appliance)
# À exécuter une seule fois, depuis votre poste.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
KEY_DIR="${SPAMBUNTU_KEY_DIR:-$HOME/.spambuntu-signing}"
KEY="$KEY_DIR/update-signing-key.pem"
PUB="appliance/etc/update-pubkey.pem"

if [ -e "$KEY" ]; then
    echo "Une clé existe déjà : $KEY (elle n'est pas écrasée)." >&2
    exit 1
fi

umask 077
mkdir -p "$KEY_DIR"
openssl genpkey -algorithm ED25519 -out "$KEY"
umask 022
openssl pkey -in "$KEY" -pubout -out "$PUB"

cat <<EOF
Clés générées.

  Clé privée  : $KEY
  Clé publique: $PUB

Étapes suivantes :
  1. Enregistrer la clé privée comme secret du dépôt GitHub (nom exact : UPDATE_SIGNING_KEY) :
       gh secret set UPDATE_SIGNING_KEY < "$KEY"
     ou Settings > Secrets and variables > Actions > New repository secret.
  2. Committer la clé publique :
       git add $PUB && git commit -m "Ajoute la clé publique de signature"
  3. SAUVEGARDER la clé privée (gestionnaire de mots de passe, coffre). Si elle est perdue,
     les appliances déjà installées ne pourront plus être mises à jour en ligne : il faudra
     les réinstaller depuis une ISO contenant une nouvelle clé publique.
EOF
