#!/bin/bash
# Exécuté APRÈS la bascule du lien « current », avant le redémarrage des services.
# Un échec déclenche le retour arrière automatique.
# Aussi exécuté depuis l'ancienne version lors d'un retour arrière (SPAMBUNTU_ROLLBACK=1) :
# on ne rejoue alors que le rafraîchissement des unités, jamais les migrations.
set -euo pipefail

NEW="${SPAMBUNTU_NEW_DIR:?SPAMBUNTU_NEW_DIR manquant}"

# Unités systemd, sudoers, wrappers et clé publique de cette version
bash "$NEW/install.sh" --refresh

if [ -z "${SPAMBUNTU_ROLLBACK:-}" ]; then
    done_file="${DESTDIR:-}/var/lib/spambuntu/migrations.done"
    mkdir -p "$(dirname "$done_file")"
    touch "$done_file"
    shopt -s nullglob
    for migration in "$NEW"/hooks/migrations/*.sh; do   # ordre alphabétique : 0001-xxx.sh, 0002-xxx.sh…
        name="$(basename "$migration")"
        if grep -qxF "$name" "$done_file"; then
            continue
        fi
        echo "Migration $name"
        bash "$migration"
        echo "$name" >> "$done_file"
    done
fi
