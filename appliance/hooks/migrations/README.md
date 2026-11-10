# Migrations

Scripts `NNNN-description.sh` exécutés une seule fois, dans l'ordre alphabétique, par
`post-update.sh` lors du passage à une version qui les contient (suivi dans
`/var/lib/spambuntu/migrations.done`).

Règle importante : un retour arrière remet l'ancien code **sans défaire les migrations**.
Chaque migration doit donc rester compatible avec la version précédente (ajouter d'abord,
ne supprimer qu'une version plus tard) et être idempotente.
