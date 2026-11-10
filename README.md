# Spambuntu

Appliance Ubuntu avec console web d'administration. Ce dépôt contient le code de l'appliance et
le mécanisme de **mise à jour en ligne** : la console détecte les nouvelles versions publiées sur
GitHub et les installe sans repasser par l'ISO.

## Comment ça marche

```
 poste de dev                    GitHub                          appliance
 ────────────                    ──────                          ─────────
 tools/release.sh 0.2.0   ─►  tag v0.2.0 poussé
                               │ workflow « Release »
                               │  · tests
                               │  · archive spambuntu-0.2.0.tar.gz
                               │  · signature Ed25519 (secret UPDATE_SIGNING_KEY)
                               └► release GitHub (archive + .sig + notes du CHANGELOG)
                                                                  │
                         console web ► « Mises à jour » ◄─────────┘ détecte (quotidien ou à la demande)
                               │ clic sur « Installer »
                               ▼
              unité systemd (root) : télécharge → vérifie la signature → sauvegarde /etc/spambuntu
              → pre-update.sh → bascule atomique du lien « current » → post-update.sh (unités, migrations)
              → redémarre → contrôle de santé ──► échec ? retour automatique à la version précédente
```

Disposition sur l'appliance :

| Chemin | Rôle |
| --- | --- |
| `/opt/spambuntu/releases/<version>/` | une copie du code par version (3 conservées) |
| `/opt/spambuntu/current` → | version active (lien changé de façon atomique) |
| `/opt/spambuntu/previous` → | version précédente, pour le retour arrière |
| `/etc/spambuntu/` | configuration (jamais écrasée par une mise à jour, sauvegardée avant chaque mise à jour) |
| `/var/lib/spambuntu/` | données, état des mises à jour, sauvegardes (5 dernières) |

## Mise en route (une seule fois)

1. **Créer la clé de signature** sur votre poste, puis déclarer le secret :
   ```bash
   tools/gen-signing-key.sh
   gh secret set UPDATE_SIGNING_KEY < ~/.spambuntu-signing/update-signing-key.pem
   git add appliance/etc/update-pubkey.pem && git commit -m "Ajoute la clé publique de signature"
   ```
   Sauvegardez la clé privée : sans elle, les appliances déjà installées ne pourront plus être
   mises à jour en ligne (réinstallation par ISO nécessaire).
2. **Dépôt privé ?** L'appliance doit alors lire les releases avec un jeton GitHub en lecture
   seule (fine-grained, permission *Contents: Read* sur ce seul dépôt), à placer dans
   `/etc/spambuntu/update.conf` (`token = …` ou `token_file = …`). Un dépôt public n'en a pas besoin.
3. **Première installation** d'une appliance : extraire une archive de release (ou l'embarquer
   dans l'ISO) puis `sudo ./install.sh` (`--no-start` pour la construction d'une ISO). Le script
   affiche une fois le mot de passe administrateur de la console ; `spambuntu-passwd` permet de
   le changer. La clé publique est embarquée dans l'archive : l'ISO n'a donc rien d'autre à contenir.

## Publier une version

```bash
# 1. Décrire les changements dans CHANGELOG.md, section « ## [0.2.0] - AAAA-MM-JJ »
#    (ce texte est affiché dans la console avant l'installation)
git commit -am "Notes de la version 0.2.0"
tools/release.sh 0.2.0            # met à jour VERSION, committe, crée le tag v0.2.0
git push origin main --follow-tags
```

Le workflow `Release` publie l'archive signée. Une préversion (`0.3.0-rc.1`) est publiée comme
*pre-release* et n'est proposée qu'aux appliances configurées avec `channel = beta`.

Pour obliger les appliances à passer par une version intermédiaire (migration lourde), mettre
cette version dans `MIN_FROM_VERSION` avant de publier.

## Côté console web

Menu **Mises à jour** : version installée, recherche manuelle, notes de la nouvelle version,
installation avec progression en direct (la console se reconnecte seule après son redémarrage),
et retour à la version précédente. Une recherche automatique tourne chaque jour
(`spambuntu-update-check.timer`) ; l'installation reste toujours déclenchée par un administrateur.

En ligne de commande, avec les mêmes garanties : `spambuntu-update check | apply | rollback | status`.

## Sécurité

- **Aucune release n'est installée sans signature valide** (Ed25519, vérifiée avec OpenSSL contre
  la clé publique locale). Sans clé publique installée, la mise à jour est refusée. Un compte GitHub
  compromis ne suffit donc pas : il faut aussi la clé de signature.
- L'archive est extraite avec contrôle des chemins (pas de `..`, de lien absolu ou sortant, de
  fichier spécial ni de lien physique) et de la taille.
- La console web tourne sous l'utilisateur `spambuntu`, sans privilège. Elle ne peut que déposer une
  demande (une version SemVer, relue strictement) et démarrer **deux unités systemd précises** via
  sudo. L'installation est faite par ces unités, en root, hors du processus web.
- Le jeton GitHub n'est jamais envoyé à un autre hôte lors des redirections de téléchargement.
- Console : mots de passe hachés (scrypt), protection CSRF, limitation des tentatives de connexion,
  CSP stricte (aucun script inline), cookies `HttpOnly` + `SameSite`.
- La console écoute par défaut sur `127.0.0.1:8080` **sans TLS** : placez-la derrière un reverse
  proxy TLS avant de l'exposer (`SPAMBUNTU_BIND` dans `/etc/spambuntu/webui.env`, et
  `"cookie_secure": true` dans `webui.json` une fois en HTTPS).

## Retour arrière : ce qui est (et n'est pas) annulé

Le retour arrière remet l'ancien **code** et relance ses unités. Il ne défait **pas** les migrations
déjà exécutées ni les données écrites entre-temps. Règle pour les migrations
(`appliance/hooks/migrations/`) : rester compatibles avec la version précédente (ajouter d'abord,
supprimer à la version suivante) et idempotentes. La configuration d'avant la mise à jour est
sauvegardée dans `/var/lib/spambuntu/backups/`.

## Développement

```bash
pip install flask pytest
python -m pytest -q            # moteur, console, scripts de release, installation, mise à jour de bout en bout
shellcheck -S warning appliance/install.sh appliance/hooks/*.sh tools/*.sh
```

`install.sh` accepte `DESTDIR=/chemin` pour installer dans une arborescence sans toucher au
système (utilisé par les tests et utile pour construire une ISO).
