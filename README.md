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
3. **Pousser le tag `v0.1.1`** (voir « Publier une version ») : le workflow *Release* publie la
   première release signée. Sans elle, une appliance fraîchement installée n'a rien à détecter.
4. **Générer l'ISO** (voir ci-dessous).

## Générer l'ISO d'installation

```bash
tools/build-iso.sh                  # → dist/spambuntu-0.1.1-amd64.iso (+ .sha256)
```

Ou, sans rien installer en local : onglet *Actions* → *ISO* → *Run workflow* (l'ISO, ~4 Go, est un
artefact du workflow : elle dépasse la limite de 2 Gio des fichiers de release GitHub).

C'est l'ISO officielle Ubuntu Server 24.04 (téléchargée, puis vérifiée par la signature GPG de
`SHA256SUMS` et la somme SHA-256), à laquelle on ajoute la release Spambuntu, les quelques paquets
Ubuntu qui manquent (Flask, gunicorn, openssl, sudo : l'installation n'a pas besoin d'internet) et
une entrée de menu « Installer Spambuntu ». Le script refuse de construire une ISO sans la clé
publique de signature (`appliance/etc/update-pubkey.pem`) : une appliance sans elle refuserait
toutes les mises à jour.

À l'installation, Ubuntu demande confirmation avant d'effacer le disque et vous fait créer le compte
administrateur du système. Spambuntu est ensuite installé automatiquement ; le mot de passe initial
de la console web (`https://<adresse-ip>:8443`, certificat auto-signé) est dans
`/root/spambuntu-console-password.txt`, rappelé à la connexion. Changez-le avec `sudo spambuntu-passwd`.

Une appliance qui n'est pas installée par l'ISO s'installe depuis l'archive d'une release :
`sudo ./install.sh` (`--no-start` pour préparer une image).

**Vérifier que la chaîne de mise à jour fonctionne** (aucune installation, pas besoin d'être root) :

```bash
spambuntu-update verify        # télécharge la dernière release, contrôle la signature avec la clé de l'appliance
```

## Passerelle de messagerie (0.2.0)

L'appliance se place **devant** votre serveur de messagerie : le MX de vos domaines pointe vers elle,
elle filtre, puis transmet le courrier sain à votre serveur.

```
Internet ──► Postfix (25) ──► Rspamd (score) ──► serveur de messagerie
                  │               ├─ score < marquage     : livré tel quel
                  │               ├─ marquage ≤ score     : livré avec « X-Spam: Yes »
                  │               ├─ quarantaine ≤ score  : retenu (page Quarantaine)
                  │               └─ rejet ≤ score        : refusé à l'expéditeur (554)
```

Dans la console : **Messagerie** (domaines et serveur de destination, seuils, réseaux de confiance) et
**Quarantaine** (lire, libérer, supprimer). Par défaut aucun domaine n'est déclaré : l'appliance ne relaie
rien tant que vous n'en avez pas ajouté (jamais de relais ouvert). Si Rspamd est indisponible, les messages
sont différés (jamais livrés sans analyse).

### Règles de filtrage (0.3.0)

La page **Règles** de la console est une liste ordonnée, à la manière des tableaux de règles des passerelles
professionnelles : *classification*, *description*, *condition*, *action*, ordre (flèches), activation, modification,
clonage, suppression. La première règle qui s'applique décide ; une règle « Poursuivre » ajoute seulement des en-têtes.
Les conditions portent sur cinq scores de classe de 0 à 100 (spam, logiciel malveillant, hameçonnage, usurpation et
fraude, courrier en masse), le score Rspamd, les listes de blocage et sûre, DMARC, une règle Rspamd précise,
l'expéditeur ou un destinataire. Les actions : livrer, marquer, mettre en quarantaine dans un dossier (réservé à
l'administrateur ou accessible au destinataire), rejeter. Voir `docs/regles-antispam.md`.

Choix de conception :
- La console ne modifie rien dans `/etc` : elle dépose une demande que `spambuntu-mail-apply.service`
  (root) **revalide** avant d'écrire la configuration de Postfix et de Rspamd. Si Postfix ou Rspamd la
  refusent (`postfix check`, `rspamadm configtest`), l'ancienne configuration est rétablie.
- La quarantaine est la file « hold » de Postfix, alimentée par Rspamd via le milter : un expéditeur ne peut
  pas forcer ni empêcher la quarantaine avec un en-tête forgé. Chaque libération ou suppression est
  journalisée dans `/var/log/spambuntu/quarantine.log`.
- Le greylisting de Rspamd est désactivé (il retarde le premier message de tout nouvel expéditeur).

Pas encore couvert : certificat TLS de confiance pour la passerelle (le certificat auto-signé suffit pour
STARTTLS entre serveurs), signature DKIM sortante.

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
