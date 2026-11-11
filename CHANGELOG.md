# Changelog

Le contenu de la section d'une version est publié comme notes de release et affiché dans la
console web de l'appliance au moment de proposer la mise à jour.

## [0.3.0] - 2026-11-11

### Ajouté
- Tableau de bord : compteurs et histogramme des dernières 24 h, domaines et règles les plus fréquents.
- Page « Journal » : recherche de messages (expéditeur, destinataire, IP, identifiant), métadonnées uniquement.
- Analyse IA des messages ambigus par un serveur Ollama distant (désactivée par défaut, mode « fantôme »
  disponible) : anonymisation avant envoi, contenu isolé contre l'injection de prompt, réponse JSON stricte,
  l'IA ne peut qu'ajouter du risque et jamais, seule, faire rejeter un message, budget horaire,
  disjoncteur, journal d'audit des envois, cascade petit/gros modèle.
- Page « IA » de la console : mode, serveur, jeton (écriture seule), autorité de certification privée, modèles,
  limites ; la configuration est appliquée par un service root qui teste la connexion.
- Quarantaine : l'explication de l'analyse IA est affichée ; « Légitime : libérer » et « Spam : supprimer »
  entraînent le filtre bayésien et alimentent un corpus de retours (métadonnées seulement).
- Résumé quotidien de quarantaine (désactivé par défaut) : un courrier par destinataire des domaines déclarés,
  avec, si l'adresse de la console est renseignée, des liens de libération personnels signés (3 jours, confirmation
  obligatoire, limités aux messages peu suspects).
- Quarantaine par niveau de risque : les messages dangereux (logiciel malveillant, hameçonnage, fraude au
  président ou à la facture, usurpation, demande d'identifiants ou de paiement, tentative d'injection,
  pièce jointe douteuse, score très élevé ou message non évalué) sont réservés à l'administrateur ;
  seul le courrier indésirable ordinaire peut être géré par son destinataire.
- Espace « Mes messages retenus » (lien personnel signé du résumé) : le destinataire libère ou supprime
  ses seuls messages ordinaires ; il voit le nombre de messages bloqués sans pouvoir les consulter ;
  aucun entraînement du filtre depuis cet espace.
- Libérer un message dangereux demande à l'administrateur une confirmation explicite après analyse.

### Modifié
- Nouvelle identité visuelle de la console : barre latérale par rubriques, icônes, thème clair/sombre
  (mémorisé), polices servies par l'appliance (aucune ressource externe), vue utilisateur épurée.
  Code couleur : rouge = réservé à l'administrateur, bleu = courrier ordinaire gérable, orange = attention.

## [0.2.0] - 2026-11-11

### Ajouté
- Passerelle de messagerie : Postfix reçoit le courrier des domaines déclarés, Rspamd le note
  (SPF, DKIM, DMARC, réputation, filtre bayésien), puis le courrier sain est transmis à votre
  serveur de messagerie. Aucun relais ouvert : seuls les domaines déclarés sont acceptés.
- Trois niveaux d'action réglables : marquage (en-tête `X-Spam: Yes`), quarantaine, rejet.
- Page « Quarantaine » dans la console : lire, libérer ou supprimer les messages retenus
  (chaque action est journalisée dans `/var/log/spambuntu/quarantine.log`).
- Vérification des destinataires auprès du serveur de destination (option) : une adresse inexistante est
  refusée tout de suite, sans rejet renvoyé à un expéditeur usurpé.
- TLS entrant (STARTTLS, TLS 1.2 minimum) avec un certificat auto-signé généré à l'installation.
- Page « Messagerie » dans la console : domaines, serveurs de destination, seuils, réseaux de confiance.

### Mise à jour depuis 0.1.x
- Installe Postfix, Rspamd et Redis (accès aux dépôts Ubuntu requis) et crée une configuration vide :
  rien n'est relayé tant que vous n'avez pas déclaré de domaine.

## [0.1.1] - 2026-11-10

### Corrigé
- Première release signée (la 0.1.0 n'a jamais été publiée : tests de publication à corriger).

## [0.1.0] - 2026-11-10

### Ajouté
- Mise à jour en ligne depuis la console web : détection d'une nouvelle version, installation
  en un clic, sans repasser par l'ISO.
- Vérification de la signature (Ed25519) de chaque release avant installation.
- Retour arrière automatique si la nouvelle version ne démarre pas correctement, et retour
  manuel à la version précédente depuis la console.
- Recherche quotidienne automatique de nouvelles versions.
- Console servie en HTTPS (port 8443, certificat auto-signé), mot de passe initial écrit dans
  `/root/spambuntu-console-password.txt`.
- `spambuntu-update verify` : contrôle, sans l'installer, qu'une release publiée est utilisable.
- ISO d'installation (`tools/build-iso.sh`, workflow *ISO*) basée sur Ubuntu Server 24.04.
