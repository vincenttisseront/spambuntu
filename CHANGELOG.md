# Changelog

Le contenu de la section d'une version est publié comme notes de release et affiché dans la
console web de l'appliance au moment de proposer la mise à jour.

## [0.1.0] - 2026-11-10

### Ajouté
- Mise à jour en ligne depuis la console web : détection d'une nouvelle version, installation
  en un clic, sans repasser par l'ISO.
- Vérification de la signature (Ed25519) de chaque release avant installation.
- Retour arrière automatique si la nouvelle version ne démarre pas correctement, et retour
  manuel à la version précédente depuis la console.
- Recherche quotidienne automatique de nouvelles versions.
