# Règles antispam : correspondance avec le catalogue de référence

Ce document met en regard le catalogue de règles d'un antispam moderne (authentification, usurpation,
réputation, contenu) et ce que fait Spambuntu aujourd'hui. Statuts : **Natif** (fourni par Rspamd, activé),
**Ajouté** (règle écrite pour Spambuntu), **Partiel**, **Absent**.

## 1. Authentification

| Règle | Statut | Mise en œuvre |
|---|---|---|
| SPF | Natif | Modules SPF de Rspamd (`R_SPF_*`) |
| DKIM | Natif | Vérification des signatures (`R_DKIM_*`) |
| DMARC + alignement | Natif | Module DMARC de Rspamd (`DMARC_POLICY_*`) |
| Action DMARC « reject » | Ajouté | Réglage `dmarc_action` : `reject` (défaut, conforme au tableau de décision), `quarantine` (rétention pour l'administrateur) ou `score` (points seulement) |

## 2. Usurpation et spoofing

| Règle | Statut | Mise en œuvre |
|---|---|---|
| Usurpation du nom d'affichage (dirigeants) | Ajouté | `SPAMBUNTU_VIP_SPOOF` : liste de dirigeants (nom + adresse) saisie dans « Messagerie ». Compare le nom affiché, sans accents ni casse, avec les noms protégés ; ignore les adresses des domaines déclarés |
| Domaines imitateurs (typosquatting) | Ajouté | `SPAMBUNTU_LOOKALIKE` : distance d'édition ≤ 1 ou 2 selon la longueur, changement d'extension (`.co` pour `.com`), chiffres pour lettres (`micr0soft`), comparés à vos domaines et à une liste de marques (Microsoft, Google, PayPal, DHL, La Poste, Ameli, impots.gouv.fr, OVH…) extensible |
| Marque dans un autre domaine | Ajouté | `SPAMBUNTU_BRAND_IN_DOMAIN` (`microsoft-support.test`), indice faible |
| Homoglyphes / IDN | Ajouté | `SPAMBUNTU_IDN_HOMOGLYPH` : alphabets mélangés dans un même domaine, décodage punycode |
| Reply-To différent de From | Natif | `REPLYTO_DOM_NEQ_FROM_DOM`, `FREEMAIL_REPLYTO_NEQ_FROM_DOM` ; le domaine du Reply-To est aussi soumis aux règles d'imitation |

Sécurité des règles d'identité : une seule évaluation par message, seule la règle la plus grave pèse ;
le total est plafonné au seuil de quarantaine, de sorte qu'une heuristique d'identité **ne rejette jamais
seule** (un faux positif reste récupérable par l'administrateur).

## 3. Réputation et infrastructure

| Règle | Statut | Mise en œuvre |
|---|---|---|
| Listes noires IP / domaines | Natif | Listes DNS de Rspamd. Le résolveur de l'appliance doit être autorisé par les fournisseurs (certaines listes refusent les résolveurs publics) |
| rDNS / PTR, HELO | Natif | `RDNS_*`, `HFILTER_*` |
| Ancienneté du domaine | **Absent** | Aucune source de date d'enregistrement n'est interrogée. Piste : liste de domaines récents (ex. flux NRD) ou requête RDAP avec cache |

## 4. Contenu et pièces jointes

| Règle | Statut | Mise en œuvre |
|---|---|---|
| Analyse sémantique (urgence, demande de paiement) | Ajouté | Analyse d'intention par un serveur Ollama distant, anonymisée, qui ne peut qu'ajouter du risque (`SPAMBUNTU_AI*`) |
| Inspection des URL | Partiel | Listes d'URL malveillantes et raccourcisseurs (Rspamd) ; hameçonnage connu (`PHISHED_*`) ; liens affichés neutralisés dans l'analyse de quarantaine. Pas de suivi des redirections ni de rendu de page |
| Bac à sable des pièces jointes | **Absent** | Pas de détonation. Contrôles de type, double extension et archives chiffrées (`MIME_*`) |
| Antivirus (signatures) | **Absent** | Pas de moteur ClamAV intégré : le « rejet immédiat sur malware » du tableau de décision est préparé (symboles `VIRUS`/`MALWARE` classés « dangereux ») mais n'a pas de détecteur |
| Ratio texte / image | Ajouté | `SPAMBUNTU_IMAGE_ONLY` : au moins une image et moins de 12 mots, indice faible |

## 5. Tableau de décision

| Cas | Décision de référence | Spambuntu |
|---|---|---|
| DMARC reject ou malware | Rejet immédiat | DMARC : rejet par défaut (`dmarc_action`). Malware : en attente d'un moteur antivirus |
| SPF/DKIM invalide, domaine récent | Quarantaine | SPF/DKIM : points au score, quarantaine au seuil. Domaine récent : absent |
| Score modéré | Courrier indésirable + marquage | Marquage `X-Spam: Yes` (le serveur de messagerie destinataire place le courrier dans « Indésirables ») |
| Tout est validé | Livraison normale | Livraison normale |

### Rejet ou quarantaine ?

La documentation de référence parle de « rejet immédiat », la consigne produit de « quarantaine avec rejet
et analyse par un administrateur ». Spambuntu applique les deux :

- les **faux positifs possibles** (heuristiques d'identité, score très élevé) sont **retenus** et visibles
  uniquement de l'administrateur, qui analyse puis libère ou supprime ;
- les **certitudes techniques** (DMARC « reject » publié par l'expéditeur) sont **rejetées au SMTP**,
  sans retenue, ce que le propriétaire du domaine a explicitement demandé ;
- `dmarc_action = quarantine` bascule ce second cas en rétention administrateur si vous préférez ne rien perdre.

## Prochaines règles envisagées

1. Moteur antivirus (ClamAV) avec rejet à la détection.
2. Âge du domaine expéditeur et des domaines des liens.
3. Détonation des pièces jointes (bac à sable externe).
4. Corrélation de campagnes (similarité du contenu entre messages).
