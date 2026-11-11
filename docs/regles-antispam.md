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
| Action DMARC « reject » | Ajouté | Règle `inbound_dmarc` de la page « Règles » : rejet (défaut, conforme au tableau de décision), quarantaine réservée à l'administrateur, ou règle désactivée (points seulement) |

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
| DMARC reject ou malware | Rejet immédiat | DMARC : rejet par défaut (règle `inbound_dmarc`). Malware : en attente d'un moteur antivirus |
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
- la règle `inbound_dmarc` (page « Règles ») bascule ce second cas en rétention administrateur si vous préférez ne rien perdre.

## 6. Moteur de règles (page « Règles »)

Le courrier est évalué par une liste **ordonnée** de règles ; la première règle qui s'applique décide, sauf les règles
« Poursuivre », qui n'ajoutent que des en-têtes. Le moteur s'exécute dans Rspamd **après** l'analyse IA, donc voit
toutes les règles déclenchées. Sans configuration lisible, il ne fait rien et les seuils de score restent seuls juges.

| Classe | Score 0-100 | Origine |
|---|---|---|
| Spam | interpolé sur les seuils de la page Messagerie (marquage = 25, quarantaine = 50, rejet = 100) | score Rspamd |
| Logiciel malveillant | additionne des signaux : virus (100), double extension (60), extension dangereuse, archive chiffrée ou imbriquée (40), leurre IA (60) | symboles Rspamd |
| Hameçonnage | `PHISH*` (100), IA hameçonnage (85), IA identifiants (60), domaine récent d'URL, redirection HTML | symboles Rspamd + IA |
| Usurpation et fraude | dirigeant (100), domaine imitateur / homoglyphes (90), nom d'affichage (60), DMARC « reject » (60), IA fraude au président (90), changement de coordonnées (70), cartes cadeaux (70)… | symboles Spambuntu + IA |
| Courrier en masse | en-têtes de liste / `Precedence: bulk` (60), désabonnement (40) | symboles Rspamd |

Conditions disponibles : les cinq scores, le score Rspamd brut, appartenance à la liste de blocage ou sûre, échec DMARC
« reject », présence d'une règle Rspamd précise, adresse de l'expéditeur (contient / égale / se termine par), adresse d'un
destinataire. Actions : livrer, marquer (`X-Spam: Yes`), mettre en quarantaine dans un **dossier**, rejeter, poursuivre.

Garde-fous :
- `inbound_blocked`, `inbound_safe` et `inbound_notspam` ne se suppriment pas et leur condition est verrouillée ;
  `inbound_notspam` est toujours active et toujours la dernière (elle livre ce qu'aucune règle n'a retenu).
- La **liste sûre exige une authentification** (DMARC validé ou SPF aligné) ; une adresse IP de la liste suffit. La liste
  de blocage n'exige rien. Une règle personnalisée qui livre d'après la seule adresse de l'expéditeur provoque un avertissement.
- Un dossier de quarantaine « accessible à l'utilisateur » ne rend **jamais** libérable un message portant un signal de
  danger (logiciel malveillant, hameçonnage, usurpation, score très élevé) : la règle ne peut que restreindre.
- Les en-têtes `X-Spambuntu-Rule` et `X-Spambuntu-Scores` envoyés par l'expéditeur sont toujours supprimés.
- Le moteur Python (aperçu, tests) et le moteur Lua (Rspamd) sont vérifiés sur les mêmes cas de référence
  (`tests/data/rules_golden.json`).

Limites : pas de suppression silencieuse (Rspamd 3.8 ne connaît pas l'action « discard » : utiliser le rejet), pas de
listes personnelles par utilisateur, pas de classes « adulte » ni « suspect », pas d'antivirus ni de bac à sable.

## Prochaines règles envisagées

1. Moteur antivirus (ClamAV) avec rejet à la détection.
2. Âge du domaine expéditeur et des domaines des liens.
3. Détonation des pièces jointes (bac à sable externe).
4. Corrélation de campagnes (similarité du contenu entre messages).
