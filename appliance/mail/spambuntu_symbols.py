"""Libellés en français des règles Rspamd, pour les vues d'analyse (jamais utilisés pour décider).

`describe(nom)` -> (catégorie, explication). Une règle inconnue garde son nom technique et la catégorie « Autre ».
"""
from __future__ import annotations

import re

CATEGORIES = ("Identité", "Authentification", "Réputation", "Contenu", "Pièces jointes", "Liens", "Apprentissage", "IA", "Autre")

_EXACT = {
    # identité
    "SPAMBUNTU_VIP_SPOOF": ("Identité", "Le nom d'affichage est celui d'un dirigeant protégé, mais l'adresse est externe"),
    "SPAMBUNTU_LOOKALIKE": ("Identité", "Le domaine expéditeur imite le vôtre ou celui d'une marque connue"),
    "SPAMBUNTU_IDN_HOMOGLYPH": ("Identité", "Le domaine mélange des alphabets pour paraître légitime (homoglyphes)"),
    "SPAMBUNTU_BRAND_IN_DOMAIN": ("Identité", "Le nom d'une marque ou de votre domaine figure dans un autre domaine"),
    "SPOOF_DISPLAY_NAME": ("Identité", "Le nom d'affichage contient une adresse qui n'est pas celle de l'expéditeur"),
    "FORGED_SENDER": ("Identité", "L'expéditeur de l'enveloppe diffère de l'adresse affichée"),
    "FROM_NEQ_DISPLAY_NAME": ("Identité", "Le nom d'affichage ressemble à une adresse différente de la vraie"),
    "SPOOF_REPLYTO": ("Identité", "L'adresse de réponse imite celle de l'expéditeur"),
    "FREEMAIL_REPLYTO_NEQ_FROM_DOM": ("Identité", "Réponse dirigée vers une messagerie gratuite, différente de l'expéditeur"),
    "REPLYTO_DOM_NEQ_FROM_DOM": ("Identité", "Le domaine de réponse diffère de celui de l'expéditeur"),
    "FREEMAIL_FROM": ("Identité", "Expéditeur sur une messagerie gratuite"),
    "FREEMAIL_REPLYTO": ("Identité", "Adresse de réponse sur une messagerie gratuite"),
    # authentification
    "R_SPF_FAIL": ("Authentification", "SPF : l'adresse IP n'est pas autorisée à envoyer pour ce domaine"),
    "R_SPF_SOFTFAIL": ("Authentification", "SPF : l'adresse IP n'est probablement pas autorisée"),
    "R_SPF_ALLOW": ("Authentification", "SPF : l'adresse IP est autorisée"),
    "R_SPF_NA": ("Authentification", "SPF : aucune politique publiée"),
    "R_DKIM_REJECT": ("Authentification", "DKIM : signature invalide"),
    "R_DKIM_ALLOW": ("Authentification", "DKIM : signature valide"),
    "R_DKIM_NA": ("Authentification", "DKIM : aucune signature"),
    "DMARC_POLICY_REJECT": ("Authentification", "DMARC : échec alors que le domaine demande le rejet"),
    "DMARC_POLICY_QUARANTINE": ("Authentification", "DMARC : échec alors que le domaine demande la quarantaine"),
    "DMARC_POLICY_SOFTFAIL": ("Authentification", "DMARC : échec avec une politique indulgente"),
    "DMARC_POLICY_ALLOW": ("Authentification", "DMARC : message conforme"),
    "DMARC_NA": ("Authentification", "DMARC : aucune politique publiée"),
    "VIOLATED_DIRECT_SPF": ("Authentification", "Le domaine de l'expéditeur interdit ce serveur d'envoi"),
    "ARC_NA": ("Authentification", "Pas de chaîne ARC"),
    # réputation / infrastructure
    "HFILTER_HOSTNAME_UNKNOWN": ("Réputation", "Le nom annoncé par le serveur d'envoi n'existe pas"),
    "HFILTER_HELO_IP_A": ("Réputation", "Le serveur s'annonce avec une adresse IP"),
    "HFILTER_FROMHOST_NORES_A_OR_MX": ("Réputation", "Le domaine de l'expéditeur n'a pas de serveur de messagerie déclaré"),
    "HFILTER_HELO_NORES_A_OR_MX": ("Réputation", "Le nom annoncé par le serveur n'a pas d'adresse déclarée"),
    "RDNS_NONE": ("Réputation", "L'adresse IP n'a pas de nom inverse (rDNS)"),
    "RDNS_DNSFAIL": ("Réputation", "Le nom inverse de l'adresse IP n'a pas pu être vérifié"),
    "RCVD_COUNT_ZERO": ("Réputation", "Aucun en-tête « Received »"),
    "AUTH_NA": ("Réputation", "Expéditeur non authentifié"),
    # contenu
    "SPAMBUNTU_IMAGE_ONLY": ("Contenu", "Message presque sans texte, composé d'images"),
    "BULK_HEADER": ("Contenu", "En-têtes d'envoi en masse"),
    "MISSING_DATE": ("Contenu", "Date absente"),
    "DATE_IN_PAST": ("Contenu", "Date ancienne"),
    "DATE_IN_FUTURE": ("Contenu", "Date dans le futur"),
    "MISSING_MID": ("Contenu", "Identifiant de message absent"),
    "MISSING_XM_UA": ("Contenu", "Logiciel d'envoi non indiqué"),
    "ZERO_FONT": ("Contenu", "Texte invisible (police de taille nulle)"),
    "R_SUSPICIOUS_IMAGES": ("Contenu", "Images suspectes"),
    "R_EMPTY_IMAGE": ("Contenu", "Image vide"),
    "R_MIXED_CHARSET": ("Contenu", "Alphabets mélangés dans le texte"),
    "MIME_HTML_ONLY": ("Contenu", "Message en HTML seul, sans version texte"),
    "MIME_GOOD": ("Contenu", "Structure MIME normale"),
    # pièces jointes
    "MIME_BAD_EXTENSION": ("Pièces jointes", "Pièce jointe d'un type dangereux"),
    "MIME_DOUBLE_BAD_EXTENSION": ("Pièces jointes", "Pièce jointe à double extension"),
    "MIME_ARCHIVE_IN_ARCHIVE": ("Pièces jointes", "Archive contenue dans une archive"),
    "MIME_ENCRYPTED_ARCHIVE": ("Pièces jointes", "Archive protégée par mot de passe"),
    "MIME_OBFUSCATED_ARCHIVE": ("Pièces jointes", "Archive à l'extension trompeuse"),
    # liens
    "HTML_SHORT_LINK_IMG_1": ("Liens", "Image cliquable vers un lien raccourci"),
    "HTML_SHORT_LINK_IMG_2": ("Liens", "Image cliquable vers un lien raccourci"),
    "HTML_SHORT_LINK_IMG_3": ("Liens", "Image cliquable vers un lien raccourci"),
    "HTML_META_REFRESH_URL": ("Liens", "Redirection automatique vers un autre site"),
    "SEM_URIBL_FRESH15": ("Liens", "Lien vers un domaine enregistré depuis moins de 15 jours"),
    # apprentissage
    "BAYES_SPAM": ("Apprentissage", "Le filtre bayésien reconnaît ce message comme du spam"),
    "BAYES_HAM": ("Apprentissage", "Le filtre bayésien reconnaît ce message comme légitime"),
    # IA
    "SPAMBUNTU_AI": ("IA", "Points ajoutés par l'analyse d'intention (IA)"),
}

_PATTERNS = (
    (re.compile(r"^SPAMBUNTU_AI_"), ("IA", "Drapeau relevé par l'analyse d'intention (IA)")),
    (re.compile(r"^(RBL_|RWL_|DNSWL_)"), ("Réputation", "Adresse IP présente dans une liste de réputation")),
    (re.compile(r"^(URIBL_|SURBL_|DBL_|SEM_URIBL)"), ("Liens", "Domaine présent dans une liste noire de liens")),
    (re.compile(r"^PHISH"), ("Liens", "Lien ou page connus pour de l'hameçonnage")),
    (re.compile(r"VIRUS|MALWARE|TROJAN|RANSOM|EXPLOIT"), ("Pièces jointes", "Programme malveillant détecté")),
    (re.compile(r"^(MIME_|ATTACH)"), ("Pièces jointes", "Particularité de structure ou de pièce jointe")),
    (re.compile(r"^(HFILTER_|RCVD_|RDNS_)"), ("Réputation", "Contrôle de l'infrastructure d'envoi")),
    (re.compile(r"^(R_DKIM|R_SPF|DKIM|DMARC)"), ("Authentification", "Contrôle d'authentification")),
    (re.compile(r"^(FROM_|TO_|REPLYTO_|FORGED_|SPOOF)"), ("Identité", "Contrôle des adresses de l'en-tête")),
    (re.compile(r"^(HTML_|URL_|URI_|SUBJECT_|BODY_)"), ("Contenu", "Particularité du contenu")),
    (re.compile(r"^BAYES_"), ("Apprentissage", "Filtre bayésien")),
)


def describe(name: str) -> tuple:
    """(catégorie, explication) d'une règle ; ("Autre", "") si elle n'est pas connue."""
    if name in _EXACT:
        return _EXACT[name]
    for pattern, info in _PATTERNS:
        if pattern.search(name):
            return info
    return ("Autre", "")


def known_names() -> list:
    """Noms de règles décrits, pour la saisie assistée des conditions « Règle Rspamd déclenchée »."""
    return sorted(_EXACT)
