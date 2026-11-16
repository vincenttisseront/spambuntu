# Sandbox des pièces jointes

Un seul ISO, deux installations : **passerelle** (antispam) et **sandbox** (worker de détonation, VM Linux sous VMware avec virtualisation imbriquée, `vhv.enable = TRUE`).

## Premier niveau (passerelle, livré)
`spambuntu-sandboxd` (127.0.0.1:11341, compte `spambuntu-sandboxd`) reçoit le message de Rspamd (module `spambuntu_sandbox.lua`, post-filtre), extrait pièces jointes et liens (bornés, en mémoire, rien n'est exécuté), applique l'analyse statique et renvoie un verdict `none|clean|suspicious|malicious` avec explication. Les empreintes SHA-256 sont mises en cache (24 h par défaut).

Configuration : `/etc/spambuntu-sandbox/sandbox.json` (`{"mode": "off|monitor|enforce"}` + limites, voir `spambuntu-sandboxctl show`).
- `off` : aucun effet. `monitor` : verdict journalisé (`/var/log/spambuntu/sandbox/audit.jsonl`) et symbole `SPAMBUNTU_SANDBOX_MONITOR` sans points. `enforce` : symboles `SPAMBUNTU_SANDBOX_MALICIOUS/SUSPICIOUS/CLEAN/ERROR` exploités par les règles (classe « logiciel malveillant »).
- Une panne ne bloque jamais le courrier (échec ouvert).

Commandes : `spambuntu-sandboxctl analyze < message.eml`, `show`, `check`.

## Worker (rôle sandbox)
`spambuntu-sandbox check|status|firewall` : contrôles (CPU virtualisé, /dev/kvm, Firecracker, images signées, appairage) et pare-feu nftables « tout refusé » (SSH + passerelle:8444).

## À venir
Protocole passerelle↔worker (mTLS, jeton d'appairage 15 min), détonation en microVM Firecracker, analyse IA du rapport, page console « Sandbox », détonation des liens.
