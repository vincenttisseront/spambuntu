#!/usr/bin/env python3
"""Transforme iso/user-data en version de test automatisé (ISO « -CITEST », jamais distribuée) :
compte jetable, aucune question, extinction à la fin, et vérifications écrites sur le port série.
"""
import subprocess
import sys
from pathlib import Path

PASSWORD = "ci-test-only"

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
if "interactive-sections:\n    - identity\n" not in text:
    sys.exit("user-data inattendu : section interactive introuvable")
hash_ = subprocess.run(["openssl", "passwd", "-6", PASSWORD], check=True, capture_output=True, text=True).stdout.strip()
text = text.replace(
    "interactive-sections:\n    - identity\n",
    f"identity:\n    hostname: spambuntu\n    username: citest\n    password: '{hash_}'\n",
)
checks = [
    "echo SPAMBUNTU-CITEST-BEGIN > /dev/ttyS0",
    "curtin in-target --target=/target -- sh -c 'spambuntu-update status --json 2>&1 | head -c 600; echo; "
    "ls -l /opt/spambuntu/ /etc/spambuntu/ /root/spambuntu-console-password.txt; "
    "systemctl is-enabled spambuntu-webui.service spambuntu-update-check.timer; "
    "visudo -c; test -s /etc/spambuntu/update-pubkey.pem && echo PUBKEY-OK' > /target/root/citest.log 2>&1",
    "cat /target/root/citest.log > /dev/ttyS0",
    "echo SPAMBUNTU-CITEST-END > /dev/ttyS0",
]
text = text.rstrip("\n") + "\n" + "".join(f"    - {c!r}\n" if "'" not in c else f"    - \"{c}\"\n" for c in checks)
text += "  shutdown: poweroff\n"
path.write_text(text, encoding="utf-8")
