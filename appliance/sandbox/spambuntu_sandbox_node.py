#!/usr/bin/env python3
"""Nœud « sandbox » de Spambuntu (rôle installé par l'entrée « Installer Spambuntu Sandbox » de l'ISO).

  spambuntu-sandbox check [--json]                          prérequis de détonation (KVM, Firecracker, images)
  spambuntu-sandbox status [--json]                         rôle, version, appairage, résultat des contrôles
  spambuntu-sandbox firewall render --gateway IP [options]  règles nftables (affichage)
  spambuntu-sandbox firewall apply  --gateway IP [options]  root : écrit et charge les règles

Ce nœud n'a ni console web ni service ouvert : il ne fait que joindre la passerelle (modèle « tirer »).
Les contrôles s'appuient sur des chemins injectables pour être testés sans matériel.
Bibliothèque standard uniquement.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_GATEWAY_PORT = 8444


@dataclass
class Paths:
    root: Path = Path("/")

    def p(self, rel: str) -> Path:
        return self.root / rel.lstrip("/")

    @property
    def cpuinfo(self) -> Path: return self.p("/proc/cpuinfo")
    @property
    def kvm(self) -> Path: return self.p("/dev/kvm")
    @property
    def firecracker(self) -> Path: return self.p("/opt/spambuntu/sandbox/bin/firecracker")
    @property
    def images(self) -> Path: return self.p("/var/lib/spambuntu/sandbox/images")
    @property
    def etc(self) -> Path: return self.p("/etc/spambuntu")
    @property
    def role_file(self) -> Path: return self.etc / "role"
    @property
    def worker_conf(self) -> Path: return self.etc / "sandbox" / "worker.json"
    @property
    def nft_conf(self) -> Path: return self.etc / "sandbox" / "nftables.conf"
    @property
    def version_file(self) -> Path: return self.p("/opt/spambuntu/current/VERSION")


@dataclass
class Check:
    id: str
    level: str           # ok | warn | error
    message: str
    hint: str = ""

    def as_dict(self) -> dict:
        return {"id": self.id, "level": self.level, "message": self.message, "hint": self.hint}


VMWARE_HINT = ("VMware : éteindre la VM, Modifier les paramètres > Processeur > cocher « Exposer la virtualisation "
               "assistée par le matériel au système d'exploitation invité » (vhv.enable = TRUE), puis la rallumer.")


def _cpu_flags(cpuinfo: Path) -> set[str]:
    try:
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("flags"):
                return set(line.partition(":")[2].split())
    except OSError:
        pass
    return set()


def run_checks(paths: Paths | None = None) -> list[Check]:
    paths = paths or Paths()
    out: list[Check] = []

    flags = _cpu_flags(paths.cpuinfo)
    virtualized = "hypervisor" in flags
    if flags & {"vmx", "svm"}:
        out.append(Check("cpu_virt", "ok", "Le processeur expose la virtualisation matérielle (VT-x / AMD-V)."))
    else:
        out.append(Check("cpu_virt", "error", "Le processeur n'expose pas VT-x / AMD-V : les microVM sont impossibles.",
                         VMWARE_HINT if virtualized else "Activer VT-x / AMD-V dans le BIOS de la machine."))

    if not paths.kvm.exists():
        out.append(Check("kvm", "error", "/dev/kvm est absent.", "Charger le module kvm_intel ou kvm_amd ; voir le contrôle précédent."))
    elif not os.access(paths.kvm, os.R_OK | os.W_OK):
        out.append(Check("kvm", "error", "/dev/kvm n'est pas accessible en lecture/écriture.", "Vérifier le groupe kvm du compte du worker."))
    else:
        out.append(Check("kvm", "ok", "/dev/kvm est disponible."))

    if paths.firecracker.is_file() and os.access(paths.firecracker, os.X_OK):
        out.append(Check("firecracker", "ok", "Firecracker est installé."))
    else:
        out.append(Check("firecracker", "warn", "Firecracker n'est pas encore installé (fourni avec le worker dans une prochaine version)."))

    out.append(_check_images(paths.images))

    if paths.worker_conf.is_file():
        out.append(Check("pairing", "ok", "Ce nœud est appairé à une passerelle."))
    else:
        out.append(Check("pairing", "warn", "Ce nœud n'est pas encore appairé à une passerelle."))
    return out


def _check_images(images: Path) -> Check:
    manifest = images / "manifest.json"
    if not manifest.is_file():
        return Check("images", "warn", "Aucune image de microVM installée (fournies avec le worker dans une prochaine version).")
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for key in ("kernel", "rootfs"):
            entry = data[key]
            name = entry["file"]
            if "/" in name or name.startswith("."):
                return Check("images", "error", f"Nom de fichier invalide dans le manifeste ({key}).")
            digest = hashlib.sha256((images / name).read_bytes()).hexdigest()
            if digest != str(entry["sha256"]).lower():
                return Check("images", "error", f"Somme SHA-256 incorrecte pour {name} : image altérée ou corrompue.")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return Check("images", "error", f"Manifeste des images illisible : {exc}")
    return Check("images", "ok", "Images de microVM présentes et vérifiées.")


# ------------------------------------------------------------------ pare-feu

def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        raise ValueError(f"adresse IP invalide : {value!r}") from None


def _net(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ValueError(f"réseau invalide : {value!r}") from None


def _port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"port invalide : {value!r}") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"port invalide : {value!r}")
    return port


def _addr_rule(addr, direction: str) -> str:
    family = "ip6" if addr.version == 6 else "ip"
    return f"{family} {direction} {addr}"


def render_firewall(gateway: str, port: int = DEFAULT_GATEWAY_PORT, ssh_from: list[str] | None = None,
                    extra: list[str] | None = None) -> str:
    """Jeu de règles nftables du worker : tout est refusé, sauf SSH d'administration, et vers la passerelle.

    Le trafic des microVM (forward) est refusé : leur sortie réseau n'est ouverte que par le worker, jamais ici.
    `extra` : « IP:protocole:port » (par exemple un serveur NTP ou DNS interne).
    """
    gw = _ip(gateway)
    port = _port(port)
    lines = [
        "# Géré par Spambuntu : ne pas modifier (spambuntu-sandbox firewall apply)",
        "table inet spambuntu_sandbox",                 # (re)création idempotente de NOTRE table seulement
        "delete table inet spambuntu_sandbox",
        "table inet spambuntu_sandbox {",
        "  chain input {",
        "    type filter hook input priority 0; policy drop;",
        "    ct state established,related accept",
        '    iifname "lo" accept',
        "    ip protocol icmp accept",
        "    meta l4proto ipv6-icmp accept",
        "    udp sport 67 udp dport 68 accept",             # bail DHCP (renouvellement)
    ]
    if ssh_from:
        for net in ssh_from:
            n = _net(net)
            lines.append(f"    {_addr_rule(n, 'saddr')} tcp dport 22 accept")
    else:
        lines.append("    tcp dport 22 accept")
    lines += [
        "  }",
        "  chain forward {",
        "    type filter hook forward priority 0; policy drop;",
        "  }",
        "  chain output {",
        "    type filter hook output priority 0; policy drop;",
        "    ct state established,related accept",
        '    oifname "lo" accept',
        "    ip protocol icmp accept",
        "    meta l4proto ipv6-icmp accept",
        "    udp sport 68 udp dport 67 accept",
        f"    {_addr_rule(gw, 'daddr')} tcp dport {port} accept",
    ]
    for item in extra or []:
        parts = item.split(":")
        if len(parts) < 3:
            raise ValueError(f"règle supplémentaire invalide : {item!r} (attendu IP:protocole:port)")
        addr_text, proto, port_text = ":".join(parts[:-2]), parts[-2].lower(), parts[-1]
        if proto not in ("tcp", "udp"):
            raise ValueError(f"protocole invalide : {proto!r}")
        lines.append(f"    {_addr_rule(_ip(addr_text), 'daddr')} {proto} dport {_port(port_text)} accept")
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def apply_firewall(text: str, paths: Paths | None = None, load: bool = True) -> Path:
    paths = paths or Paths()
    paths.nft_conf.parent.mkdir(parents=True, exist_ok=True)
    tmp = paths.nft_conf.with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    if load:
        check = subprocess.run(["nft", "-c", "-f", str(tmp)], capture_output=True, text=True)
        if check.returncode != 0:
            tmp.unlink(missing_ok=True)
            raise RuntimeError(f"règles nftables refusées : {check.stderr.strip()}")
    os.replace(tmp, paths.nft_conf)
    if load:
        subprocess.run(["nft", "-f", str(paths.nft_conf)], check=True)
    return paths.nft_conf


# ------------------------------------------------------------------ état

def read_role(paths: Paths | None = None) -> str:
    paths = paths or Paths()
    try:
        value = paths.role_file.read_text(encoding="utf-8").strip()
    except OSError:
        return "gateway"
    return value if value in ("gateway", "sandbox") else "gateway"


def status(paths: Paths | None = None) -> dict:
    paths = paths or Paths()
    try:
        version = paths.version_file.read_text(encoding="utf-8").strip()
    except OSError:
        version = "?"
    checks = run_checks(paths)
    return {"role": read_role(paths), "version": version, "paired": paths.worker_conf.is_file(),
            "ready": not any(c.level == "error" for c in checks) and paths.worker_conf.is_file(),
            "checks": [c.as_dict() for c in checks]}


def _print_checks(checks: list[Check]) -> None:
    marks = {"ok": "[ OK ]", "warn": "[ !! ]", "error": "[FAIL]"}
    for c in checks:
        print(f"{marks[c.level]} {c.message}")
        if c.hint and c.level != "ok":
            print(f"       -> {c.hint}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="spambuntu-sandbox", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "status"):
        sp = sub.add_parser(name)
        sp.add_argument("--json", action="store_true")
    fw = sub.add_parser("firewall")
    fw.add_argument("action", choices=["render", "apply"])
    fw.add_argument("--gateway", required=True)
    fw.add_argument("--port", type=int, default=DEFAULT_GATEWAY_PORT)
    fw.add_argument("--ssh-from", action="append", default=[], metavar="RÉSEAU")
    fw.add_argument("--allow", action="append", default=[], metavar="IP:tcp|udp:PORT")
    args = ap.parse_args(argv)

    if args.cmd == "check":
        checks = run_checks()
        if args.json:
            print(json.dumps([c.as_dict() for c in checks], ensure_ascii=False, indent=2))
        else:
            _print_checks(checks)
        return 1 if any(c.level == "error" for c in checks) else 0
    if args.cmd == "status":
        st = status()
        if args.json:
            print(json.dumps(st, ensure_ascii=False, indent=2))
        else:
            print(f"Rôle : {st['role']} · version {st['version']} · {'appairé' if st['paired'] else 'non appairé'}")
            _print_checks([Check(**c) for c in st["checks"]])
        return 0
    try:
        text = render_firewall(args.gateway, args.port, args.ssh_from, args.allow)
        if args.action == "render":
            print(text, end="")
        else:
            if os.geteuid() != 0:
                print("Erreur : cette commande doit être exécutée en root.", file=sys.stderr)
                return 1
            print(f"Règles écrites et chargées : {apply_firewall(text)}")
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
