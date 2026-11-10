#!/usr/bin/env python3
"""Prépare le dépôt apt embarqué de l'ISO : les .deb que le système installé par l'ISO ne contient pas.

  iso_debs.py MANIFEST... --packages packages.txt --out DIR

Les MANIFEST sont ceux de l'ISO Ubuntu (casper/*.manifest, format « diff » : lignes +nom<TAB>version).
Ils servent à simuler l'installation sur un système identique à celui de l'ISO ; seuls les paquets
qu'apt installerait réellement sont téléchargés (et vérifiés par apt, via la signature des dépôts Ubuntu).
À exécuter sur Ubuntu 24.04 (le même suite que l'ISO).
"""
import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def installed_set(manifests):
    inst = {}
    for manifest in manifests:
        for line in Path(manifest).read_text(encoding="utf-8").splitlines():
            if line.startswith(("+++", "---")) or not line or line[0] not in "+-":
                continue
            name, _, version = line[1:].partition("\t")
            base = name.split(":")[0]
            if line[0] == "+":
                inst[base] = (name, version)
            else:
                inst.pop(base, None)
    return inst


def write_status(inst, path):
    with open(path, "w", encoding="utf-8") as fh:
        for base, (name, version) in sorted(inst.items()):
            arch = name.split(":")[1] if ":" in name else "all"
            fh.write(f"Package: {base}\nStatus: install ok installed\nArchitecture: {arch}\n"
                     f"Version: {version}\nMaintainer: iso\nDescription: iso\n\n")


def plan(status, packages):
    out = subprocess.run(
        ["apt-get", "-s", "-o", f"Dir::State::status={status}", "-o", "Debug::NoLocking=1",
         "install", "--no-install-recommends", *packages],
        check=True, capture_output=True, text=True).stdout
    todo = []
    for line in out.splitlines():
        m = re.match(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) ", line)
        if m and m.group(2) != m.group(3):          # même version = rien à faire
            todo.append((m.group(1), m.group(3)))
    return todo


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("manifests", nargs="+")
    ap.add_argument("--packages", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    packages = [l.strip() for l in Path(args.packages).read_text(encoding="utf-8").splitlines()
                if l.strip() and not l.lstrip().startswith("#")]
    inst = installed_set(args.manifests)
    if len(inst) < 300:
        sys.exit(f"manifeste suspect ({len(inst)} paquets) : abandon")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        status = Path(tmp) / "status"
        write_status(inst, status)
        todo = plan(status, packages)
    if not todo:
        sys.exit("aucun paquet à embarquer : simulation incohérente")
    print("Paquets embarqués :", ", ".join(f"{n}={v}" for n, v in todo))
    subprocess.run(["apt-get", "-q", "-o", "APT::Sandbox::User=root", "download",
                    *[f"{n}={v}" for n, v in todo]], cwd=out, check=True)
    packages_file = subprocess.run(["dpkg-scanpackages", "--multiversion", ".", "/dev/null"], cwd=out,
                                   check=True, capture_output=True, text=True).stdout
    (out / "Packages").write_text(packages_file, encoding="utf-8")


if __name__ == "__main__":
    main()
