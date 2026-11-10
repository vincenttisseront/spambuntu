<#
.SYNOPSIS
  Construit l'ISO Spambuntu sous Windows 10/11 avec Docker Desktop (aucun outil Linux a installer).
.DESCRIPTION
  Lance Ubuntu 24.04 dans Docker, y installe xorriso & co, puis execute tools/build-iso.sh.
  Premier lancement : telecharge ~3 Go (ISO Ubuntu, mise en cache dans le dossier de sortie) ;
  prevoir ~12 Go de disque. Le script refuse de construire sans appliance\etc\update-pubkey.pem.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tools\make-iso.ps1
  .\tools\make-iso.ps1 -OutDir D:\iso -CaCert C:\certs\proxy.pem
#>
param(
    [string]$OutDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'dist'),
    # Autorite de certification d'un proxy d'entreprise qui inspecte le HTTPS (fichier PEM)
    [string]$CaCert = ''
)
$ErrorActionPreference = 'Stop'
function Fail($m) { Write-Host "ERREUR : $m" -ForegroundColor Red; exit 1 }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail "Docker n'est pas installe. Installez Docker Desktop puis relancez." }
& docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker Desktop ne repond pas. Demarrez-le, attendez qu'il soit pret, puis relancez." }

$repo = Split-Path $PSScriptRoot -Parent
if (-not (Test-Path (Join-Path $repo 'appliance\etc\update-pubkey.pem'))) {
    Fail "appliance\etc\update-pubkey.pem est absent : generez la cle (tools/gen-signing-key.sh), commitez la cle publique, puis relancez."
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = (Resolve-Path $OutDir).Path

$mounts = @('-v', "${repo}:/src:ro", '-v', "${out}:/out")
$ca = ''
if ($CaCert) {
    if (-not (Test-Path $CaCert)) { Fail "CaCert introuvable : $CaCert" }
    Copy-Item $CaCert (Join-Path $out '.proxy-ca.pem') -Force
    $ca = 'cp /out/.proxy-ca.pem /usr/local/share/ca-certificates/proxy-ca.crt && update-ca-certificates >/dev/null && '
}

# Le depot Windows peut avoir des fins de ligne CRLF : copie de travail normalisee en LF dans le conteneur.
$inner = @'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates git xorriso gnupg curl dpkg-dev python3 openssl >/dev/null
__CA__
mkdir -p /work && cd /src && tar --exclude=./.git --exclude=./dist --exclude=./.iso-cache -cf - . | tar -xf - -C /work
cd /work
grep -rIl $'\r' . 2>/dev/null | xargs -r sed -i 's/\r$//'
chmod +x tools/*.sh tools/*.py
mkdir -p /out/.iso-cache
ISO_CACHE=/out/.iso-cache tools/build-iso.sh --output /out/spambuntu-amd64.iso
VERSION=$(tr -d '[:space:]' < VERSION)
mv -f /out/spambuntu-amd64.iso "/out/spambuntu-$VERSION-amd64.iso"
(cd /out && sha256sum "spambuntu-$VERSION-amd64.iso" | tee "spambuntu-$VERSION-amd64.iso.sha256")
rm -f /out/spambuntu-amd64.iso.sha256 /out/.proxy-ca.pem
'@
$inner = $inner.Replace('__CA__', $ca).Replace("`r", '')

Write-Host "Construction de l'ISO dans Docker (ubuntu:24.04)..." -ForegroundColor Cyan
& docker run --rm @mounts ubuntu:24.04 bash -c $inner
if ($LASTEXITCODE -ne 0) { Fail "la construction a echoue (voir ci-dessus)." }
Write-Host "Termine. ISO dans : $out" -ForegroundColor Green
Get-ChildItem $out -Filter 'spambuntu-*-amd64.iso*' | Format-Table Name, Length -AutoSize
