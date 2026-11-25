#!/usr/bin/env bash
# Install a set of solc versions into the solc-select artefact store so Slither
# can select the right compiler per contract offline.
set -euo pipefail

VERSIONS="${SOLC_VERSIONS:-0.4.26 0.5.17 0.6.12 0.8.19}"
ART="${HOME}/.solc-select/artifacts"
mkdir -p "$ART"

for v in $VERSIONS; do
  d="$ART/solc-$v"
  mkdir -p "$d"
  echo "Downloading solc $v ..."
  wget -q -O "$d/solc-$v" \
    "https://github.com/ethereum/solidity/releases/download/v$v/solc-static-linux"
  chmod +x "$d/solc-$v"
done

# default global version + a solc on PATH
echo "0.8.19" > "${HOME}/.solc-select/global-version"
ln -sf "$ART/solc-0.8.19/solc-0.8.19" /usr/local/bin/solc
solc --version
