#!/usr/bin/env bash
# Build the docker images the `-env hive` path needs. They cannot be
# pulled from a registry: they are built from the ethpandaops hive fork,
# which carries the -bn/-vc client definitions hiveenv drives.
#
# Usage: scripts/build-hive-images.sh [clients...]
#   default clients: lighthouse teku prysm nimbus lodestar grandine
#   env: HIVE_DIR overrides the hive checkout location (default ./hive,
#   cloned automatically when missing). Several GB of downloads and build
#   output; one-time cost, re-run only to refresh.
set -euo pipefail

HIVE_DIR="${HIVE_DIR:-$PWD/hive}"
clients=("$@")
if [ ${#clients[@]} -eq 0 ]; then
  clients=(lighthouse teku prysm nimbus lodestar grandine)
fi

if [ ! -d "$HIVE_DIR/clients" ]; then
  echo "==> cloning ethpandaops/hive into $HIVE_DIR"
  git clone --depth 1 https://github.com/ethpandaops/hive "$HIVE_DIR"
fi

# EL (geth). No tag suffix on purpose: env/hiveenv references
# hive/clients/go-ethereum, which docker resolves to :latest.
echo "==> building EL image (geth)"
docker build -t hive/clients/go-ethereum "$HIVE_DIR/clients/go-ethereum"

for c in "${clients[@]}"; do
  echo "==> building $c BN image"
  docker build -t "hive/clients/$c-bn:local" "$HIVE_DIR/clients/$c-bn"
  # grandine has no upstream VC definition (clients/grandine-vc does not
  # exist and grandine.sh wires no validators into the BN); its BN is
  # driven by the lighthouse VC through the standard validator API.
  if [ "$c" != "grandine" ]; then
    echo "==> building $c VC image"
    docker build -t "hive/clients/$c-vc:local" "$HIVE_DIR/clients/$c-vc"
  fi
done

echo "==> done. hive/clients images now available:"
docker images --format '{{.Repository}}:{{.Tag}}' | grep '^hive/clients/' | sort
