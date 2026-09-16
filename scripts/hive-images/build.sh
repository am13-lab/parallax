#!/usr/bin/env bash
# Build the hive client images used by the `-env hive` backend.
#
# Usage:
#   scripts/hive-images/build.sh /path/to/ethereum/hive [extra docker build args]
#
# Each image builds for the host architecture by default; pass
# `--platform linux/amd64` (or arm64) to cross-build. All images are tagged
# hive/clients/<name>:local; retag/push to your own registry as needed.
#
# The go-ethereum image additionally needs the swap step (see
# patches/swap-geth.Dockerfile) because upstream Dockerfile.git clones
# github.com from inside the build.
set -euo pipefail

HIVE_REPO="${1:?usage: build.sh /path/to/ethereum/hive [extra docker build args]}"
shift || true

cd "$HIVE_REPO"

for c in teku-bn teku-vc prysm-bn prysm-vc nimbus-bn nimbus-vc lighthouse-bn lighthouse-vc; do
  echo "==> building hive/clients/${c}:local"
  docker build "$@" -t "hive/clients/${c}:local" "clients/${c}"
done

echo "==> building hive/clients/lodestar-{bn,vc}:local (pinned v1.31.0)"
for c in lodestar-bn lodestar-vc; do
  docker build "$@" --build-arg tag=v1.31.0 -t "hive/clients/${c}:local" "clients/${c}"
done

echo "==> building hive/clients/grandine-bn:local"
docker build "$@" -t hive/clients/grandine-bn:local clients/grandine-bn

echo "==> building hive/clients/go-ethereum:local (stock, baseimage override)"
docker build "$@" --build-arg baseimage=ethereum/client-go --build-arg tag=latest \
  -t hive/clients/go-ethereum:local clients/go-ethereum

HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> applying patches"
docker build "$@" -f "${HERE}/patches/lighthouse-bn.Dockerfile"  -t hive/clients/lighthouse-bn:local  "${HERE}/patches"
docker build "$@" -f "${HERE}/patches/lighthouse-vc.Dockerfile"  -t hive/clients/lighthouse-vc:local  "${HERE}/patches"
docker build "$@" -f "${HERE}/patches/lodestar-bn.Dockerfile"    -t hive/clients/lodestar-bn:local    "${HERE}/patches"
docker build "$@" -f "${HERE}/patches/lodestar-vc.Dockerfile"    -t hive/clients/lodestar-vc:local    "${HERE}/patches"
docker build "$@" -f "${HERE}/patches/grandine-bn.Dockerfile"    -t hive/clients/grandine-bn:local    "${HERE}/patches"

echo "done. 12 images tagged hive/clients/*:local"
