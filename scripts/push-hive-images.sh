#!/usr/bin/env bash
# Push the locally built hive/clients images to Docker Hub under the
# am13lab namespace, so others can run `-env hive` without building.
#
# Prerequisites:
#   1. local images built (scripts/build-hive-images.sh)
#   2. docker login  (namespace am13lab)
#
# docker run resolves these automatically for the default
# -hive-image-repo docker.io/am13lab.
set -euo pipefail

NS="${NS:-am13lab}"
clients=(lighthouse teku prysm nimbus lodestar grandine)

push() { # push <local-image> <name:tag>
  echo "==> $NS/$2"
  docker tag "$1" "$NS/$2"
  docker push "$NS/$2"
}

push hive/clients/go-ethereum "go-ethereum:latest"
for c in "${clients[@]}"; do
  push "hive/clients/$c-bn:local" "$c-bn:local"
  # grandine has no upstream VC; its BN is driven by the lighthouse VC.
  [ "$c" = "grandine" ] || push "hive/clients/$c-vc:local" "$c-vc:local"
done

echo "==> done. others now auto-pull these via -hive-image-repo docker.io/$NS (the default)."
