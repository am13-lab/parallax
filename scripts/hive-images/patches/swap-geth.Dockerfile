# go-ethereum: upstream Dockerfile.git clones github.com inside the build
# (blocked on some networks). Build geth on the host for the target arch
#   CGO_ENABLED=0 GOOS=linux GOARCH=<amd64|arm64> go build -o geth ./cmd/geth
# and swap the binary in. Both arches must come from the same checkout.
FROM hive/clients/go-ethereum:latest
COPY geth-linux-${TARGETARCH}/geth /usr/local/bin/geth
