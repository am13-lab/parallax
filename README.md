# libp2p-difftest

Differential testing of Ethereum consensus layer libp2p networking across client
implementations (Prysm, Lighthouse, Teku, Nimbus, Lodestar, Grandine).

The tool compares how CL clients behave on the same P2P protocol inputs and reports
divergences: accept vs reject mismatches, error code differences, resource anomalies,
and spec violations. Findings anchor to consensus-spec rules for triage.

## Status

Design phase. See DESIGN.md for the architecture and roadmap.

## Modes

- static: attach to already-running beacon nodes via a YAML endpoint list.
- kurtosis: deploy a devnet with ethpandaops/ethereum-package, then test it.
- hive: run as an ethereum/hive simulator.

## Usage (planned)

```bash
go run ./cmd/difftest list
go run ./cmd/difftest run --env static --config clients.yaml --category reqresp
go run ./cmd/difftest run --env kurtosis --eth-package configs/net.yaml --suite smoke
```

## License

See LICENSE (to be added).
