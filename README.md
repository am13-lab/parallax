# Parallax

Differential testing of Ethereum consensus layer libp2p networking across
client implementations (Prysm, Lighthouse, Teku, Nimbus, Lodestar, Grandine).

The tool sends the same protocol inputs to all clients on a shared chain and
reports divergences: accept versus reject mismatches, error code differences,
resource anomalies, and chain-value inconsistencies. Findings carry consensus
spec rule anchors and severity so they feed directly into triage.

## Architecture

See DESIGN.md for the full contract and docs/METHODOLOGY.md for the testing
playbook: the verdict model, how the seed cases were constructed, and a
worked recipe for adding more tests. Summary:

- one core engine: wire codecs, libp2p probe, beacon API client, client
  adapter, sequential runner, report writers (JSON plus JUnit)
- three interchangeable environments: static endpoint list, kurtosis
  (ethereum-package), and an ethereum/hive simulator
- every layer is tested without a live devnet through an in-process fake
  beacon node (testnode) and fake backend servers

## Commands

```bash
# show the case registry
go run ./cmd/parallax list

# attach to running nodes (previous tool's clients.yaml format)
go run ./cmd/parallax run --env static --config clients.yaml \
    --category reqresp --seed 42 --out results/

# provision a devnet via ethereum-package, then test it
go run ./cmd/parallax run --env kurtosis --enclave p2p-test \
    --args-file configs/net.yaml

# analyze a saved report, apply the known-divergence allowlist,
# and emit the previous tool's report shape for existing triage scripts
go run ./cmd/parallax analyze --report results/report.json \
    --allowlist known_divergences.json --legacy
```

Outputs: `results/report.json` (canonical v1 schema) and
`results/junit.xml` (CI integration).

No devnet available? Run the full seed set against scripted fake nodes to
see the pipeline produce real artifacts:

```bash
go run ./cmd/simulation --out results/demo
```

## Development

```bash
go test ./...          # full suite; no docker or devnet required
```

The hive simulator is a separate Go module (hive-sim/); its tests spin a
fake hive API server, so they also run without docker:

```bash
cd hive-sim && go test ./...
```

A live `./hive --sim` run and a kurtosis provisioning run are manual
verification steps, as recorded in DESIGN.md section 9.
