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

## Quick start

Prerequisites: Go 1.25+. For live devnets: Docker (OrbStack or Docker
Desktop) and the kurtosis CLI (`brew install kurtosis-tech/tap/kurtosis-cli`).

1. Sanity check, no devnet needed (about 1 minute):

```bash
go run ./cmd/simulation --out results/demo
```

This runs the full case set against scripted fake nodes and writes
`results/demo/report.json` plus `results/demo/junit.xml`.

2. List what can be tested:

```bash
go run ./cmd/parallax list
```

3. Test a live devnet. Either let Parallax provision one through
   ethereum-package (one command, takes ~15 minutes for six clients):

```bash
go run ./cmd/parallax run --env kurtosis --enclave parallax-test \
    --args-file configs/live-cl0801-lite.yaml \
    --seed 42 --out results/live
```

Or attach to nodes that are already running (any devnet; the YAML is the
previous tool's clients.yaml format):

```bash
go run ./cmd/parallax run --env static --config clients.yaml \
    --seed 42 --out results/live
```

4. Triage, with known divergences suppressed:

```bash
go run ./cmd/parallax analyze --report results/live/report.json \
    --allowlist knowledge/known_divergences.json
```

Everything that survives the allowlist is a candidate finding; each
divergence carries per-client verdicts and spec rule anchors.

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
