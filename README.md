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

## Running tests

Two live backends share the same case set, differential engine, and report
formats. Pick one per run with `-env`:

| | `-env hive` | `-env kurtosis` |
|---|---|---|
| Orchestration | docker direct (env/hiveenv) | ethereum-package (starlark) |
| Provisioning files | generated into `<out>/gen/`, auditable | managed by ethereum-package |
| Dependencies | docker CLI only | kurtosis engine + package cache |
| Best for | fast iteration, supply-chain-visible runs | full devnet service shape |

Both paths auto-clean leftovers of the same enclave name before starting.

**Clients**: hive selects and launches them with
`-hive-clients "lighthouse,teku,prysm,nimbus,lodestar,grandine"` (any
subset). kurtosis launches whatever `participants` the args file lists
(see `configs/net-*.yaml`); `-clients` then filters who participates in
the comparison.

**Test tiers** (`-suite`, default `quick`):

| tier | cases | what | 6-client duration |
|---|---|---|---|
| `quick` | 36 | representative cases per family and input class | ~4 min |
| `standard` | 215 | hand-written families, IR-generated excluded | ~40 min |
| `full` | 628 | everything including IR-generated | ~2 h |

```bash
# quick tier against six clients on the hive path (about 4 minutes)
go run ./cmd/parallax run -env hive -enclave hivesmoke \
    -hive-clients "lighthouse,teku,prysm,nimbus,lodestar,grandine" \
    -out results/hive-quick

# standard tier via ethereum-package
go run ./cmd/parallax run -env kurtosis -enclave parallax \
    -args-file configs/net-geth6.yaml -suite standard \
    -out results/kurtosis-standard

# full tier adds the IR-generated cases; heavy families run last
go run ./cmd/parallax run -env hive -enclave hivesmoke \
    -hive-clients "lighthouse,teku,prysm,nimbus,lodestar,grandine" \
    -suite full -out results/hive-full
```

The hive path needs its provisioning generator built once:

```bash
(cd hive-sim && go build -o ../dist/hivegen ./cmd/hivegen)
```

Provisioning older than an hour is regenerated automatically (beacon
clients reject aged-out genesis states). Analyze a finished batch with:

```bash
go run ./cmd/parallax analyze --report results/hive-quick/report.json \
    --allowlist knowledge/known_divergences.json --junit-out results/hive-quick/junit.xml
```

## Commands

Regenerate the spec-derived test cases end to end (knowledge artifacts, IR
plans, and runner.Spec cases) from a consensus-specs checkout:

`specchain` drives the pipeline either one-shot or staged — each stage
leaves inspectable artifacts (`knowledge/`, generated case files):

```bash
# one-shot: every stage in order
go run ./cmd/specchain -specs /path/to/consensus-specs/specs

# staged: run one stage at a time, inspect artifacts between steps
go run ./cmd/specchain spec  -specs /path/to/consensus-specs/specs
go run ./cmd/specchain ir
go run ./cmd/specchain cases

# artifact presence and freshness per stage
go run ./cmd/specchain status
```

Each stage can also run on its own for partial regeneration:

```bash
# knowledge artifacts only
go run ./cmd/specgen -generate -specs /path/to/consensus-specs/specs

# SM-IR test plans from the knowledge artifacts
go run ./cmd/irdrive

# runner.Spec cases from the IR plans (three generate modes)
go run ./cmd/smgen -generate knowledge/ir/sm_ir_generated
go run ./cmd/smgen -generate-stateless knowledge/ir/stateless_tests_generated.json
go run ./cmd/smgen -generate-sequences knowledge/ir/sequence_tests_generated.json
```

`specgen` writes `knowledge/spec/rule_ast.json`,
`knowledge/spec/spec_rules_generated.json`, and
`knowledge/spec/protocol_model.json`. The protocol model keeps its existing
typed method definitions and refreshes protocol availability from the spec.

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
