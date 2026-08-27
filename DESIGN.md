# libp2p-difftest Design

Status: draft v1
This document is the architectural contract for the rewrite. The implementation
must match it; changes to it are design decisions and get their own commits.

## 1. Goals

1. Differential testing of Ethereum CL libp2p behavior across the six clients
   (prysm, lighthouse, teku, nimbus, lodestar, grandine) with results anchored
   to consensus-spec rules.
2. One core testing engine, three interchangeable front-ends:
   - static: attach to already-running beacon nodes from a YAML endpoint list.
   - kurtosis: provision a devnet via ethpandaops/ethereum-package, then test.
   - hive: run as an ethereum/hive simulator.
3. Stable by construction: every layer testable without a live devnet, through
   an in-process fake beacon node and fake backend servers.
4. Consumable output: versioned JSON report plus JUnit XML for CI.

## 2. Non-goals (for this rewrite)

- Porting every test case from the previous p2p-testing repo. The framework
  ships a seed set (section 8); the rest are incremental ports.
- State machine sequences, replay corpora, mutation and evolutionary loops.
  These build on the same Spec model later; they are not in v1.
- LLM log oracles. Log collection is pluggable; rule-based or LLM analysis is
  future work.
- Gossipsub/scoring-specific devnet configurations beyond what the seed cases
  need.

## 3. Lessons from the previous implementation

- Parsing human-readable `kurtosis enclave inspect` output (genconfig) was the
  single most fragile piece. The kurtosis backend must use the Go API.
- Tests self-registering via init() side effects made the runner impossible to
  embed elsewhere. Test sets must be explicit values, constructed on demand.
- Optional interfaces (MetadataProvider, PreflightProvider,
  SpecRuleAnnotated, MinimumClientsProvider) scattered behavior across type
  assertions. A single Spec struct replaces all of them.
- The libp2p probe stack is battle-tested against all six clients and must be
  carried over nearly verbatim: secp256k1 identity (Nimbus rejects Ed25519 in
  Noise), noise security, yamux plus mplex muxers, tcp transport.
- Kurtosis-only log collection (shelling out to `kurtosis service logs`)
  leaked backend details into the core. Log access belongs to the environment
  abstraction.

## 4. Package layout

```
cmd/difftest      CLI: list, run, analyze subcommands (stdlib flag only)
wire              pure functions: varint, snappy framing, SSZ-snappy req/resp
                  build/parse, malformed payload builders, crc32c, fork digest
probe             libp2p probe host: connect, identity rotation, req/resp
                  send, status responder, gossip publish, gossip observe
beacon            beacon API client: node identity, head/fork state, health,
                  metrics snapshot
client            Client implementation gluing probe + beacon, proxy rotation
runner            Spec model, scheduling, preflight, ban handling, divergence
                  collection, report assembly
report            report schema v1, JSON writer, JUnit writer, findings dedup
env               Endpoint, Environment, Provider interfaces
env/staticenv     attach-only backend from YAML (previous config format)
env/kurtosisenv   kurtosis Go API backend: provision via ethereum-package,
                  service/port enumeration, log retrieval
cases             explicit test suites (no init registration)
cases/reqresp     seed req/resp cases
cases/gossip      seed gossip cases
cases/discovery   seed discovery cases
cases/transport   seed transport cases
testnode          in-process fake beacon node (libp2p host + HTTP beacon API),
                  the corner stone of the test suite
hive-sim          separate Go module: ethereum/hive simulator adapter
```

Dependency rule: nothing below (wire, probe, beacon, env) imports anything
above (client, runner, cases, cmd). The hive-sim module imports the core via a
replace directive so the hivesim dependency never reaches the core module.

## 5. Core interfaces

### 5.1 Environment

```go
package env

type Endpoint struct {
    Name       string // display name, e.g. "prysm-1"
    ClientType string // normalized type, e.g. "prysm"
    Multiaddr  string // libp2p reachable address with peer ID
    BeaconAPI  string // http URL, may be empty
    Service    string // backend-specific identifier, used for Logs()
}

type Environment interface {
    Endpoints() []Endpoint
    // Logs returns the service log stream since the given time. Returns
    // ErrLogsUnsupported when the backend cannot provide logs; the runner
    // treats that as a normal capability gap, never an error condition.
    Logs(ctx context.Context, ep Endpoint, since time.Time) (io.ReadCloser, error)
    // Info describes the environment for the report fingerprint:
    // provider name, client images and versions, fork digest, config path.
    Info() map[string]string
    // Teardown releases the environment. staticenv does nothing.
    Teardown(ctx context.Context) error
}

type Provider interface {
    Name() string
    // Setup attaches to or provisions an environment, depending on backend
    // semantics (static attaches, kurtosis provisions unless told to attach).
    Setup(ctx context.Context, cfg any) (Environment, error)
}
```

### 5.2 Test model

```go
package runner

type Spec struct {
    ID       string // stable, dotted, e.g. "reqresp.ping.empty_body"
    Category string // "reqresp", "gossip", "discovery", "transport"
    Metadata Metadata
    // Preflight proves the test is meaningful on the current environment
    // before it consumes a scheduling slot. Nil means always runnable.
    Preflight func(ctx context.Context, cs []Client) PreflightResult
    Run       func(ctx context.Context, te TestEnv) []Divergence
}

type Metadata struct {
    SpecRules  []string // consensus-spec rule anchors
    RunClass   RunClass // standard | heavy | config
    LogSensitive bool
    MinClients int      // default 2; 1 for single-client checks
}

type TestEnv struct {
    Clients []Client // filtered to MinClients by the runner
    RNG     *rand.Rand
    Log     *slog.Logger
}
```

Spec is a plain struct of functions: cheap to construct, trivial to fake in
tests, serializable into manifests later. Test suites are explicit:

```go
package cases

func All() []runner.Spec
func ByID(id string) (runner.Spec, bool)
func ByCategory(cat string) []runner.Spec
```

### 5.3 Client

```go
package runner

type Client interface {
    Name() string
    Type() string
    // ReqResp sends one request on a req/resp protocol and reads the full
    // response (all chunks) within the timeout.
    ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*ReqRespResult, error)
    PublishGossip(ctx context.Context, topic string, data []byte) error
    // EnsureConnected re-establishes the libp2p connection when needed.
    EnsureConnected(ctx context.Context) error
    // RotateIdentity replaces the probe identity (new peer ID, fresh limiter
    // and ban state on the target).
    RotateIdentity(ctx context.Context) error
    Snapshot(ctx context.Context) (*ResourceSnapshot, error)
    Close() error
}
```

### 5.4 Runner and report

```go
package runner

type Options struct {
    Seed           int64
    TestIDs        []string // exact selection, bypasses run-class filtering
    Categories     []string
    IncludeHeavy   bool
    IncludeConfig  bool
    InterTestDelay time.Duration
    MaxDuration    time.Duration // 0 = run the selection once
    BanThreshold   int           // consecutive connect failures before exclusion
    RotateEvery    int           // identity rotation cadence, 0 disables
    PerTestTimeout time.Duration
}

func Run(ctx context.Context, specs []Spec, clients []Client, opts Options, sinks ...Sink) *Report
```

The runner is sequential by design: tests mutate target state (rate limit
buckets, peer scores, connection counts), so parallelism would create
cross-test contamination. Determinism comes from the seed: selection order is
a seeded shuffle of the filtered list.

Report schema v1 (see report/schema.go):

```go
type Report struct {
    SchemaVersion int
    StartedAt, EndedAt time.Time
    Seed int64
    Environment map[string]string
    Results []TestResult
    Summary Summary
}
type TestResult struct {
    TestID, Category string
    Status  Status // pass | divergent | skipped | error
    Divergences []Divergence
    Elapsed time.Duration
}
```

Divergence and Finding types carry the previous repo's semantics (types,
severity, outlier clients, allowlist suppression) with the same JSON field
names so existing triage tooling keeps working.

JUnit mapping: pass → testcase, divergent → failure (one per divergence,
root cause in the message), skipped → skipped, error → failure with error
marker. A run maps to one testsuite per category.

## 6. Environment backends

### 6.1 staticenv

Reads the previous repo's clients.yaml format unchanged:

```yaml
clients:
  - name: prysm-1
    client_type: prysm
    multiaddr: /ip4/127.0.0.1/tcp/46562/p2p/16Uiu2HAm...
    beacon_api: http://127.0.0.1:45554
```

Setup validates that multiaddrs parse and pings BeaconAPI endpoints when
present. Logs returns ErrLogsUnsupported. Teardown is a no-op. This preserves
every existing genconfig artifact and PoC workflow.

### 6.2 kurtosisenv

Two modes selected by CLI flags, one backend:

- provision: run ethereum-package through the kurtosis Go API
  (`kurtosis-context.RunPackage`) with the user's args file and enclave name.
- attach: connect to an existing enclave.

Discovery replaces genconfig entirely: enumerate services via the API, map
each CL service's port bindings (tcp discovery port, http port), fetch the
peer ID from the service's Beacon API `/eth/v1/node/identity`, and emit
Endpoints. Client type is derived from the service name.

Logs use the API's service-log retrieval. The entire kurtosis API surface is
hidden behind a narrow interface (`type apiClient interface`) so the mapping
logic is unit-tested against fakes without kurtosis installed.

### 6.3 hive-sim

A separate module at ./hive-sim that imports the core. Mapping:

- One hivesim test case per difftest category. Inside each test case the
  simulator starts one node per configured CL client type with identical
  genesis files and env (differential testing needs same-chain peers), waits
  for them to become healthy, then calls runner.Run with the category's
  specs.
- Result mapping: divergent → hive test failure with per-divergence detail in
  the details field; pass → pass. The full JSON report is attached to the
  test details.
- Client logs remain hive's responsibility (workspace logs). Log-sensitive
  analysis happens post-run, outside the simulator, in v1.

The simulator is validated against a fake hive API server (httptest) in unit
tests; a real `./hive --sim` run is manual validation at the end.

## 7. Test strategy (TDD)

Every package lands with tests first, in the same commit as the code when the
cycle is small, or as test commit followed by implementation commit when it is
not. The rule: no behavior merges without a failing test that it makes pass.

- wire: table-driven tests plus spec-derived vectors. Round-trip properties
  (build then parse returns input) and negative cases (length bombs, trailing
  bytes, truncated frames). No libp2p involved.
- probe: tested against testnode over real TCP within localhost. Cover
  connect, req/resp success and stream-reset, identity rotation producing a
  new peer ID, gossip publish delivery.
- testnode: a scriptable fake CL node. A go-libp2p host serving the eth2
  req/resp protocols (configurable responses per protocol: success, error
  code, reset, timeout, garbage) plus a pubsub gossip topic sink, plus an
  httptest beacon API serving canned /eth/v1/node/identity, headers, fork,
  metrics. Every higher layer's tests script this node instead of a devnet.
- beacon: httptest-driven tests for state parsing and metric extraction.
- client: probe + beacon glue, proxy rotation order, ban-counting behavior.
- runner: fake Spec and fake Client implementations. Cover selection and
  seeded ordering (same seed, same order), preflight skipping, ban exclusion
  and recovery, deadline stop, delay scheduling, report assembly.
- report: golden-file JSON and JUnit output tests; dedup and allowlist tests.
- env/staticenv: YAML load/validate tests.
- env/kurtosisenv: mapping tests against a fake apiClient (service list,
  port bindings, peer ID fetch); no kurtosis binary needed.
- cmd: subcommand wiring tests, plus one end-to-end smoke: staticenv with two
  testnodes, run the seed suite, assert report shape and JUnit output.
- hive-sim: suite construction and result mapping against a fake hive API.

## 8. Seed test set (v1 scope)

reqresp (port and harden from the previous repo):
- reqresp.status.valid: valid Status request returns success chunk.
- reqresp.ping.empty_body: zero-length ping, clients must respond or reset;
  divergence if verdicts differ.
- reqresp.ping.extra_bytes: ping with trailing bytes.
- reqresp.status.malformed: corrupted SSZ payload, expect rejection.
- reqresp.status.pre_status: request before Status handshake; spec says
  clients must not serve; known to differ, anchor the rule.
- reqresp.blocks_by_root.length_bomb: claimed varint length far above actual.
- reqresp.blocks_by_root.trailing_bytes: response chunk with trailing bytes.
- reqresp.metadata.valid: valid Metadata request round-trip.
- reqresp.goodbye.valid: goodbye with rationale code.
- reqresp.unknown_protocol: request a protocol the client does not serve.

gossip:
- gossip.block.malformed: publish garbage to beacon_block topic; observe
  verdict via gossipsub observer subscription.
- gossip.block.oversize: payload above GOSSIP_MAX_SIZE.

discovery:
- discovery.enr.fields: parse each client's ENR, compare eth2/attnets fields
  for consistency with the chain state.

transport:
- transport.handshake.connect: plain noise/tcp connectability per client.
- transport.handshake.identity_rotation: rotate and reconnect, new peer ID.

## 9. Roadmap

Phase 1, core engine: wire, testnode, probe, beacon, client, runner, report.
Verification: go test ./... green, fake-node end-to-end test produces a
valid report from a three-spec mini suite.

Phase 2, environments: env interfaces, staticenv, kurtosisenv.
Verification: staticenv e2e against testnodes; kurtosisenv mapping tests
green against fakes; manual kurtosis run deferred to a live check.

Phase 3, CLI and cases: cmd/difftest list/run/analyze, seed case set.
Verification: difftest list shows the seed set; difftest run against
testnodes emits report.json and junit.xml; analyze re-processes a saved
report.

Phase 4, hive: hive-sim module with fake-API tests.
Verification: fake-API tests green; docker build of the simulator succeeds;
live hive run is a documented manual step.

## 10. Decisions and trade-offs

- Sequential execution over parallelism: stability and determinism first.
  Parallel categories are a future option only for provably isolated tests.
- Spec-as-struct over interface zoo: one obvious way to define a test;
  optional capabilities are nil function fields.
- kurtosis Go API over CLI parsing: heavier dependency, isolated inside
  env/kurtosisenv behind an interface; removes the most fragile code.
- JUnit and JSON both written by default: JSON for triage tooling, JUnit so
  any CI lights up red without custom parsing.
- Previous clients.yaml format kept: existing artifacts, PoCs and genconfig
  output remain usable, migration cost is zero.
- hive-sim as a separate Go module: keeps hivesim and its transitive
  dependencies out of the core module while sharing code through replace.
- Report JSON field names match the previous repo where concepts are the
  same, so triage scripts and the known-divergence allowlist format survive.

## 11. Open risks

- The kurtosis Go API surface moves; the thin interface confines breakage to
  one file.
- hivesim client-start semantics (per-test lifetime) may force one hive test
  case per category rather than per difftest spec; the fake-API tests pin the
  actual behavior before any live run.
- go-libp2p v0.47 behavior differences across the six clients are inherited
  from the previous stack and considered solved; any regression shows up in
  the probe tests against testnode first.
