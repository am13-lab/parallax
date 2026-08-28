# libp2p-difftest Design

Status: v3 (implemented; deviations from v2 recorded below)
This document is the architectural contract for the rewrite. The implementation
must match it; changes to it are design decisions and get their own commits.

Review history: v1 was reviewed and revised. Fixes incorporated in v2:
gossip observation, no-Status connect and chain state added to the client
surface; TestEnv carries the Environment; MinClients redefined as a floor;
Sink replaced by an Options callback; report compatibility claim replaced by
an explicit adapter plan; proxy handling specified; env moved into Phase 1;
hive phase re-scoped with its true cost documented; KnowledgeIDs restored;
identity-rotation claim scoped; kurtosis provision marked manual-verified;
per-endpoint fingerprint fields; recovery cooldown added; chain config
introduced.

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
- LLM log oracles. Log collection is available through the Environment; rule
  or LLM based log analysis is future work and plugs in at the runner level.
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
- Gossip verdicts require a second target-facing libp2p host that subscribes
  and watches re-propagation; that capability is part of the client surface,
  not a test-side ad hoc construct.

## 4. Package layout

```
cmd/difftest      CLI: list, run, analyze subcommands (stdlib flag only)
wire              pure functions: varint, snappy framing, SSZ-snappy req/resp
                  build/parse, malformed payload builders, crc32c, fork digest
probe             libp2p probe host: connect (with/without Status handshake),
                  identity rotation, req/resp send, status responder, gossip
                  publish, gossip observe
beacon            beacon API client: node identity, head/fork state, health,
                  metrics snapshot
client            Client implementation gluing probe + beacon + proxies
runner            Spec model, scheduling, preflight, ban handling, divergence
                  collection, report assembly, chain config
report            report schema v1, JSON writer, JUnit writer, findings dedup,
                  allowlist suppression, legacy-shape adapter
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
    Name       string   // display name, e.g. "prysm-1"
    ClientType string   // normalized type, e.g. "prysm"
    Multiaddr  string   // libp2p reachable address with peer ID
    BeaconAPI  string   // http URL, may be empty
    Service    string   // backend-specific identifier, used for Logs()
    Proxies    []string // alternate multiaddrs (socat forwarders) for identity
                        // rotation; empty means rotation reuses the direct addr
    Image      string   // optional, backend-provided fingerprint data
    Version    string   // optional, backend-provided fingerprint data
}

type Environment interface {
    Endpoints() []Endpoint
    // Logs returns the service log stream since the given time. Returns
    // ErrLogsUnsupported when the backend cannot provide logs; the runner
    // treats that as a normal capability gap, never an error condition.
    Logs(ctx context.Context, ep Endpoint, since time.Time) (io.ReadCloser, error)
    // Info describes the environment for the report fingerprint: provider
    // name, config path, preset. Per-endpoint image/version data lives on
    // the Endpoint, so one accessor covers both granularities.
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
    KnowledgeIDs []string // knowledge-base traceability
    SpecRules    []string // consensus-spec rule anchors
    RunClass     RunClass // standard | heavy | config
    LogSensitive bool
    // MinClients is a floor, not a target: the runner skips the test when
    // fewer clients are usable and passes all usable clients otherwise.
    MinClients int // default 2; 1 for single-client checks
}

type TestEnv struct {
    Clients []Client // all usable clients, at least Metadata.MinClients
    Env     env.Environment
    Chain   ChainConfig
    RNG     *rand.Rand
    Log     *slog.Logger
}

// ChainConfig carries everything fork- and preset-dependent that cases and
// the testnode need: preset name, fork digest, genesis validators root,
// active fork version, GOSSIP_MAX_SIZE, MAX_CHUNK_SIZE. It is provided by
// the CLI (--preset, default mainnet) or derived from the first client with
// a Beacon API, and cases must not hardcode these values.
type ChainConfig struct {
    Preset               string
    ForkDigest           [4]byte
    GenesisForkVersion   [4]byte
    GenesisValidatorsRoot [32]byte
    GossipMaxSize        uint64
    MaxChunkSize         uint64
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

type ConnectMode int

const (
    ConnectWithStatus ConnectMode = iota // handshake after connect (default)
    ConnectNoStatus                      // connect only; for pre-Status cases
)

type Client interface {
    Name() string
    Type() string

    // ReqResp sends one request on a req/resp protocol and reads the full
    // response (all chunks) within the timeout.
    ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*ReqRespResult, error)

    // PublishGossip publishes data on a gossip topic.
    PublishGossip(ctx context.Context, topic string, data []byte) error

    // ObserveGossip subscribes via a second target-facing libp2p host and
    // waits for the published message to re-propagate, returning the local
    // acceptance verdict (accept/reject/ignore/timeout).
    ObserveGossip(ctx context.Context, topic string, wait time.Duration) (GossipVerdict, error)

    // Connect (re-)establishes the libp2p connection in the given mode.
    Connect(ctx context.Context, mode ConnectMode) error
    // RotateIdentity replaces the probe identity. This yields a fresh
    // peer-ID-keyed state on the target (req/resp limiters, bad-response
    // scores); IP-keyed bans on some clients intentionally survive it.
    RotateIdentity(ctx context.Context) error

    // State returns chain state fetched from the Beacon API: head slot and
    // root, active fork, fork digest, finalized checkpoint. Cases use it for
    // request bodies and context bytes. ErrNoBeaconAPI when unavailable.
    State(ctx context.Context) (*NodeState, error)
    Snapshot(ctx context.Context) (*ResourceSnapshot, error)
    Close() error
}
```

### 5.4 Runner and report

```go
package runner

type Options struct {
    Seed             int64
    TestIDs          []string // exact selection, bypasses run-class filtering
    Categories       []string
    IncludeHeavy     bool
    IncludeConfig    bool
    InterTestDelay   time.Duration
    MaxDuration      time.Duration // 0 = run the selection once
    BanThreshold     int           // consecutive connect failures before exclusion
    RecoveryCooldown time.Duration // banned clients are re-probed after this; 0 disables
    RotateEvery      int           // identity rotation cadence, 0 disables
    PerTestTimeout   time.Duration
    // Progress is invoked after each test completes; nil is valid.
    Progress func(TestResult)
}

// Run executes the selection sequentially and returns the assembled report.
func Run(ctx context.Context, specs []Spec, clients []Client, env env.Environment,
    chain ChainConfig, opts Options) *Report
```

The runner is sequential by design: tests mutate target state (rate limit
buckets, peer scores, connection counts), so parallelism would create
cross-test contamination. Determinism comes from the seed: selection order is
a seeded shuffle of the filtered list.

Ban handling: a client whose connection fails BanThreshold times consecutively
is excluded from comparison for subsequent tests (recorded per result as
ExcludedClients, mirroring the previous DivergenceReport field). After
RecoveryCooldown the runner re-probes and reinstates on success.

Report schema v1 (report/schema.go):

```go
type Report struct {
    SchemaVersion int
    StartedAt, EndedAt time.Time
    Seed int64
    Environment map[string]string      // provider, preset, config path
    Endpoints   []EndpointFingerprint  // name, image, version, client type
    Results []TestResult
    Summary Summary
}
type TestResult struct {
    TestID, Category string
    Status  Status // pass | divergent | skipped | error
    SkipReason string // set when Status == skipped (preflight, min clients)
    ExcludedClients []string
    Divergences []Divergence
    Elapsed time.Duration
}
```

Divergence and Finding types carry the previous repo's semantics (types,
severity, outlier clients, allowlist suppression) with the same field
semantics. The canonical output shape is new (Results-nested); triage
compatibility is an explicit adapter: `analyze --legacy` re-emits the
previous repo's top-level report shape ({timestamp, divergences[], findings[],
run_summary}) from a saved v1 report. Porting triage scripts wholesale is not
free and is not claimed to be.

Allowlist suppression lives in the report package: findings matched by the
known-divergences format (transition or test-pattern glob, client, optional
spec-rule id) are marked Suppressed with a reason, not dropped.

JUnit mapping: pass → testcase, divergent → failure (one per divergence,
root cause in the message), skipped → skipped, error → failure with error
marker. A run maps to one testsuite per category.

## 6. Environment backends

### 6.1 staticenv

Reads the previous repo's clients.yaml format unchanged, including the
optional proxy_addrs field (mapped to Endpoint.Proxies):

```yaml
clients:
  - name: prysm-1
    client_type: prysm
    multiaddr: /ip4/127.0.0.1/tcp/46562/p2p/16Uiu2HAm...
    beacon_api: http://127.0.0.1:45554
    proxy_addrs: []            # optional
```

Setup validates that multiaddrs parse and pings BeaconAPI endpoints when
present. Logs returns ErrLogsUnsupported. Teardown is a no-op. This preserves
every existing genconfig artifact and PoC workflow. Note the stated
limitation: with an empty BeaconAPI the client cannot supply chain state, so
fork-digest-dependent cases preflight-skip; this is reported, never guessed.

### 6.2 kurtosisenv

Two modes selected by CLI flags, one backend:

- provision: run ethereum-package through the kurtosis Go API
  (`kurtosis-context.RunPackage`) with the user's args file and enclave name.
  This path is covered by interface fakes only and marked manual-verified; a
  live kurtosis run is the acceptance step when one is available.
- attach: connect to an existing enclave.

Discovery replaces genconfig entirely: enumerate services via the API, map
each CL service's port bindings (tcp discovery port, http port), fetch the
peer ID from the service's Beacon API `/eth/v1/node/identity`, and emit
Endpoints. Client type is derived from the ethereum-package service name; the
derivation rules are pinned in the fake tests so upstream naming changes fail
a test instead of silently producing wrong client types.

Logs use the API's service-log retrieval. The entire kurtosis API surface is
hidden behind a narrow interface (`type apiClient interface`) so the mapping
logic is unit-tested against fakes without kurtosis installed.

### 6.3 hive-sim

A separate module at ./hive-sim that imports the core. V1 scope, stated
honestly: the simulator module delivers suite construction and result
mapping, tested against a fake hive API server (httptest) that implements the
subset of the simulation API hivesim uses (suites, tests, node start, test
end). The heavy lift of a production-ready simulator is genesis and bootnode
provisioning in hive's HIVE_* conventions for six CL clients plus reachable
container networking, and it depends on hive carrying CL client definitions
(ethpandaops fork). That work is explicitly out of v1 and documented as its
own plan; the fake-API tests pin the interaction patterns so the later
provisioning work slots into a tested harness.

Mapping within scope: one hive test case per difftest category; inside it the
simulator starts one node per configured CL client type, waits for health,
runs runner.Run, and maps divergent → hive failure with per-divergence
detail, pass → pass, and the full JSON report in the test details.

## 7. Test strategy (TDD)

Every package lands with tests first, in the same commit as the code when the
cycle is small, or as test commit followed by implementation commit when it is
not. The rule: no behavior merges without a failing test that it makes pass.

- wire: table-driven tests plus spec-derived vectors. Round-trip properties
  (build then parse returns input) and negative cases (length bombs, trailing
  bytes, truncated frames). No libp2p involved.
- testnode: a scriptable fake CL node. A go-libp2p host serving the eth2
  req/resp protocols (configurable responses per protocol: success, error
  code, reset, timeout, garbage) plus a pubsub gossip topic sink, plus an
  httptest beacon API serving canned /eth/v1/node/identity, headers, fork,
  metrics, using mainnet-preset canned chain data. Every higher layer's tests
  script this node instead of a devnet.
- probe: tested against testnode over real TCP within localhost. Cover
  connect with and without Status, req/resp success and stream-reset,
  identity rotation producing a new peer ID, gossip publish delivery and
  observation.
- beacon: httptest-driven tests for state parsing and metric extraction.
- client: probe + beacon glue, proxy rotation order across Endpoint.Proxies,
  ban-counting behavior.
- runner: fake Spec and fake Client implementations. Cover selection and
  seeded ordering (same seed, same order), preflight skipping, MinClients as
  a floor, ban exclusion and cooldown recovery, deadline stop, delay
  scheduling, Progress callback, report assembly.
- report: golden-file JSON and JUnit output tests; dedup, allowlist
  suppression, and legacy-adapter tests.
- env/staticenv: YAML load/validate tests (including proxy_addrs mapping).
- env/kurtosisenv: mapping tests against a fake apiClient (service list,
  port bindings, peer ID fetch, client-type derivation); no kurtosis binary
  needed.
- cmd: subcommand wiring tests, plus one end-to-end smoke: staticenv with two
  testnodes, run the seed suite, assert report shape and JUnit output.
- hive-sim: suite construction and result mapping against a fake hive API.

## 8. Test set

The v1 seed set was 14 cases. Batch 1 of the migration added the status
family (4 boundary variants plus finalized and fork mismatch, with a
still-connected ping check) and 19 discovery cases (ENR structure and
sequence properties, cross-client ENR consistency, and beacon-metadata
cross-checks), for 39 registered cases. The old repo's
discovery.enr.fork_digest_valid and discovery.consistency.fork_digest are
covered by the existing discovery.fork_digest case rather than ported
twice. Old-case knowledge IDs (SHERLOCK-*, PROSE-*) carry into
Metadata.KnowledgeIDs. Batch 2 ported the four parameterized reqresp
families (boundary, malformed, trailing bytes, length bombs) as
table-driven constructors, 38 more cases, for 77 registered cases total.
Duplicates with the seed set (status random-bytes malformation,
blocks_by_root trailing bytes and length bomb) were skipped, not double
ported. Batch 3 ported the transporttest family (corrupted frames, stalled
handshakes, identify abuse; 9 cases, heavy class where inputs degrade
target state), the exhaustion family (4 heavy cases via SendSlowly and
SendOnly), 15 gossip cases (malformed payloads, subnet OOB topics,
attestation staleness, replay, unknown topic, plus a config-class
post-Fulu topic split and a heavy invalid flood), the Gloas execution
payload boundary family (6 config cases, preflighted on the fork), data
column validation (2), rate-limit bursts (2 heavy), and custody derivation
(1) — with honest skips documented for discv5-dependent discovery cases,
peer-score introspection, and proxy colocation. Batch 4 ported the
generative subsystems as deterministic generators: a cryptomsg sweep
(81 cases: malformation x protocol x size plus varint claims), 30 seeded
statemachine sequences over a request-step alphabet, and 8 single-client
semantic conformance checks. The registry holds 237 cases (215 standard,
15 heavy, 7 config); the simulation runs the standard selection.

reqresp (port and harden from the previous repo):
- reqresp.status.valid: valid Status request returns success chunk.
- reqresp.ping.empty_body: zero-length ping, clients must respond or reset;
  divergence if verdicts differ.
- reqresp.ping.extra_bytes: ping with trailing bytes.
- reqresp.status.malformed: corrupted SSZ payload, expect rejection.
- reqresp.status.pre_status: request before Status handshake (ConnectNoStatus);
  spec says clients must not serve; known to differ, anchor the rule.
- reqresp.blocks_by_root.length_bomb: claimed varint length far above actual,
  context bytes from Client.State.
- reqresp.blocks_by_root.trailing_bytes: response chunk with trailing bytes.
- reqresp.metadata.valid: valid Metadata request round-trip.
- reqresp.goodbye.valid: goodbye with rationale code.
- reqresp.unknown_protocol: request a protocol the client does not serve.

gossip:
- gossip.block.malformed: publish garbage to beacon_block topic; verdict via
  Client.ObserveGossip.
(gossip.block.oversize was dropped: go-libp2p-pubsub caps messages at
1 MiB by default and does not expose the limit as an option, so publishing
above the cap tests our own stack, not the target. It returns once the
probe's gossipsub is configurable.)

discovery:
- discovery.fork_digest: compare each client's chain state fork digest
  (ENR eth2 preferred, beacon-derived fallback); same-chain clients must
  agree. (v2 planned raw ENR field comparison; needs a raw-ENR accessor on
  the client surface.)

transport:
- transport.handshake.connect: plain noise/tcp connectability per client.
- transport.handshake.identity_rotation: rotate and reconnect, new peer ID.

## 9. Roadmap

Phase 1, core engine: env interfaces, wire, testnode, probe, beacon, client,
runner, report.
Verification: go test ./... green, fake-node end-to-end test produces a
valid report from a three-spec mini suite.

Phase 2, kurtosis backend: env/kurtosisenv behind the fake-tested interface.
Verification: mapping tests green; provision path marked manual-verified.

Phase 3, CLI and cases: cmd/difftest list/run/analyze, seed case set.
Verification: difftest list shows the seed set; difftest run against
testnodes emits report.json and junit.xml; analyze re-processes a saved
report and emits the legacy shape on demand.

Phase 4, hive harness: hive-sim module with fake-API tests.
Verification: fake-API tests green; docker build of the simulator succeeds;
live hive runs and genesis provisioning are documented as the next plan, not
claimed as done.

## 10. Decisions and trade-offs

- Sequential execution over parallelism: stability and determinism first.
  Parallel categories are a future option only for provably isolated tests.
- Spec-as-struct over interface zoo: one obvious way to define a test;
  optional capabilities are nil function fields.
- kurtosis Go API over CLI parsing: heavier dependency, isolated inside
  env/kurtosisenv behind an interface; removes the most fragile code. The
  provision path is interface-tested only and marked manual-verified.
- JUnit and JSON both written by default: JSON for triage tooling, JUnit so
  any CI lights up red without custom parsing.
- New canonical report shape with an explicit legacy adapter: compatibility
  is provided by analyze --legacy, not by pretending the shapes are equal.
- Previous clients.yaml format kept (including proxy_addrs): existing
  artifacts, PoCs and genconfig output remain usable, migration cost is zero.
- hive-sim as a separate Go module: keeps hivesim and its transitive
  dependencies out of the core module while sharing code through replace.
- Chain config flows through ChainConfig, never hardcoded in cases: fork and
  preset dependence is explicit and the testnode serves matching canned data.
- Report JSON field semantics (types, severities, allowlist entries) match
  the previous repo where concepts are the same, so the known-divergences
  allowlist format survives.

## 11. Implementation deviations from v2 (as built)

- TestEnv carries Meta (the running spec's metadata) so cases can stamp
  divergences without closing over spec variables.
- runner.Client gained Health(ctx) as a cheap liveness check feeding the
  ban/recovery logic; Snapshot covers resources but is not a liveness probe.
- ConnectMode semantics: Connect(NoStatus) always builds a fresh unhandshaken
  connection (the pre-Status case depends on this); Connect(WithStatus)
  reuses the live connection when possible.
- The runner panics-to-error conversion reports StatusError with the panic
  captured, and a test that only skips is recorded with no elapsed time.
- env/kurtosisenv: the kurtosis API wrapper is v1.20.0-specific; per-line
  log timestamps do not exist in that API version, so Logs returns the full
  stream and callers pre-position by collecting at test boundaries.
- hive-sim: Config.SpecsFor and Config.ClientFactory are injection points
  (fake-tested); production paths use the cases registry and client.New.
- cases: outcome classes are accept / reject / other; 1-vs-1 verdict ties
  report the rejecting side as the outlier.
- run never tears the environment down automatically: on failures the
  enclave or endpoints stay alive for inspection, and teardown is always an
  explicit decision.

## 12. Open risks

- The kurtosis Go API surface moves; the thin interface confines breakage to
  one file, and the provision path stays manual-verified until a live run.
- hivesim client-start semantics (per-test lifetime) are pinned by the
  fake-API tests; production hive runs additionally need CL client
  definitions and genesis provisioning, which are explicitly out of v1.
- go-libp2p v0.47 behavior differences across the six clients are inherited
  from the previous stack and considered solved; any regression shows up in
  the probe tests against testnode first.
