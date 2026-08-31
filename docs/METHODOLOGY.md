# Methodology

How Parallax generates its test cases, classifies verdicts, and how to
extend the suite. Architecture contracts live in DESIGN.md; this document is
the testing playbook.

## 1. Differential testing principle

Every case sends the same protocol input to all clients on one shared chain
(same genesis, same fork digest) and compares the verdicts. A divergence is
not automatically a bug in one client; it means the clients disagree, and at
most one side can match the consensus spec. Each divergence records which
clients deviated (outliers) and which spec rules the input touches, so triage
starts from the spec, not from the diff itself.

The unit of comparison is the verdict class, not the raw bytes:

- accept: a success chunk (result code 0x00) came back
- reject: stream reset, a protocol error code (0x01/0x02/0x03), or an
  exchange that failed with no response bytes
- other: anything unclassifiable (transport errors, empty responses)

Two clients that reject with different error strings still agree at the
class level. This normalization is deliberate: it keeps rate-limit messages
and reset wording from drowning the real accept/reject splits. The full raw
outcomes stay in the divergence's ClientResults map for triage.

## 2. Divergence detection

`diverge()` in cases/cases.go groups clients by verdict class:

- one class only: the case passes, no divergence
- multiple classes: one Divergence is emitted; the minority side becomes the
  outlier set. On a 1-vs-1 tie (one acceptor, one rejector) the rejecting
  side is treated as the deviation, since spec-conformant behavior is
  normally the accepting side for valid inputs.
- severity: HIGH when the split is clean accept vs reject, LOW when an
  "other" class is involved (usually harness-side transport trouble)

Special cases with their own logic:

- reqresp.goodbye.valid maps reset to accept: the spec allows clients to
  disconnect without answering a goodbye, so a reset is compliant.
- discovery.fork_digest compares chain values, not verdict classes: same
  chain clients must report the same fork digest; any mismatch is a
  CONSENSUS_VALUE_MISMATCH divergence.
- gossip cases use a weaker oracle (next section).

## 3. Verdict observation for gossip

Req/resp verdicts come from the response wire bytes. Gossip has no response,
so acceptance is observed indirectly: the client publishes the message and a
second libp2p host (the observer), connected only to the target, watches for
re-propagation. A re-propagated message is a strong accept signal. Silence
is a weak negative: reject, ignore, or a gossipsub mesh that never formed
all look identical. Cases and triage must treat gossip rejections as
suspect until confirmed from client logs.

## 4. Case anatomy

A case is a plain runner.Spec value, no registration magic:

```go
{
    ID:       "reqresp.ping.empty_body",   // stable, dotted, unique
    Category: "reqresp",                   // reqresp|gossip|discovery|transport
    Metadata: runner.Metadata{
        SpecRules: []string{"reqresp:ping"},  // spec anchors for triage
        RunClass:  runner.RunClassStandard,   // standard|heavy|config
        MinClients: 0,                        // 0 defaults to floor 2
    },
    Preflight: nil,  // optional: prove the case is meaningful first
    Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
        results := map[string]string{}
        for _, c := range te.Clients {
            res, err := c.ReqResp(ctx, pingV1, wire.BuildSSZSnappy(nil), 5*time.Second)
            results[c.Name()] = outcome(res, err)
        }
        return diverge("reqresp.ping.empty_body", "reqresp", te.Meta, results)
    },
}
```

Rules the model enforces:

- chain-dependent values (fork digest, gossip topic, genesis root) come from
  te.Chain, never hardcoded; gossip topics are built with the digest from
  the environment, so the same case runs on any fork or preset
- per-client state (chain state for Status bodies and context bytes) comes
  from c.State(ctx); cases needing it declare a Preflight that skips cleanly
  when a client has no beacon API
- cases must be deterministic given TestEnv.RNG, so a seed reproduces a run
- cases restore client state they mutate (pre_status reconnects with a
  handshake) because the runner executes everything sequentially against
  the same targets

## 5. How the seed set was generated

Each seed case follows the same construction loop:

1. Pick a spec rule with differential potential: rules that clients could
   plausibly interpret differently (framing strictness, pre-handshake
   serving, unknown protocol handling, allocation before validation).
2. Build the input with the wire package helpers (valid frame, malformed
   variants, length bombs, trailing bytes) so the bytes match the encoding
   rules exactly except for the single property under test.
3. Define the conformant verdict class from the spec text.
4. Prove the case logic in both directions against testnode: a convergent
   run (all fake nodes behave the same, expect zero divergences) and a
   divergent run (one fake node deviates, expect exactly one divergence
   with the right outlier).
5. Anchor the case with SpecRules and register it in the cases package.

The two-directional testnode validation is the core stability trick: a case
that cannot produce a divergence against a scripted deviant node is broken,
and so is a case that reports divergence against identical nodes.

## 6. Migration status

Batch 1 (done) ported the status family and the discovery ENR families
(25 cases) with two capability additions: NodeState now carries the raw
ENR string, and clients expose beacon node metadata. Batch 2 (done)
parameterized the reqresp boundary/malformed/trailing/length-bomb
families across protocols as table-driven constructors (38 cases).
Batch 3 (done) ported the transporttest, exhaustion, gossip and Gloas
protocol families (40 cases, heavy and config classes marked honestly;
discv5-dependent and peer-score introspection cases are documented
skips). Batch 4 (done) ported the generative subsystems as deterministic
generators producing Spec values: a cryptomsg sweep (81), seeded
statemachine sequences (30), and semantic conformance checks (8). The
registry now holds 237 cases. Remaining known gaps, deferred with
reasons: discv5 raw UDP discovery cases, peer-score introspection, proxy
colocation floods, and the old statemachine engine's full profile
system (the trimmed sequence generator covers the concept).

## 6a. How to add a test

Worked recipe, using a hypothetical req/resp boundary case:

1. Reuse or add protocol constants in cases/reqresp.go:

```go
const attesterSlashingV2 = "/eth2/beacon_chain/req/attester_slashing/2/ssz_snappy"
```

2. Write the case spec and append it to reqrespSpecs():

```go
{
    ID:       "reqresp.attester_slashing.empty_body",
    Category: "reqresp",
    Metadata: runner.Metadata{SpecRules: []string{"reqresp:attester-slashing"}},
    Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
        results := map[string]string{}
        for _, c := range te.Clients {
            res, err := c.ReqResp(ctx, attesterSlashingV2, wire.BuildSSZSnappy(nil), reqTimeout)
            results[c.Name()] = outcome(res, err)
        }
        return diverge("reqresp.attester_slashing.empty_body", "reqresp", te.Meta, results)
    },
},
```

3. Test it in cases/cases_test.go, both directions, with scripted testnode
   behaviors (see the existing cases there):

```go
func TestAttesterSlashingEmptyBody(t *testing.T) {
    t.Run("converge", func(t *testing.T) {
        h := start(t, 2, map[string][]*testnode.Script{
            attesterSlashingV2: {okRead(), okRead()},
        }, nil, nil)
        spec, _ := cases.ByID("reqresp.attester_slashing.empty_body")
        if divs := spec.Run(context.Background(), h.env()); len(divs) != 0 {
            t.Fatalf("identical nodes must converge: %+v", divs)
        }
    })
    t.Run("diverge", func(t *testing.T) {
        h := start(t, 2, map[string][]*testnode.Script{
            attesterSlashingV2: {okRead(), resetRead()},
        }, nil, nil)
        spec, _ := cases.ByID("reqresp.attester_slashing.empty_body")
        divs := spec.Run(context.Background(), h.env())
        if len(divs) != 1 || divs[0].OutlierClients[0] != "B" {
            t.Fatalf("deviant node must be the outlier: %+v", divs)
        }
    })
}
```

4. `go test ./cases/` must be green, then commit. The case automatically
   appears in `parallax list` and every subsequent run.

Checklist for a good case: single property under test, spec rule anchor,
deterministic input, preflight when chain state is needed, convergent plus
divergent testnode proof, no cross-test state leakage.

## 7. The test pyramid

- wire: pure-function unit tests, spec-derived vectors, round trips and
  negative cases. No networking.
- testnode + probe + beacon: protocol behavior against an in-process fake
  CL node over real localhost TCP.
- cases: every case proven convergent and divergent against scripted nodes.
- runner: scheduling, selection, ban and recovery semantics against fake
  clients.
- e2e + cmd: the whole engine produces valid reports end to end.
- live runs (static / kurtosis / hive): the same specs against real
  clients; this is where divergences become findings.

## 8. Running

```bash
go run ./cmd/parallax list                 # case registry
go run ./cmd/parallax run --env static --config clients.yaml
go run ./cmd/parallax analyze --report results/report.json --allowlist known.json

# simulation: full seed set against scripted fake nodes, real artifacts
go run ./cmd/simulation --out results/demo
```

The simulation command is the fastest way to see the pipeline produce a
report and junit.xml without any devnet.

## 9. Where tests come from (discovery sources)

Every case should trace to one of six sources; the Metadata.KnowledgeIDs
field records which. This is how the original suite was built and how new
tests should be found.

1. Spec prose mining. The p2p-interface specs and EIPs are full of MUST,
   MUST NOT and SHOULD sentences. The previous repo parsed them into
   structured rule artifacts (ast/rule_ast.json,
   spec_rules_generated.json) and hashed each sentence into a stable
   anchor (the PROSE-MUST-* knowledge IDs). Each rule with differential
   potential, meaning clients could plausibly disagree about it, becomes
   a case. Workflow: grep the spec section for normative verbs, check the
   rule against the coverage matrix, write the case, anchor it.

2. New forks and EIPs (the highest-yield source). A new hardfork is a
   test-case generator if you know the matrix: every new req/resp
   protocol automatically gets the standard sweep (valid, empty body,
   zero count, over-max count, seven malformations, trailing bytes,
   length bombs, pre-fork handling); every new gossip topic gets the
   gossip family; every new ENR field gets the discovery family; every
   new validation rule gets a semantic check; every fork boundary gets
   pre/post-transition cases. The Gloas execution-payload family and the
   Fulu data-column families were produced exactly this way. When the
   next fork ships, port its protocol IDs into the batch-2 constructor
   tables and the matrix generates itself.

3. Audit report mining. Findings from public audits of ANY implementation
   transfer across clients because the bug patterns do (missing
   timeouts, unbounded allocation before validation, encoding edge
   cases, discovery manipulation, replay). The previous repo built
   docs/knowledge/audit-findings-p2p-reference.md from Sigma Prime's
   public-audits repository, mapping Reth, Forest, Gossamer, Charon and
   Drand findings onto CL test cases (the RETH-* knowledge IDs). Same
   for audit contest findings (the SHERLOCK-1140-* IDs). Workflow: read
   the P2P sections of new audit reports, for each finding ask "do all
   six clients check this?", and turn the unchecked variant into a case.

4. Client advisories and incidents. Security advisories and post-mortems
   (the CL-2020-01, CL-2022-06 style IDs) describe real crashes and
   DoSes. Each one generalizes into at least one regression case: the
   triggering input becomes the payload, the advisory's fix becomes the
   expected verdict.

5. Divergence feedback. Every triaged divergence from a live run feeds
   back as a permanent seed: the triggering payload enters the corpus,
   mutations of it become generated variants, and the known-divergences
   allowlist records it. Regression coverage compounds this way.

6. Client source review. When one client adds a new check, limit or
   protocol handling in its p2p code, that is a hypothesis that the
   other five lack it. Reading client changelogs and p2p handler diffs
   is a targeted way to find exactly these asymmetries.

Priority order for new work: fork/EIP matrices first (mechanical, high
yield), then audit mining (targeted), then spec prose mining (exhaustive
but slower), then divergence feedback (continuous).
