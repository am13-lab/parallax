package cases

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"parallax/runner"
)

// irharness.go — runtime support for the smgen-generated IR cases
// (spec_ir_generated.go and siblings). It bridges runner.TestEnv to the
// irContext payload builders consume and evaluates fork constraints in
// Preflight.

// irForkOrder is the consensus fork schedule used for fork-gated preflights.
var irForkOrder = []string{"phase0", "altair", "bellatrix", "capella", "deneb", "electra", "fulu", "gloas", "heze"}

func irForkRank(name string) int {
	for i, f := range irForkOrder {
		if f == name {
			return i
		}
	}
	return -1
}

// irNewContext builds an irContext from the test environment: chain facts come
// from the first client with valid state, falling back to the chain config and
// zero values (mirroring the p2p-testing executor's behavior when state is
// unavailable).
func irNewContext(te runner.TestEnv) *irContext {
	ictx := &irContext{Rng: rand.New(rand.NewSource(te.RNG.Int63()))}
	ictx.ForkDigest = te.Chain.ForkDigest
	for _, c := range te.Clients {
		st, err := c.State(context.Background())
		if err != nil || st == nil || !st.Valid {
			continue
		}
		if st.ForkDigest != ([4]byte{}) {
			ictx.ForkDigest = st.ForkDigest
		}
		ictx.Fork = st.Fork
		ictx.HeadSlot = st.HeadSlot
		ictx.HeadRoot = st.HeadRoot
		ictx.FinalizedEpoch = st.FinalizedEpoch
		ictx.FinalizedRoot = st.FinalizedRoot
		ictx.ForkVersion = st.ForkVersion
		ictx.GenesisForkVersion = st.GenesisForkVersion
		ictx.GenesisValidatorsRoot = st.GenesisValidatorRoot
		ictx.CurrentEpoch = st.HeadSlot / irSlotsPerEpoch
		break
	}
	ictx.Keys = defaultKeystore()
	if src, ok := te.Clients[0].(interface {
		LiveBeaconAPI() string
		LivePoolContains(topic string, index uint64) (contains, observable bool)
	}); ok {
		ictx.LiveBuilder = newLiveBuilderContext(src)
	}
	return ictx
}

// --- order-check / disconnect / custody shared execution helpers ---

// irOrderCheck sends a range request and validates response chunk ordering.
// The all-or-none rule applies only to the column all-or-none probe.
func irOrderCheck(ctx context.Context, client runner.Client, protocol, label string, body []byte, timeoutMs int) string {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeoutMs <= 0 {
		timeout = 30 * time.Second
	}
	res, err := client.ReqResp(ctx, protocol, body, timeout)
	if err != nil {
		return "other:" + err.Error()
	}
	if res == nil {
		return "other:nil result"
	}
	if res.StreamReset || (res.Error != "" && len(res.RawBytes) == 0) {
		return "reject"
	}
	if len(res.RawBytes) == 0 {
		// A clean zero-chunk range response is trivially ordered.
		return irOrderCorrect
	}
	return irValidateResponseOrder(protocol, res.RawBytes, strings.Contains(label, "all_or_none"))
}

// irDisconnectAndRestore force-closes the connection and immediately
// reconnects so subsequent cases on the shared client are unaffected. The
// restore step is a parallax adaptation; upstream leaves the peer down and
// relies on reconnect transitions.
func irDisconnectAndRestore(ctx context.Context, client runner.Client) string {
	if err := client.Close(); err != nil {
		return "other:" + err.Error()
	}
	if err := client.Connect(ctx, runner.ConnectNoStatus); err != nil {
		return "reconnect_failed"
	}
	return "disconnected_ok"
}

// irCustodyRequest resolves the peer's custody columns from its ENR and sends
// a DataColumnsByRange request over custody (or non-custody) columns.
func irCustodyRequest(ctx context.Context, client runner.Client, ictx *irContext, selector string) string {
	bapi := ""
	if src, ok := client.(interface{ LiveBeaconAPI() string }); ok {
		bapi = src.LiveBeaconAPI()
	}
	columns, err := irPeerCustodyColumns(bapi, selector == "non_custody")
	if err != nil {
		return "inapplicable"
	}
	if len(columns) == 0 {
		return "inapplicable"
	}
	if len(columns) > 4 {
		picked := make([]uint64, 4)
		for i := range picked {
			picked[i] = columns[ictx.Rng.Intn(len(columns))]
		}
		columns = picked
	}
	body := buildDataColumnsByRangeRequest(ictx.HeadSlot, 1, columns)
	protocol := "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
	res, err := client.ReqResp(ctx, protocol, body, 10*time.Second)
	if err != nil {
		return "other:" + err.Error()
	}
	if selector == "non_custody" {
		ictx.NonCustodyRequested++
	} else {
		ictx.CustodyColumnsRequested++
	}
	return classOf(outcome(res, err))
}

// irFullGossipTopic builds the full gossip topic from a short name and the
// context's fork digest: /eth2/<fork_digest_hex>/<name>/ssz_snappy.
func irFullGossipTopic(ictx *irContext, name string) string {
	if strings.HasPrefix(name, "/eth2/") {
		return name // already a full topic
	}
	if name == "" {
		name = "beacon_block"
	}
	return fmt.Sprintf("/eth2/%s/%s/ssz_snappy", hex.EncodeToString(ictx.ForkDigest[:]), name)
}

const irSlotsPerEpoch = 32

// irPreflightFork gates a case on the first client's active fork: runnable
// when the fork satisfies gte (>=) or membership in in. An empty gte and in
// list is always runnable. Unknown fork names (state unavailable) are treated
// as satisfying the constraint so chain-state hiccups do not silently drop
// coverage.
func irPreflightFork(ctx context.Context, cs []runner.Client, gte string, in []string) runner.PreflightResult {
	if gte == "" && len(in) == 0 {
		return runner.PreflightResult{Runnable: true}
	}
	if len(cs) == 0 {
		return runner.PreflightResult{Runnable: false, Reason: "no clients"}
	}
	st, err := cs[0].State(ctx)
	if err != nil || st == nil || st.Fork == "" {
		return runner.PreflightResult{Runnable: true, Reason: "fork unknown; not gating"}
	}
	if len(in) > 0 {
		for _, f := range in {
			if f == st.Fork {
				return runner.PreflightResult{Runnable: true}
			}
		}
		return runner.PreflightResult{Runnable: false, Reason: "fork " + st.Fork + " not in " + joinForks(in)}
	}
	rank, want := irForkRank(st.Fork), irForkRank(gte)
	if want >= 0 && rank < want {
		return runner.PreflightResult{Runnable: false, Reason: "fork " + st.Fork + " < " + gte}
	}
	return runner.PreflightResult{Runnable: true}
}

func joinForks(fs []string) string {
	out := ""
	for i, f := range fs {
		if i > 0 {
			out += ","
		}
		out += f
	}
	return out
}
