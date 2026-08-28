package cases_test

import (
	"context"
	"testing"
	"time"

	"libp2p-difftest/cases"
	"libp2p-difftest/client"
	"libp2p-difftest/internal/testutil"
	"libp2p-difftest/runner"
	"libp2p-difftest/testnode"
)

const (
	pingProto    = "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	statusProto  = "/eth2/beacon_chain/req/status/1/ssz_snappy"
	statusV2Spec = "/eth2/beacon_chain/req/status/2/ssz_snappy"
	metadataSpec = "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
	bbrSpec      = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
	unknownProto = "/eth2/beacon_chain/req/definitely_not_real/1/ssz_snappy"
	gossipTopic  = "/eth2/deadbeef/beacon_block/ssz_snappy"
)

// harness spins up testnodes with per-node protocol scripts and wires them
// as runner.Clients.
type harness struct {
	nodes   []*testnode.Node
	clients []runner.Client
	chain   runner.ChainConfig
}

// start builds nodeCount nodes; scripts maps protocol -> per-node behaviors
// (index beyond the slice means the node does not serve the protocol).
func start(t *testing.T, nodeCount int, scripts map[string][]*testnode.Script, relay []bool, enrs [][]byte) *harness {
	t.Helper()
	beacons := make([]*testnode.BeaconConfig, nodeCount)
	for i := range beacons {
		beacons[i] = &testnode.BeaconConfig{ENR: enrFor(t, enrs, i), HeadSlot: 32}
	}
	return startBeacons(t, nodeCount, scripts, relay, beacons)
}

// startBeacons is start() with full control over each node's beacon config
// (ENR contents, node metadata).
func startBeacons(t *testing.T, nodeCount int, scripts map[string][]*testnode.Script,
	relay []bool, beacons []*testnode.BeaconConfig) *harness {
	t.Helper()
	h := &harness{chain: runner.ChainConfig{
		Preset:        "mainnet",
		ForkDigest:    [4]byte{0xde, 0xad, 0xbe, 0xef},
		GossipMaxSize: 10485760,
		MaxChunkSize:  1048576,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for i := 0; i < nodeCount; i++ {
		protos := map[string]*testnode.Script{}
		for proto, behaviors := range scripts {
			if i < len(behaviors) && behaviors[i] != nil {
				protos[proto] = behaviors[i]
			}
		}
		cfg := &testnode.Config{
			Protocols: protos,
			Topics:    []string{gossipTopic},
			Beacon:    beacons[i],
		}
		if beacons[i] == nil {
			cfg.Beacon = &testnode.BeaconConfig{HeadSlot: 32}
		}
		if i < len(relay) && !relay[i] {
			off := false
			cfg.RelayGossip = &off
		}
		node, err := testnode.Start(cfg)
		if err != nil {
			t.Fatalf("testnode %d: %v", i, err)
		}
		h.nodes = append(h.nodes, node)

		c, err := client.New(ctx, &client.Config{
			Name:       fmtName(i),
			ClientType: "fake",
			Multiaddr:  node.Multiaddr(),
			BeaconAPI:  node.BeaconURL(),
		})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		h.clients = append(h.clients, c)
	}
	t.Cleanup(func() {
		for _, c := range h.clients {
			c.Close()
		}
		for _, n := range h.nodes {
			n.Close()
		}
	})
	return h
}

func enrFor(t *testing.T, enrs [][]byte, i int) string {
	t.Helper()
	if i >= len(enrs) {
		return ""
	}
	return testutil.BuildTestENR(enrs[i], make([]byte, 8))
}

func fmtName(i int) string {
	return string(rune('A' + i))
}

func (h *harness) env() runner.TestEnv {
	return runner.TestEnv{
		Clients: h.clients,
		Chain:   h.chain,
		RNG:     nil,
	}
}

func okRead() *testnode.Script {
	return &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true}
}

func resetRead() *testnode.Script {
	return &testnode.Script{Behavior: testnode.Reset, ReadRequest: true}
}

// ---- tests ----

func TestRegistryStable(t *testing.T) {
	all := cases.All()
	if len(all) < 10 {
		t.Fatalf("seed set too small: %d", len(all))
	}
	seen := map[string]bool{}
	for _, s := range all {
		if s.ID == "" || s.Category == "" || s.Run == nil {
			t.Fatalf("malformed spec: %+v", s)
		}
		if seen[s.ID] {
			t.Fatalf("duplicate spec id: %s", s.ID)
		}
		seen[s.ID] = true
	}
	if _, ok := cases.ByID("reqresp.ping.empty_body"); !ok {
		t.Fatal("ByID must find registered cases")
	}
	if got := cases.ByCategory("transport"); len(got) != 2 {
		t.Fatalf("transport category: %d", len(got))
	}
}

func TestStatusValidConvergent(t *testing.T) {
	h := start(t, 2, map[string][]*testnode.Script{
		statusProto:  {okRead(), okRead()},
		statusV2Spec: {okRead(), okRead()},
	}, nil, nil)
	spec, _ := cases.ByID("reqresp.status.valid")
	divs := spec.Run(context.Background(), h.env())
	if len(divs) != 0 {
		t.Fatalf("identical nodes must converge: %+v", divs)
	}
}

func TestPingEmptyBodyDiverges(t *testing.T) {
	h := start(t, 2, map[string][]*testnode.Script{
		pingProto: {okRead(), resetRead()},
	}, nil, nil)
	spec, _ := cases.ByID("reqresp.ping.empty_body")
	divs := spec.Run(context.Background(), h.env())
	if len(divs) != 1 {
		t.Fatalf("accept vs reset must diverge: %+v", divs)
	}
	d := divs[0]
	if len(d.ClientResults) != 2 || len(d.OutlierClients) != 1 || d.OutlierClients[0] != "B" {
		t.Fatalf("divergence detail: %+v", d)
	}
	if d.Severity != runner.SeverityHigh || d.Type != runner.DivAcceptReject {
		t.Fatalf("severity/type: %+v", d)
	}
}

func TestUnknownProtocolAgainstServingNode(t *testing.T) {
	// Node A wrongly serves an unknown protocol; node B correctly resets.
	h := start(t, 2, map[string][]*testnode.Script{
		unknownProto: {okRead(), resetRead()},
	}, nil, nil)
	spec, _ := cases.ByID("reqresp.unknown_protocol")
	divs := spec.Run(context.Background(), h.env())
	if len(divs) != 1 {
		t.Fatalf("serving vs resetting unknown protocol must diverge: %+v", divs)
	}
}

func TestLengthBombRejectsOnBoth(t *testing.T) {
	// Both nodes reject the bomb (Reset): converge on reject, no divergence.
	h := start(t, 2, map[string][]*testnode.Script{
		bbrSpec: {resetRead(), resetRead()},
	}, nil, nil)
	spec, _ := cases.ByID("reqresp.blocks_by_root.length_bomb")
	divs := spec.Run(context.Background(), h.env())
	if len(divs) != 0 {
		t.Fatalf("uniform rejection converges: %+v", divs)
	}
}

func TestLengthBombDivergesWhenOneServes(t *testing.T) {
	h := start(t, 2, map[string][]*testnode.Script{
		bbrSpec: {okRead(), resetRead()},
	}, nil, nil)
	spec, _ := cases.ByID("reqresp.blocks_by_root.length_bomb")
	divs := spec.Run(context.Background(), h.env())
	if len(divs) != 1 {
		t.Fatalf("serving a length bomb must diverge: %+v", divs)
	}
}

func TestGossipMalformedVerdicts(t *testing.T) {
	t.Run("diverge", func(t *testing.T) {
		h := start(t, 2, map[string][]*testnode.Script{}, []bool{true, false}, nil)
		spec, _ := cases.ByID("gossip.block.malformed")
		divs := spec.Run(context.Background(), h.env())
		if len(divs) != 1 {
			t.Fatalf("relay vs reject must diverge: %+v", divs)
		}
	})
	t.Run("converge", func(t *testing.T) {
		h := start(t, 2, map[string][]*testnode.Script{}, []bool{false, false}, nil)
		spec, _ := cases.ByID("gossip.block.malformed")
		divs := spec.Run(context.Background(), h.env())
		if len(divs) != 0 {
			t.Fatalf("uniform rejection converges: %+v", divs)
		}
	})
}

func TestDiscoveryForkDigest(t *testing.T) {
	same := make([]byte, 16)
	copy(same[0:4], []byte{0xde, 0xad, 0xbe, 0xef})
	other := make([]byte, 16)
	copy(other[0:4], []byte{0x01, 0x02, 0x03, 0x04})

	t.Run("converge", func(t *testing.T) {
		h := start(t, 2, map[string][]*testnode.Script{}, nil, [][]byte{same, same})
		spec, _ := cases.ByID("discovery.fork_digest")
		divs := spec.Run(context.Background(), h.env())
		if len(divs) != 0 {
			t.Fatalf("same digest must converge: %+v", divs)
		}
	})
	t.Run("diverge", func(t *testing.T) {
		h := start(t, 2, map[string][]*testnode.Script{}, nil, [][]byte{same, other})
		spec, _ := cases.ByID("discovery.fork_digest")
		divs := spec.Run(context.Background(), h.env())
		if len(divs) != 1 || divs[0].Type != runner.DivConsensusValue {
			t.Fatalf("digest mismatch must diverge: %+v", divs)
		}
	})
}

func TestTransportCases(t *testing.T) {
	h := start(t, 2, map[string][]*testnode.Script{
		statusProto:  {okRead(), okRead()},
		statusV2Spec: {okRead(), okRead()},
	}, nil, nil)
	for _, id := range []string{"transport.handshake.connect", "transport.handshake.identity_rotation"} {
		spec, _ := cases.ByID(id)
		divs := spec.Run(context.Background(), h.env())
		if len(divs) != 0 {
			t.Fatalf("%s must pass against live nodes: %+v", id, divs)
		}
	}
}

func TestStatusPreStatusRestoresConnection(t *testing.T) {
	// One node serves status unconditionally (non-conformant), the other
	// rejects pre-handshake requests: divergence.
	h := start(t, 2, map[string][]*testnode.Script{
		statusProto: {okRead(), resetRead()},
	}, nil, nil)
	spec, _ := cases.ByID("reqresp.status.pre_status")
	divs := spec.Run(context.Background(), h.env())
	if len(divs) != 1 {
		t.Fatalf("pre-status serving vs rejecting must diverge: %+v", divs)
	}
	// The case must restore handshaken connections: a follow-up ping works.
	ctx := context.Background()
	for _, c := range h.clients {
		if err := c.Connect(ctx, runner.ConnectWithStatus); err != nil {
			t.Fatalf("reconnect %s: %v", c.Name(), err)
		}
	}
}
