package client_test

import (
	"context"
	"testing"
	"time"

	"parallax/client"
	"parallax/internal/testutil"
	"parallax/runner"
	"parallax/testnode"
	"parallax/wire"
)

const (
	pingProto    = "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	statusProto  = "/eth2/beacon_chain/req/status/1/ssz_snappy"
	statusV2Spec = "/eth2/beacon_chain/req/status/2/ssz_snappy"
	goodbyeSpec  = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
	testTopic    = "/eth2/aaaaaaaa/beacon_block/ssz_snappy"
)

func startNode(t *testing.T, cfg *testnode.Config) *testnode.Node {
	t.Helper()
	n, err := testnode.Start(cfg)
	if err != nil {
		t.Fatalf("testnode start: %v", err)
	}
	t.Cleanup(n.Close)
	return n
}

func startDefaultNode(t *testing.T) *testnode.Node {
	return startNode(t, &testnode.Config{
		Protocols: map[string]*testnode.Script{
			pingProto:    {Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true},
			statusProto:  {Behavior: testnode.Success, Chunks: [][]byte{make([]byte, 84)}, ReadRequest: true},
			statusV2Spec: {Behavior: testnode.Success, Chunks: [][]byte{make([]byte, 92)}, ReadRequest: true},
			goodbyeSpec:  {Behavior: testnode.Success},
		},
		Beacon: &testnode.BeaconConfig{ENR: testENR(t), HeadSlot: 64},
	})
}

var cachedENR string

func testENR(t *testing.T) string {
	t.Helper()
	if cachedENR != "" {
		return cachedENR
	}
	eth2 := make([]byte, 16)
	copy(eth2[0:4], []byte{0xab, 0xcd, 0xef, 0x01})
	cachedENR = testutil.BuildTestENR(eth2, make([]byte, 8))
	return cachedENR
}

func newClientAt(t *testing.T, maddr, beaconAPI string, proxies []string) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := client.New(ctx, &client.Config{
		Name:       "node-under-test",
		ClientType: "fake",
		Multiaddr:  maddr,
		BeaconAPI:  beaconAPI,
		Proxies:    proxies,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestNewPerformsStatusHandshake(t *testing.T) {
	n := startDefaultNode(t)
	c := newClientAt(t, n.Multiaddr(), n.BeaconURL(), nil)

	// The handshake itself must already have happened.
	if got := n.Requests(statusProto); len(got) != 1 {
		t.Fatalf("status handshake request not recorded: %d", len(got))
	}
	// And the client stays functional.
	res, err := c.ReqResp(context.Background(), pingProto, wire.BuildSSZSnappy([]byte("hi")), 2*time.Second)
	if err != nil || res.Error != "" {
		t.Fatalf("ping after handshake failed: err=%v res=%+v", err, res)
	}
	if len(res.ResponseChunks) != 1 || res.ResponseChunks[0].Payload == nil {
		t.Fatalf("ping chunk mismatch: %+v", res.ResponseChunks)
	}
}

// The /status/2/ protocol must carry the 92-byte V2 envelope, not the
// 84-byte V1 body.
func TestStatusV2HandshakeSendsV2Body(t *testing.T) {
	n := startDefaultNode(t)
	newClientAt(t, n.Multiaddr(), n.BeaconURL(), nil)

	got := n.Requests(statusV2Spec)
	if len(got) != 1 {
		t.Fatalf("status v2 handshake request not recorded: %d", len(got))
	}
	if len(got[0]) != 92 {
		t.Fatalf("v2 handshake body must be the 92-byte V2 envelope, got %d bytes", len(got[0]))
	}
}

func TestNewNoStatusMode(t *testing.T) {
	n := startDefaultNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name:       "n",
		ClientType: "fake",
		Multiaddr:  n.Multiaddr(),
		BeaconAPI:  n.BeaconURL(),
		Mode:       client.ModeNoStatus,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if got := n.Requests(statusProto); len(got) != 0 {
		t.Fatalf("no status request expected, got %d", len(got))
	}
}

func TestReqRespStreamReset(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Reset},
	}})
	c := newClientAt(t, n.Multiaddr(), n.BeaconURL(), nil)

	res, err := c.ReqResp(context.Background(), pingProto, wire.BuildSSZSnappy([]byte("q")), 2*time.Second)
	if err != nil {
		t.Fatalf("ReqResp must not hard-fail: %v", err)
	}
	if res.Error == "" || !res.StreamReset {
		t.Fatalf("reset must surface as StreamReset with error: %+v", res)
	}
}

func TestStateFromBeaconAPI(t *testing.T) {
	n := startDefaultNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name:       "n",
		ClientType: "fake",
		Multiaddr:  n.Multiaddr(),
		BeaconAPI:  n.BeaconURL(),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	state, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if state.ForkDigest != [4]byte{0xab, 0xcd, 0xef, 0x01} {
		t.Fatalf("fork digest from canned ENR: %x", state.ForkDigest)
	}
}

func TestStateNoBeaconAPI(t *testing.T) {
	n := startDefaultNode(t)
	c := newClientAt(t, n.Multiaddr(), "", nil)

	if _, err := c.State(context.Background()); err == nil {
		t.Fatal("state without beacon API must error")
	}
}

func TestHealthAndSnapshot(t *testing.T) {
	n := startDefaultNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name:       "n",
		ClientType: "fake",
		Multiaddr:  n.Multiaddr(),
		BeaconAPI:  n.BeaconURL(),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}
	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.HeadSlot != 64 {
		t.Fatalf("snapshot head slot: %d", snap.HeadSlot)
	}
}

func TestRotateIdentityCyclesToProxy(t *testing.T) {
	nodeA := startDefaultNode(t)
	nodeB := startDefaultNode(t)
	c := newClientAt(t, nodeA.Multiaddr(), nodeA.BeaconURL(), []string{nodeB.Multiaddr()})

	// Initial connection goes to the direct multiaddr (node A) when no
	// proxy has been selected yet... actually New connects via proxy[0]
	// when proxies exist; requests must appear on B from the start.
	if got := nodeB.Requests(statusProto); len(got) != 1 {
		t.Fatalf("initial connect must use the first proxy (node B): %d", len(got))
	}
	if got := nodeA.Requests(statusProto); len(got) != 0 {
		t.Fatalf("node A must not be dialed when a proxy is configured: %d", len(got))
	}

	// Rotation cycles back into the proxy list (single entry: still B)
	// with a fresh identity.
	before := c.OwnPeerID()
	if err := c.RotateIdentity(context.Background()); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if c.OwnPeerID() == before {
		t.Fatal("identity must change on rotation")
	}
	if got := nodeB.Requests(statusProto); len(got) != 2 {
		t.Fatalf("post-rotation handshake missing: %d", len(got))
	}
}

func TestObserveGossipAcceptAndReject(t *testing.T) {
	t.Run("accept_when_relayed", func(t *testing.T) {
		n := startNode(t, &testnode.Config{
			Protocols: map[string]*testnode.Script{statusProto: {Behavior: testnode.Success}},
			Topics:    []string{testTopic},
		})
		c := newClientAt(t, n.Multiaddr(), n.BeaconURL(), nil)

		payload := wire.GossipSnappyEncode([]byte("accepted message"))
		verdict, err := c.ObserveGossip(context.Background(), testTopic, payload, 10*time.Second)
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		if verdict != runner.VerdictAccept {
			t.Fatalf("want accept, got %v", verdict)
		}
	})

	t.Run("reject_when_not_relayed", func(t *testing.T) {
		relayOff := false
		n := startNode(t, &testnode.Config{
			Protocols:   map[string]*testnode.Script{statusProto: {Behavior: testnode.Success}},
			Topics:      []string{testTopic},
			RelayGossip: &relayOff,
		})
		c := newClientAt(t, n.Multiaddr(), n.BeaconURL(), nil)

		payload := wire.GossipSnappyEncode([]byte("rejected message"))
		verdict, err := c.ObserveGossip(context.Background(), testTopic, payload, 4*time.Second)
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		if verdict != runner.VerdictReject {
			t.Fatalf("want reject, got %v", verdict)
		}
	})
}

func TestConnectNoStatusFreshConnection(t *testing.T) {
	n := startDefaultNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name:       "n",
		ClientType: "fake",
		Multiaddr:  n.Multiaddr(),
		BeaconAPI:  n.BeaconURL(),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	beforeV1 := len(n.Requests(statusProto))
	beforeV2 := len(n.Requests(statusV2Spec))
	if err := c.Connect(ctx, client.ModeNoStatus); err != nil {
		t.Fatalf("connect no status: %v", err)
	}
	if len(n.Requests(statusProto)) != beforeV1 || len(n.Requests(statusV2Spec)) != beforeV2 {
		t.Fatalf("NoStatus connect must not handshake")
	}

	if err := c.Connect(ctx, client.ModeWithStatus); err != nil {
		t.Fatalf("connect with status: %v", err)
	}
	gotV1 := len(n.Requests(statusProto)) - beforeV1
	gotV2 := len(n.Requests(statusV2Spec)) - beforeV2
	if gotV1 != 1 || gotV2 != 1 {
		t.Fatalf("WithStatus connect must handshake v1+v2: v1 +%d, v2 %d", gotV1, gotV2)
	}
}

func TestSendOnlyAndSlowly(t *testing.T) {
	n := startDefaultNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name: "n", ClientType: "fake", Multiaddr: n.Multiaddr(), BeaconAPI: n.BeaconURL(),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if err := c.SendOnly(ctx, pingProto, wire.BuildSSZSnappy([]byte{0x01})); err != nil {
		t.Fatalf("send only: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(n.Requests(pingProto)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := n.Requests(pingProto); len(got) == 0 {
		t.Fatal("SendOnly request must reach the node")
	}
	if _, err := c.SendSlowly(ctx, pingProto, wire.BuildSSZSnappy([]byte{0x02}), 2*time.Millisecond, 3*time.Second); err != nil {
		t.Fatalf("send slowly: %v", err)
	}
}

// TestSendOnlyStreamReclaimed pins the SendOnly stream lifecycle: after the
// reclaim TTL the stream must be fully torn down, so long runs stop leaking
// streams on the muxed connection.
func TestSendOnlyStreamReclaimed(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Hang, ReadRequest: true},
	}})
	client.SetSendOnlyStreamTTL(100 * time.Millisecond)
	t.Cleanup(func() { client.SetSendOnlyStreamTTL(15 * time.Second) })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name:       "n",
		ClientType: "fake",
		Multiaddr:  n.Multiaddr(),
		BeaconAPI:  n.BeaconURL(),
		Mode:       client.ModeNoStatus,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if err := c.SendOnly(ctx, pingProto, wire.BuildSSZSnappy([]byte{0x01})); err != nil {
		t.Fatalf("send only: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(n.Requests(pingProto)) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(n.Requests(pingProto)) == 0 {
		t.Fatal("SendOnly request must reach the node")
	}
	if got := c.OpenStreams(pingProto); got != 1 {
		t.Fatalf("stream must be open before the TTL expires, open: %d", got)
	}

	deadline = time.Now().Add(3 * time.Second)
	for c.OpenStreams(pingProto) > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := c.OpenStreams(pingProto); got != 0 {
		t.Fatalf("SendOnly stream must be reclaimed after the TTL, still open: %d", got)
	}
}

// TestHealthCatchesDeadP2P pins the live-run lesson (prysm served /health
// 200 for a whole standard run while every status handshake failed):
// Health must verify the libp2p plane, not just the Beacon API.
func TestHealthCatchesDeadP2P(t *testing.T) {
	n := startDefaultNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name:       "n",
		ClientType: "fake",
		Multiaddr:  n.Multiaddr(),
		BeaconAPI:  n.BeaconURL(),
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if err := c.Health(ctx); err != nil {
		t.Fatalf("healthy node must pass Health: %v", err)
	}

	n.BreakLibp2p()
	time.Sleep(500 * time.Millisecond) // let the swarm drop the dead conn

	if err := c.Health(ctx); err == nil {
		t.Fatal("dead libp2p must fail Health even with a green Beacon API")
	}
}
