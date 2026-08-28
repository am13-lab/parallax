package probe_test

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"

	"libp2p-difftest/probe"
	"libp2p-difftest/testnode"
	"libp2p-difftest/wire"
)

const pingProto = "/eth2/beacon_chain/req/ping/1/ssz_snappy"

func startNode(t *testing.T, cfg *testnode.Config) *testnode.Node {
	t.Helper()
	n, err := testnode.Start(cfg)
	if err != nil {
		t.Fatalf("testnode start: %v", err)
	}
	t.Cleanup(n.Close)
	return n
}

func newProbe(t *testing.T) *probe.Probe {
	t.Helper()
	p, err := probe.New()
	if err != nil {
		t.Fatalf("probe.New: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestProbeConnectAndPeerID(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{pingProto: {Behavior: testnode.Success}}})
	p := newProbe(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if p.PeerID() == "" {
		t.Fatal("peer id must be set after connect")
	}
	if p.PeerID() != n.TargetPeerID() {
		t.Fatalf("peer id mismatch: probe sees %q, node is %q", p.PeerID(), n.TargetPeerID())
	}
}

func TestProbeSendAndReceiveSuccess(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Success, Chunks: [][]byte{{0x01, 0x02}}, ReadRequest: true},
	}})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	resp, dur, err := p.SendAndReceive(ctx, pingProto, wire.BuildSSZSnappy([]byte("req")), 2*time.Second)
	if err != nil {
		t.Fatalf("send and receive: %v", err)
	}
	if dur <= 0 {
		t.Fatal("duration must be positive")
	}
	chunks := wire.ParseReqRespResponseV1(resp)
	if len(chunks) != 1 || !bytes.Equal(chunks[0].Payload, []byte{0x01, 0x02}) {
		t.Fatalf("chunk mismatch: %+v", chunks)
	}
	if got := n.Requests(pingProto); len(got) != 1 || !bytes.Equal(got[0], []byte("req")) {
		t.Fatalf("node must have recorded the request: %v", got)
	}
}

func TestProbeSendAndReceiveMeasuresTTFB(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Success, Chunks: [][]byte{{0x07}}, Delay: 200 * time.Millisecond},
	}})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	resp, ttfb, dur, err := p.SendAndReceiveWithTTFB(ctx, pingProto, wire.BuildSSZSnappy([]byte("q")), 3*time.Second)
	if err != nil {
		t.Fatalf("send and receive: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("response must not be empty")
	}
	if ttfb < 150*time.Millisecond {
		t.Fatalf("ttfb must reflect the scripted delay: %v", ttfb)
	}
	if dur < ttfb {
		t.Fatalf("duration %v cannot be below ttfb %v", dur, ttfb)
	}
}

func TestProbeSendAndReceiveReset(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Reset},
	}})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	resp, _, err := p.SendAndReceive(ctx, pingProto, wire.BuildSSZSnappy([]byte("q")), 2*time.Second)
	if err == nil {
		t.Fatal("reset must surface as an error")
	}
	if len(resp) != 0 {
		t.Fatalf("reset must yield no response bytes, got %x", resp)
	}
}

func TestProbeSendAndReceiveTimeout(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Hang},
	}})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	start := time.Now()
	_, _, err := p.SendAndReceive(ctx, pingProto, wire.BuildSSZSnappy([]byte("q")), 400*time.Millisecond)
	if err == nil {
		t.Fatal("timeout must surface as an error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("read timeout must be honored promptly")
	}
}

func TestProbeStatusResponder(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{pingProto: {Behavior: testnode.Success}}})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	statusSSZ := bytes.Repeat([]byte{0x42}, 84)
	p.InstallStatusHandlers(statusSSZ, statusSSZ)

	// Dial back into the probe like a real client would and check the
	// canned Status response chunk.
	dialer := dialBackHost(t)
	ai, err := peer.AddrInfoFromString(p.ListenAddr())
	if err != nil {
		t.Fatalf("probe listen addr: %v", err)
	}
	if err := dialer.Connect(ctx, *ai); err != nil {
		t.Fatalf("dial back: %v", err)
	}
	stream, err := dialer.NewStream(ctx, ai.ID, protocol.ID("/eth2/beacon_chain/req/status/1/ssz_snappy"))
	if err != nil {
		t.Fatalf("open status stream: %v", err)
	}
	defer stream.Close()
	stream.Write(wire.BuildSSZSnappy(bytes.Repeat([]byte{0x01}, 84)))
	stream.CloseWrite()

	buf := make([]byte, 4096)
	n1, err := stream.Read(buf)
	if err != nil && n1 == 0 {
		t.Fatalf("read status response: %v", err)
	}
	resp := buf[:n1]
	if resp[0] != 0x00 {
		t.Fatalf("status responder must answer with success chunk, got %#x", resp[0])
	}
	body, err := wire.ParseReqRespRequest(resp[1:])
	if err != nil || !bytes.Equal(body, statusSSZ) {
		t.Fatalf("status body mismatch: err=%v body=%x", err, body)
	}
}

func TestProbeRotateIdentity(t *testing.T) {
	n := startNode(t, &testnode.Config{Protocols: map[string]*testnode.Script{
		pingProto: {Behavior: testnode.Success, Chunks: [][]byte{{0x09}}, ReadRequest: true},
	}})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	oldID := p.OwnPeerID()
	if oldID == "" {
		t.Fatal("own peer id must be available")
	}

	if err := p.RotateIdentity(ctx); err != nil {
		t.Fatalf("rotate identity: %v", err)
	}
	if p.OwnPeerID() == oldID {
		t.Fatal("identity rotation must produce a new peer id")
	}

	// The rotated probe must be functional against the same target.
	resp, _, err := p.SendAndReceive(ctx, pingProto, wire.BuildSSZSnappy([]byte("after-rotate")), 2*time.Second)
	if err != nil {
		t.Fatalf("send after rotation: %v", err)
	}
	if len(resp) == 0 {
		t.Fatal("empty response after rotation")
	}
}

func TestProbeGossipPublishReachesSink(t *testing.T) {
	topic := "/eth2/aaaaaaaa/beacon_block/ssz_snappy"
	n := startNode(t, &testnode.Config{
		Protocols: map[string]*testnode.Script{pingProto: {Behavior: testnode.Success}},
		Topics:    []string{topic},
	})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := p.PrepareGossipTopic(topic); err != nil {
		t.Fatalf("prepare topic: %v", err)
	}

	payload := []byte("probe gossip payload")
	if err := p.Publish(topic, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := n.Gossip(topic); len(got) > 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("published gossip never reached the node sink")
}

func TestObserverSeesRelayedGossip(t *testing.T) {
	topic := "/eth2/aaaaaaaa/beacon_block/ssz_snappy"
	n := startNode(t, &testnode.Config{
		Protocols: map[string]*testnode.Script{pingProto: {Behavior: testnode.Success}},
		Topics:    []string{topic},
	})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	obs, err := probe.NewObserver(n.Multiaddr(), nil, nil)
	if err != nil {
		t.Fatalf("observer: %v", err)
	}
	t.Cleanup(func() { obs.Close() })
	if err := obs.Watch(topic); err != nil {
		t.Fatalf("watch: %v", err)
	}

	if err := p.PrepareGossipTopic(topic); err != nil {
		t.Fatalf("prepare topic: %v", err)
	}
	since := time.Now()
	payload := []byte("observer relay payload")
	if err := p.Publish(topic, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if obs.Saw(topic, payload, since) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("observer never saw the relayed message")
}

func TestObserverRejectModeTimesOut(t *testing.T) {
	topic := "/eth2/aaaaaaaa/beacon_block/ssz_snappy"
	relayOff := false
	n := startNode(t, &testnode.Config{
		Protocols:   map[string]*testnode.Script{pingProto: {Behavior: testnode.Success}},
		Topics:      []string{topic},
		RelayGossip: &relayOff,
	})
	p := newProbe(t)
	ctx := context.Background()
	if err := p.Connect(ctx, n.Multiaddr()); err != nil {
		t.Fatalf("connect: %v", err)
	}

	obs, err := probe.NewObserver(n.Multiaddr(), nil, nil)
	if err != nil {
		t.Fatalf("observer: %v", err)
	}
	t.Cleanup(func() { obs.Close() })
	if err := obs.Watch(topic); err != nil {
		t.Fatalf("watch: %v", err)
	}
	if err := p.PrepareGossipTopic(topic); err != nil {
		t.Fatalf("prepare topic: %v", err)
	}
	since := time.Now()
	if err := p.Publish(topic, []byte("should be rejected")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if obs.Saw(topic, []byte("should be rejected"), since) {
			t.Fatal("rejected message must not be relayed to the observer")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestGossipMessageID(t *testing.T) {
	data := []byte("payload")
	id1 := probe.GossipMessageID("topic-a", data)
	if len(id1) != 20 {
		t.Fatalf("message id must be 20 bytes, got %d", len(id1))
	}
	if id2 := probe.GossipMessageID("topic-a", data); !bytes.Equal(id1, id2) {
		t.Fatal("same content on same topic must produce the same id")
	}
	// The invalid-snappy domain hashes only the raw data, so topic changes
	// do not alter the id for invalid payloads; compressed payloads do.
	if id3 := probe.GossipMessageID("topic-b", []byte{0xff, 0x00}); !bytes.Equal(probe.GossipMessageID("topic-a", []byte{0xff, 0x00}), id3) {
		t.Fatal("invalid-domain ids for identical raw data must match")
	}
	idSnappy := probe.GossipMessageID("topic-a", snappyBlock(data))
	idSnappyB := probe.GossipMessageID("topic-b", snappyBlock(data))
	if bytes.Equal(idSnappy, idSnappyB) {
		t.Fatal("valid-domain ids must differ across topics")
	}
	if bytes.Equal(id1, idSnappy) {
		t.Fatal("snappy-compressed input must hash over the decompressed payload domain")
	}
}

// dialBackHost builds a minimal host for dialing INTO the probe.
func dialBackHost(t *testing.T) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateSecp256k1Key(crand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
	)
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func snappyBlock(b []byte) []byte {
	return wire.GossipSnappyEncode(b)
}
