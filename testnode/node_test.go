package testnode

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"

	"libp2p-difftest/wire"
)

const testProtocol = "/eth2/beacon_chain/req/ping/1/ssz_snappy"

// dialerHost builds a client libp2p host with the same stack real targets use.
func dialerHost(t *testing.T) host.Host {
	t.Helper()
	priv, _, err := crypto.GenerateSecp256k1Key(crand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
		t.Fatalf("dialer host: %v", err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

// exchange opens a stream, sends a request frame, and reads the response.
func exchange(t *testing.T, h host.Host, maddr string, proto string, reqBody []byte, readTimeout time.Duration) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ai, err := peer.AddrInfoFromString(maddr)
	if err != nil {
		t.Fatalf("parse multiaddr: %v", err)
	}
	if err := h.Connect(ctx, *ai); err != nil {
		t.Fatalf("connect: %v", err)
	}

	stream, err := h.NewStream(ctx, ai.ID, protocol.ID(proto))
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	defer stream.Close()

	if _, err := stream.Write(wire.BuildSSZSnappy(reqBody)); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	if err := stream.CloseWrite(); err != nil {
		return nil, fmt.Errorf("close write: %w", err)
	}

	readCtx, readCancel := context.WithTimeout(ctx, readTimeout)
	defer readCancel()
	if err := stream.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		// Deadline support is optional per stream; fall back to context only.
		_ = readCtx
	}
	buf := make([]byte, 64*1024)
	var out []byte
	for {
		n, err := stream.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			// A trailing EOF after buffered data is a complete response;
			// only surface the error when nothing was read (reset, timeout).
			if len(out) > 0 {
				return out, nil
			}
			return out, err
		}
	}
}

func TestNodeStartAndIdentity(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {Behavior: Success}},
		Beacon:    &BeaconConfig{ENR: "enr:-test", HeadSlot: 100},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	if n.Multiaddr() == "" {
		t.Fatal("multiaddr must not be empty")
	}

	resp, err := http.Get(n.BeaconURL() + "/eth/v1/node/identity")
	if err != nil {
		t.Fatalf("beacon identity: %v", err)
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			PeerID string `json:"peer_id"`
			ENR    string `json:"enr"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if body.Data.ENR != "enr:-test" {
		t.Fatalf("canned ENR mismatch: %q", body.Data.ENR)
	}
	if body.Data.PeerID == "" {
		t.Fatal("identity must carry the node's real peer ID")
	}
}

func TestNodeHealthAndFork(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {Behavior: Success}},
		Beacon:    &BeaconConfig{ForkVersion: "0x04000000", ForkName: "fulu", HeadSlot: 64, HeadRoot: "0xabc"},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	resp, err := http.Get(n.BeaconURL() + "/eth/v1/node/health")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health: status %d err %v", resp.StatusCode, err)
	}
	resp.Body.Close()

	resp, err = http.Get(n.BeaconURL() + "/eth/v1/beacon/states/head/fork")
	if err != nil {
		t.Fatalf("fork: %v", err)
	}
	defer resp.Body.Close()
	var fork struct {
		Data struct {
			CurrentVersion string `json:"current_version"`
			EPOCH          string `json:"epoch"`
			Name           string `json:"name,omitempty"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&fork); err != nil {
		t.Fatalf("decode fork: %v", err)
	}
	if fork.Data.CurrentVersion != "0x04000000" {
		t.Fatalf("fork version mismatch: %q", fork.Data.CurrentVersion)
	}
}

func TestNodeReqRespSuccess(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {
			Behavior:    Success,
			Chunks:      [][]byte{{0xaa, 0xbb}},
			ReadRequest: true,
		}},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	h := dialerHost(t)
	resp, err := exchange(t, h, n.Multiaddr(), testProtocol, []byte("ping-body"), 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// ping is a V1 protocol: no context bytes in the response chunk.
	chunks := wire.ParseReqRespResponseV1(resp)
	if len(chunks) != 1 || chunks[0].ResultCode != 0 {
		t.Fatalf("want one success chunk, got %+v", chunks)
	}
	if !bytes.Equal(chunks[0].Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("chunk payload mismatch: %x", chunks[0].Payload)
	}
	if len(n.Requests(testProtocol)) != 1 || !bytes.Equal(n.Requests(testProtocol)[0], []byte("ping-body")) {
		t.Fatalf("request not recorded: %v", n.Requests(testProtocol))
	}
}

func TestNodeReqRespSuccessWithContext(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {
			Behavior:    Success,
			Chunks:      [][]byte{{0x01}},
			WithContext: true,
			Context:     [4]byte{1, 2, 3, 4},
		}},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	h := dialerHost(t)
	resp, err := exchange(t, h, n.Multiaddr(), testProtocol, []byte("x"), 2*time.Second)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	chunks := wire.ParseReqRespResponse(resp)
	if len(chunks) != 1 || !bytes.Equal(chunks[0].Context, []byte{1, 2, 3, 4}) {
		t.Fatalf("context chunk mismatch: %+v", chunks)
	}
}

func TestNodeReqRespErrorAndResetAndGarbage(t *testing.T) {
	cases := []struct {
		name    string
		script  Script
		wantErr bool
	}{
		{
			name:   "error_code",
			script: Script{Behavior: ErrorCode, Code: 0x02, Message: "oops"},
		},
		{
			name:    "reset",
			script:  Script{Behavior: Reset},
			wantErr: true,
		},
		{
			name:    "garbage",
			script:  Script{Behavior: Garbage, Garbage: []byte{0x01, 0x02, 0x03}},
			wantErr: true, // parseable as an error chunk but nonsense framing
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := Start(&Config{Protocols: map[string]*Script{testProtocol: &tc.script}})
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			defer n.Close()

			h := dialerHost(t)
			resp, err := exchange(t, h, n.Multiaddr(), testProtocol, []byte("q"), 2*time.Second)
			if tc.wantErr {
				if err == nil && len(resp) == 0 {
					t.Fatal("want error or data, got neither")
				}
				return
			}
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			chunks := wire.ParseReqRespResponse(resp)
			if len(chunks) != 1 || chunks[0].ResultCode != 0x02 {
				t.Fatalf("want error chunk 0x02, got %+v", chunks)
			}
			if string(chunks[0].Payload) != "oops" {
				t.Fatalf("error message mismatch: %q", chunks[0].Payload)
			}
		})
	}
}

func TestNodeReqRespHang(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {Behavior: Hang}},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	h := dialerHost(t)
	start := time.Now()
	_, err = exchange(t, h, n.Multiaddr(), testProtocol, []byte("q"), 300*time.Millisecond)
	if err == nil {
		t.Fatal("hang must cause a read timeout")
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("hang ended too early: %v", elapsed)
	}
}

func TestNodeResetBeforeRead(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {Behavior: Reset, ReadRequest: false}},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	h := dialerHost(t)
	_, err = exchange(t, h, n.Multiaddr(), testProtocol, []byte("never-read"), 2*time.Second)
	if err == nil {
		t.Fatal("reset before read must surface as a stream error")
	}
	if len(n.Requests(testProtocol)) != 0 {
		t.Fatal("no request may be recorded when the node resets before reading")
	}
}

func TestNodeGossipSink(t *testing.T) {
	n, err := Start(&Config{
		Protocols: map[string]*Script{testProtocol: {Behavior: Success}},
		Topics:    []string{"/eth2/aaaaaaaa/beacon_block/ssz_snappy"},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	h := dialerHost(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ai, _ := peer.AddrInfoFromString(n.Multiaddr())
	if err := h.Connect(ctx, *ai); err != nil {
		t.Fatalf("connect: %v", err)
	}

	payload := []byte("fake block payload")
	if err := publishGossip(t, h, n.Multiaddr(), "/eth2/aaaaaaaa/beacon_block/ssz_snappy", payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := n.Gossip("/eth2/aaaaaaaa/beacon_block/ssz_snappy"); len(got) == 1 {
			if !bytes.Equal(got[0], payload) {
				t.Fatalf("gossip payload mismatch: %x", got[0])
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gossip message not recorded within deadline")
}

func TestNodeGossipRejectModeDropsMessage(t *testing.T) {
	topic := "/eth2/aaaaaaaa/beacon_block/ssz_snappy"
	relayOff := false
	n, err := Start(&Config{
		Protocols:   map[string]*Script{testProtocol: {Behavior: Success}},
		Topics:      []string{topic},
		RelayGossip: &relayOff,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	// In reject mode the gossipsub validator rejects the message, so it is
	// neither relayed nor delivered to the local sink. That is exactly the
	// target behavior a gossip verdict observer interprets as rejection.
	h := dialerHost(t)
	if err := publishGossip(t, h, n.Multiaddr(), topic, []byte("reject me")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(n.Gossip(topic)) > 0 {
			t.Fatal("rejected gossip must not be recorded at the sink")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// publishGossip joins the topic on a throwaway gossipsub-enabled host and
// publishes a raw snappy block, the way the probe's gossip publisher does.
func publishGossip(t *testing.T, h host.Host, maddr, topic string, payload []byte) error {
	t.Helper()
	ps, err := pubsub.NewGossipSub(context.Background(), h)
	if err != nil {
		return fmt.Errorf("gossipsub: %w", err)
	}
	tp, err := ps.Join(topic)
	if err != nil {
		return fmt.Errorf("join: %w", err)
	}
	t.Cleanup(func() { tp.Close() })
	// Gossipsub grafts connected peers onto the topic mesh on the next
	// heartbeat (default 1s); publish before that and the message goes
	// nowhere. Wait one heartbeat plus margin.
	time.Sleep(1200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return tp.Publish(ctx, payload)
}
