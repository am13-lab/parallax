// Package testnode provides an in-process fake consensus-layer beacon node:
// a libp2p host with scriptable req/resp protocol behavior, a gossipsub
// sink, and a canned HTTP beacon API. It is the testing cornerstone: every
// higher layer is tested against it instead of a live devnet.
package testnode

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsubpb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"

	"libp2p-difftest/wire"
)

// Behavior selects how a scripted protocol responds.
type Behavior int

const (
	Success   Behavior = iota // respond with configured chunks
	ErrorCode                 // respond with a result code plus message
	Reset                     // reset the stream
	Hang                      // never respond
	Garbage                   // write raw bytes then close
)

// Script configures one protocol's behavior.
type Script struct {
	Behavior    Behavior
	Chunks      [][]byte // SSZ payloads for Success (one response chunk each)
	WithContext bool     // prefix 4-byte fork context on each success chunk
	Context     [4]byte  // context bytes when WithContext
	Code        byte     // result code for ErrorCode (1=invalid, 2=error, 3=unavailable)
	Message     string   // message body for ErrorCode
	Garbage     []byte   // raw bytes for Garbage
	// ReadRequest reads and records the request before responding.
	// When false (Reset), the stream is reset without reading.
	ReadRequest bool
	// Delay holds the response before writing it.
	Delay time.Duration
}

// BeaconConfig carries the canned beacon API data.
type BeaconConfig struct {
	ENR         string
	HeadSlot    uint64
	HeadRoot    string // 0x-hex
	ForkVersion string // 0x-hex
	ForkName    string
	PeerCount   int
	Metrics     string // raw prometheus text

	// Node metadata (/eth/v1/node/metadata).
	MetaSeqNumber uint64
	MetaAttnets   string // 0x-hex bitvector
	MetaSyncnets  string // 0x-hex bitvector
	MetaCGC       string // custody group count as string; empty omits the field
}

// Config configures a testnode.
type Config struct {
	Protocols map[string]*Script
	Topics    []string
	// RelayGossip controls whether received gossip is relayed (accepted) or
	// rejected via the gossipsub validator (not forwarded). Rejected
	// messages are still recorded at the sink. Default (nil) relays.
	RelayGossip *bool
	Beacon      *BeaconConfig
	// MaxChunk bounds request frame reads; default 16 MiB.
	MaxChunk uint64
}

// Node is a running fake beacon node.
type Node struct {
	host      host.Host
	ps        *pubsub.PubSub
	beaconURL string
	ctx       context.Context
	cancel    context.CancelFunc
	closer    func()
	closed    sync.Once

	mu       sync.Mutex
	requests map[string][][]byte
	gossip   map[string][][]byte
}

// Start launches a testnode listening on 127.0.0.1.
func Start(cfg *Config) (*Node, error) {
	ctx, cancel := context.WithCancel(context.Background())

	priv, _, err := crypto.GenerateSecp256k1Key(crand.Reader)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("generate identity: %w", err)
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
		cancel()
		return nil, fmt.Errorf("libp2p host: %w", err)
	}

	n := &Node{
		host:     h,
		ctx:      ctx,
		cancel:   cancel,
		requests: make(map[string][][]byte),
		gossip:   make(map[string][][]byte),
	}

	maxChunk := cfg.MaxChunk
	if maxChunk == 0 {
		maxChunk = 16 << 20
	}
	for proto, script := range cfg.Protocols {
		p, s := proto, script
		h.SetStreamHandler(protocol.ID(p), func(stream network.Stream) {
			n.serveStream(stream, p, s, maxChunk)
		})
	}

	// CL clients exchange unsigned gossip with content-based message ids;
	// mirror that so StrictNoSign publishers are accepted.
	ps, err := pubsub.NewGossipSub(ctx, h,
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		pubsub.WithMessageIdFn(func(pmsg *pubsubpb.Message) string {
			return string(wire.GossipMessageID(pmsg.GetTopic(), pmsg.GetData()))
		}),
	)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("gossipsub: %w", err)
	}
	n.ps = ps
	for _, topic := range cfg.Topics {
		if err := n.sink(topic, cfg.RelayGossip); err != nil {
			h.Close()
			cancel()
			return nil, fmt.Errorf("topic sink %s: %w", topic, err)
		}
	}

	beaconSrv, err := n.startBeacon(cfg.Beacon)
	if err != nil {
		h.Close()
		cancel()
		return nil, fmt.Errorf("beacon api: %w", err)
	}

	n.closer = func() {
		cancel()
		beaconSrv.Close()
		h.Close()
	}

	return n, nil
}

// Multiaddr returns the node's libp2p dial address.
func (n *Node) Multiaddr() string {
	addrs := n.host.Addrs()
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0].String() + "/p2p/" + n.host.ID().String()
}

// BeaconURL returns the canned beacon API base URL.
func (n *Node) BeaconURL() string { return n.beaconURL }

// TargetPeerID returns the node's own libp2p peer ID.
func (n *Node) TargetPeerID() string { return n.host.ID().String() }

// Requests returns the decoded SSZ bodies received per protocol.
func (n *Node) Requests(protocol string) [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([][]byte, len(n.requests[protocol]))
	copy(out, n.requests[protocol])
	return out
}

// Gossip returns raw payloads received per topic.
func (n *Node) Gossip(topic string) [][]byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([][]byte, len(n.gossip[topic]))
	copy(out, n.gossip[topic])
	return out
}

// Close shuts the node down.
func (n *Node) Close() {
	n.closed.Do(func() {
		if n.closer != nil {
			n.closer()
		}
	})
}

func (n *Node) serveStream(stream network.Stream, protocol string, s *Script, maxChunk uint64) {
	defer stream.Close()

	if s.Delay > 0 {
		time.Sleep(s.Delay)
	}

	switch s.Behavior {
	case Reset:
		if s.ReadRequest {
			n.readAndRecord(stream, protocol, maxChunk)
		}
		stream.Reset()
		return
	case Hang:
		if s.ReadRequest {
			n.readAndRecord(stream, protocol, maxChunk)
		}
		<-n.ctx.Done()
		return
	}

	if s.ReadRequest {
		n.readAndRecord(stream, protocol, maxChunk)
	}

	switch s.Behavior {
	case Success:
		var buf []byte
		for _, chunk := range s.Chunks {
			buf = append(buf, 0x00)
			if s.WithContext {
				buf = append(buf, s.Context[:]...)
			}
			buf = append(buf, wire.BuildSSZSnappy(chunk)...)
		}
		stream.Write(buf)
		stream.CloseWrite()
	case ErrorCode:
		msg := s.Message
		buf := append([]byte{s.Code}, wire.EncodeVarint(uint64(len(msg)))...)
		buf = append(buf, msg...)
		stream.Write(buf)
		stream.CloseWrite()
	case Garbage:
		stream.Write(s.Garbage)
		stream.CloseWrite()
	}
}

func (n *Node) readAndRecord(stream network.Stream, protocol string, maxChunk uint64) {
	frame, err := wire.ReadFrame(stream, maxChunk)
	if err != nil {
		return
	}
	body, err := wire.SnappyDecode(frame)
	if err != nil {
		return
	}
	n.mu.Lock()
	n.requests[protocol] = append(n.requests[protocol], body)
	n.mu.Unlock()
}

func (n *Node) sink(topic string, relay *bool) error {
	tp, err := n.ps.Join(topic)
	if err != nil {
		return err
	}
	sub, err := tp.Subscribe()
	if err != nil {
		return err
	}
	if relay != nil && !*relay {
		// Reject mode: the message fails validation and is not relayed,
		// which is exactly what a gossip verdict observer watches for.
		if err := n.ps.RegisterTopicValidator(topic, rejectValidator()); err != nil {
			return err
		}
	}
	go n.drain(topic, sub)
	return nil
}

func rejectValidator() func(ctx context.Context, from peer.ID, msg *pubsub.Message) pubsub.ValidationResult {
	return func(context.Context, peer.ID, *pubsub.Message) pubsub.ValidationResult {
		return pubsub.ValidationReject
	}
}

func (n *Node) drain(topic string, sub *pubsub.Subscription) {
	ctx := n.ctx
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return
		}
		n.mu.Lock()
		n.gossip[topic] = append(n.gossip[topic], msg.GetData())
		n.mu.Unlock()
	}
}

func (n *Node) startBeacon(cfg *BeaconConfig) (*http.Server, error) {
	if cfg == nil {
		cfg = &BeaconConfig{}
	}
	mux := http.NewServeMux()
	peerID := n.host.ID().String()

	mux.HandleFunc("/eth/v1/node/identity", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, fmt.Sprintf(`{"data":{"peer_id":"%s","enr":"%s"}}`, peerID, cfg.ENR))
	})
	mux.HandleFunc("/eth/v1/node/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/eth/v1/node/peer_count", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, fmt.Sprintf(`{"data":{"connected":"%d","connecting":"0","disconnected":"0","disconnecting":"0"}}`, cfg.PeerCount))
	})
	mux.HandleFunc("/eth/v1/beacon/headers/head", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, fmt.Sprintf(`{"data":{"root":"%s","canonical":true,"header":{"message":{"slot":"%d","proposer_index":"0","parent_root":"%s","state_root":"%s"},"signature":"0x00"}}}`,
			cfg.HeadRoot, cfg.HeadSlot, cfg.HeadRoot, cfg.HeadRoot))
	})
	mux.HandleFunc("/eth/v1/beacon/states/head/fork", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, fmt.Sprintf(`{"data":{"previous_version":"%s","current_version":"%s","epoch":"0","name":"%s"}}`,
			cfg.ForkVersion, cfg.ForkVersion, cfg.ForkName))
	})
	mux.HandleFunc("/eth/v1/node/metadata", func(w http.ResponseWriter, r *http.Request) {
		cgc := ""
		if cfg.MetaCGC != "" {
			cgc = fmt.Sprintf(`,"custody_group_count":"%s"`, cfg.MetaCGC)
		}
		writeJSON(w, fmt.Sprintf(`{"data":{"seq_number":"%d","attnets":"%s","syncnets":"%s"%s}}`,
			cfg.MetaSeqNumber, cfg.MetaAttnets, cfg.MetaSyncnets, cgc))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(cfg.Metrics))
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	n.beaconURL = "http://" + ln.Addr().String()
	return srv, nil
}

func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(body))
}
