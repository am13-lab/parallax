// Package probe provides the libp2p probing peer used to test consensus
// clients: connect, req/resp exchange, identity rotation, gossip publishing,
// and a second target-only observer host for gossip verdicts.
//
// The transport stack (secp256k1 identity, noise, yamux + mplex, tcp) is
// carried over from the previous implementation where it was validated
// against all six CL clients.
package probe

import (
	"context"
	crand "crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"

	ma "github.com/multiformats/go-multiaddr"

	"parallax/wire"
)

// Probe is a libp2p host for probing one target peer.
type Probe struct {
	host     host.Host
	peerInfo *peer.AddrInfo
	maddr    ma.Multiaddr

	// Cached Status responder payloads so handlers survive host rebuilds
	// during EnsureConnected and RotateIdentity.
	statusV1SSZ []byte
	statusV2SSZ []byte
	statusSet   bool

	muPub sync.Mutex
	pub   *Publisher
}

// New creates a probe with a fresh secp256k1 identity.
func New() (*Probe, error) {
	h, err := newHost()
	if err != nil {
		return nil, err
	}
	return &Probe{host: h}, nil
}

func newHost() (host.Host, error) {
	priv, _, err := crypto.GenerateSecp256k1Key(crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate secp256k1 key: %w", err)
	}
	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Security(noise.ID, noise.New),
		libp2p.Muxer("/yamux/1.0.0", yamux.DefaultTransport),
		libp2p.Muxer("/mplex/6.7.0", mplex.DefaultTransport),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
	)
	if err != nil {
		return nil, fmt.Errorf("create libp2p host: %w", err)
	}
	return h, nil
}

// InstallStatusHandlers responds to inbound eth2 Status requests. Clients
// like Nimbus disconnect peers that do not answer their Status probe.
func (p *Probe) InstallStatusHandlers(statusV1SSZ, statusV2SSZ []byte) {
	p.statusV1SSZ, p.statusV2SSZ, p.statusSet = statusV1SSZ, statusV2SSZ, true
	p.host.SetStreamHandler(protocol.ID("/eth2/beacon_chain/req/status/1/ssz_snappy"), func(s network.Stream) {
		serveSingleChunkResponse(s, statusV1SSZ)
	})
	p.host.SetStreamHandler(protocol.ID("/eth2/beacon_chain/req/status/2/ssz_snappy"), func(s network.Stream) {
		serveSingleChunkResponse(s, statusV2SSZ)
	})
}

func serveSingleChunkResponse(stream network.Stream, ssz []byte) {
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(stream)

	response := append([]byte{0x00}, wire.BuildSSZSnappy(ssz)...)
	_, _ = stream.Write(response)
	_ = stream.CloseWrite()
}

// Connect dials the target multiaddr. Only the given address is kept in the
// peerstore, so libp2p never dials unreachable internal Docker addresses.
func (p *Probe) Connect(ctx context.Context, multiaddr string) error {
	maddr, err := ma.NewMultiaddr(multiaddr)
	if err != nil {
		return fmt.Errorf("parse multiaddr: %w", err)
	}
	peerInfo, err := peer.AddrInfoFromP2pAddr(maddr)
	if err != nil {
		return fmt.Errorf("extract peer info: %w", err)
	}

	p.maddr = maddr
	p.peerInfo = peerInfo

	if err := p.host.Connect(ctx, *peerInfo); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	p.host.Peerstore().ClearAddrs(peerInfo.ID)
	p.host.Peerstore().AddAddrs(peerInfo.ID, peerInfo.Addrs, time.Hour)
	return nil
}

// EnsureConnected reconnects if the connection dropped, replacing the host
// when dial backoff makes the existing one unusable.
func (p *Probe) EnsureConnected(ctx context.Context) error {
	if p.peerInfo == nil {
		return fmt.Errorf("not connected: call Connect first")
	}
	if len(p.host.Network().ConnsToPeer(p.peerInfo.ID)) > 0 {
		return nil
	}

	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := p.host.Connect(connectCtx, *p.peerInfo)
	cancel()
	if err == nil {
		p.host.Peerstore().ClearAddrs(p.peerInfo.ID)
		p.host.Peerstore().AddAddrs(p.peerInfo.ID, p.peerInfo.Addrs, time.Hour)
		return nil
	}

	p.host.Close()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		newHost, hostErr := newHost()
		if hostErr != nil {
			lastErr = hostErr
			continue
		}
		p.host = newHost
		p.resetPublisher()
		if p.statusSet {
			p.InstallStatusHandlers(p.statusV1SSZ, p.statusV2SSZ)
		}

		connectCtx, cancel2 := context.WithTimeout(ctx, 15*time.Second)
		connectErr := p.host.Connect(connectCtx, *p.peerInfo)
		cancel2()
		if connectErr != nil {
			p.host.Close()
			lastErr = connectErr
			continue
		}
		p.host.Peerstore().ClearAddrs(p.peerInfo.ID)
		p.host.Peerstore().AddAddrs(p.peerInfo.ID, p.peerInfo.Addrs, time.Hour)
		return nil
	}
	return fmt.Errorf("reconnect failed after 3 attempts: %w", lastErr)
}

// RotateIdentity replaces the probe host with a fresh identity and
// reconnects to the same target. This yields fresh peer-ID-keyed state on
// the target (req/resp limiters, bad-response scores); IP-keyed state on
// some clients intentionally survives it.
func (p *Probe) RotateIdentity(ctx context.Context) error {
	if p.peerInfo == nil {
		return fmt.Errorf("not connected: call Connect first")
	}
	newHost, err := newHost()
	if err != nil {
		return err
	}
	old := p.host
	p.host = newHost
	p.resetPublisher()
	if p.statusSet {
		p.InstallStatusHandlers(p.statusV1SSZ, p.statusV2SSZ)
	}
	old.Close()

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := p.host.Connect(connectCtx, *p.peerInfo); err != nil {
		return fmt.Errorf("connect after rotation: %w", err)
	}
	p.host.Peerstore().ClearAddrs(p.peerInfo.ID)
	p.host.Peerstore().AddAddrs(p.peerInfo.ID, p.peerInfo.Addrs, time.Hour)
	return nil
}

// SendAndReceive opens a stream, sends the request body, closes the write
// side, and reads the whole response within the timeout.
func (p *Probe) SendAndReceive(ctx context.Context, protocolID string, body []byte, timeout time.Duration) ([]byte, time.Duration, error) {
	resp, _, dur, err := p.SendAndReceiveWithTTFB(ctx, protocolID, body, timeout)
	return resp, dur, err
}

// SendAndReceiveWithTTFB additionally reports the time to the first
// response byte.
func (p *Probe) SendAndReceiveWithTTFB(ctx context.Context, protocolID string, body []byte, timeout time.Duration) ([]byte, time.Duration, time.Duration, error) {
	stream, err := p.openStream(ctx, protocolID)
	if err != nil {
		return nil, 0, 0, err
	}
	defer stream.Close()

	start := time.Now()
	if len(body) > 0 {
		if _, err := stream.Write(body); err != nil {
			return nil, 0, 0, fmt.Errorf("write: %w", err)
		}
	}
	if err := stream.CloseWrite(); err != nil {
		return nil, 0, 0, fmt.Errorf("close write: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(timeout))

	var resp []byte
	var ttfb time.Duration
	buf := make([]byte, 64*1024)
	for {
		n, readErr := stream.Read(buf)
		if n > 0 {
			if ttfb == 0 {
				ttfb = time.Since(start)
			}
			resp = append(resp, buf[:n]...)
		}
		if readErr != nil {
			// A deadline or reset after data is still a failed exchange,
			// but the caller decides based on whether resp has content.
			if readErr == io.EOF {
				return resp, ttfb, time.Since(start), nil
			}
			return resp, ttfb, time.Since(start), fmt.Errorf("read: %w", readErr)
		}
	}
}

// OpenStream opens a raw libp2p stream to the target without writing, for
// fine-grained multi-step interactions.
func (p *Probe) OpenStream(ctx context.Context, protocolID string) (network.Stream, error) {
	return p.openStream(ctx, protocolID)
}

// SendOnly sends the body without reading the response (server timeout tests).
func (p *Probe) SendOnly(ctx context.Context, protocolID string, body []byte) (network.Stream, error) {
	stream, err := p.openStream(ctx, protocolID)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		if _, err := stream.Write(body); err != nil {
			stream.Close()
			return nil, fmt.Errorf("write: %w", err)
		}
	}
	stream.CloseWrite()
	return stream, nil
}

// SendSlowly sends the body byte-by-byte with a delay (slow-client testing).
// The loop respects ctx cancellation so a cancelled/timeout-bound test never
// waits longer than its own deadline.
func (p *Probe) SendSlowly(ctx context.Context, protocolID string, body []byte, delayPerByte, timeout time.Duration) ([]byte, error) {
	stream, err := p.openStream(ctx, protocolID)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	for _, b := range body {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("slow send cancelled: %w", ctx.Err())
		case <-time.After(delayPerByte):
		}
		if _, err := stream.Write([]byte{b}); err != nil {
			return nil, fmt.Errorf("slow write: %w", err)
		}
	}
	stream.CloseWrite()

	_ = stream.SetReadDeadline(time.Now().Add(timeout))
	resp, readErr := io.ReadAll(stream)
	if readErr != nil && readErr != io.EOF {
		return resp, fmt.Errorf("read after slow send: %w", readErr)
	}
	return resp, nil
}

func (p *Probe) openStream(ctx context.Context, protocolID string) (network.Stream, error) {
	if err := p.EnsureConnected(ctx); err != nil {
		return nil, err
	}
	streamCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream, err := p.host.NewStream(streamCtx, p.peerInfo.ID, protocol.ID(protocolID))
	if err != nil {
		return nil, fmt.Errorf("open stream %s: %w", protocolID, err)
	}
	return stream, nil
}

// Multiaddr returns the target multiaddr.
func (p *Probe) Multiaddr() string {
	if p.maddr != nil {
		return p.maddr.String()
	}
	return ""
}

// PeerID returns the target peer ID.
func (p *Probe) PeerID() string {
	if p.peerInfo != nil {
		return p.peerInfo.ID.String()
	}
	return ""
}

// OwnPeerID returns the probe's own peer ID (changes on RotateIdentity).
func (p *Probe) OwnPeerID() string { return p.host.ID().String() }

// ListenAddr returns the probe's own dialable address.
func (p *Probe) ListenAddr() string {
	addrs := p.host.Addrs()
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0].String() + "/p2p/" + p.host.ID().String()
}

// Host returns the underlying libp2p host.
func (p *Probe) Host() host.Host { return p.host }

// Close shuts down the probe host.
func (p *Probe) Close() error {
	if p.pub != nil {
		p.pub.Close()
		p.pub = nil
	}
	return p.host.Close()
}
