// Package client implements runner.Client on top of the probe (libp2p) and
// beacon (HTTP API) packages: connection lifecycle, Status handshake,
// identity and proxy rotation, and gossip verdict observation.
package client

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"libp2p-difftest/beacon"
	"libp2p-difftest/env"
	"libp2p-difftest/probe"
	"libp2p-difftest/runner"
	"libp2p-difftest/wire"
)

// ConnectMode alias so callers do not need to import runner for basic use.
type Mode = runner.ConnectMode

const (
	ModeWithStatus = runner.ConnectWithStatus
	ModeNoStatus   = runner.ConnectNoStatus
)

// Config configures one client target.
type Config struct {
	Name       string
	ClientType string
	Multiaddr  string
	BeaconAPI  string
	Proxies    []string
	Mode       Mode
	Logger     *slog.Logger
}

// Client is one testable consensus node.
type Client struct {
	name       string
	clientType string
	directAddr string
	proxies    []string
	proxyIdx   int // -1 = direct
	beaconAPI  string
	mode       Mode
	log        *slog.Logger

	probe *probe.Probe
	state *beacon.NodeState

	statusV1 []byte
	statusV2 []byte
	hasState bool

	mu       sync.Mutex
	observer *probe.Observer
}

// New creates a client: fetches chain state, connects, and performs the
// Status handshake (unless ModeNoStatus).
func New(ctx context.Context, cfg *Config) (*Client, error) {
	c := &Client{
		name:       cfg.Name,
		clientType: cfg.ClientType,
		directAddr: cfg.Multiaddr,
		proxies:    cfg.Proxies,
		proxyIdx:   -1,
		beaconAPI:  cfg.BeaconAPI,
		mode:       cfg.Mode,
		log:        cfg.Logger,
	}
	if c.log == nil {
		c.log = slog.Default()
	}

	if c.beaconAPI != "" {
		bc := beacon.New(c.beaconAPI)
		state, err := bc.State(ctx)
		if err == nil {
			c.state = state
			c.hasState = true
			c.statusV1 = beacon.BuildStatusSSZ(state)
			c.statusV2 = beacon.BuildStatusSSZV2(state)
		} else {
			c.log.Warn("beacon state unavailable", "client", c.name, "err", err)
		}
	}

	p, err := probe.New()
	if err != nil {
		return nil, fmt.Errorf("create probe for %s: %w", c.name, err)
	}
	if c.hasState {
		p.InstallStatusHandlers(c.statusV1, c.statusV2)
	}
	if err := p.Connect(ctx, c.currentAddr()); err != nil {
		p.Close()
		return nil, fmt.Errorf("connect to %s: %w", c.name, err)
	}
	c.probe = p

	if c.mode == ModeWithStatus && c.hasState {
		c.statusHandshake(ctx)
	}
	return c, nil
}

func (c *Client) currentAddr() string {
	if len(c.proxies) > 0 {
		idx := c.proxyIdx
		if idx < 0 {
			idx = 0
		}
		return c.proxies[idx%len(c.proxies)]
	}
	return c.directAddr
}

func (c *Client) statusHandshake(ctx context.Context) {
	for _, proto := range []string{"/eth2/beacon_chain/req/status/1/ssz_snappy", "/eth2/beacon_chain/req/status/2/ssz_snappy"} {
		body := c.statusV1
		if strings.HasSuffix(proto, "/2/") {
			body = c.statusV2
		}
		_, _, err := c.probe.SendAndReceive(ctx, proto, wire.BuildSSZSnappy(body), 5*time.Second)
		if err != nil {
			c.log.Warn("status handshake failed (non-fatal)", "client", c.name, "protocol", proto, "err", err)
		}
	}
}

// Name returns the display name.
func (c *Client) Name() string { return c.name }

// Type returns the normalized client type.
func (c *Client) Type() string { return c.clientType }

// OwnPeerID returns the probe's current peer ID.
func (c *Client) OwnPeerID() string { return c.probe.OwnPeerID() }

// ReqResp sends one request and reads the full response.
func (c *Client) ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*runner.ReqRespResult, error) {
	if err := c.probe.EnsureConnected(ctx); err != nil {
		if cerr := c.reconnect(ctx); cerr != nil {
			return &runner.ReqRespResult{
				Error:       fmt.Sprintf("reconnect failed: %s (original: %s)", cerr, err),
				StreamReset: true,
			}, nil
		}
	}

	resp, ttfb, dur, err := c.probe.SendAndReceiveWithTTFB(ctx, protocol, body, timeout)

	result := &runner.ReqRespResult{
		RawBytes:        resp,
		Duration:        dur,
		TimeToFirstByte: ttfb,
	}
	if err != nil {
		result.Error = err.Error()
		if len(resp) == 0 {
			result.StreamReset = true
		}
		// Connection-level failure despite EnsureConnected: reconnect once
		// through the next address and retry a single time.
		if len(resp) == 0 && isStreamOpenFailure(err.Error()) {
			if cerr := c.reconnect(ctx); cerr == nil {
				resp2, ttfb2, dur2, err2 := c.probe.SendAndReceiveWithTTFB(ctx, protocol, body, timeout)
				if err2 == nil {
					result = &runner.ReqRespResult{
						RawBytes:        resp2,
						Duration:        dur2,
						TimeToFirstByte: ttfb2,
					}
				}
			}
		}
	}

	if len(result.RawBytes) > 0 {
		result.ResponseChunks = wire.ParseReqRespResponse(result.RawBytes)
	}
	return result, nil
}

func isStreamOpenFailure(msg string) bool {
	return strings.Contains(msg, "connection failed") ||
		strings.Contains(msg, "connection closed") ||
		strings.Contains(msg, "all dials failed")
}

// PublishGossip publishes a raw payload on the topic.
func (c *Client) PublishGossip(ctx context.Context, topic string, data []byte) error {
	return c.probe.Publish(topic, data)
}

// PrepareGossipTopic joins the topic ahead of publishing.
func (c *Client) PrepareGossipTopic(ctx context.Context, topic string) error {
	return c.probe.PrepareGossipTopic(topic)
}

// ObserveGossip watches the topic via a target-only observer, publishes the
// payload, and waits for the target to re-propagate it.
func (c *Client) ObserveGossip(ctx context.Context, topic string, data []byte, wait time.Duration) (runner.GossipVerdict, error) {
	obs, err := c.ensureObserver()
	if err != nil {
		return runner.VerdictUnknown, fmt.Errorf("observer: %w", err)
	}
	if err := obs.Watch(topic); err != nil {
		return runner.VerdictUnknown, fmt.Errorf("watch %s: %w", topic, err)
	}
	if err := c.PublishGossip(ctx, topic, data); err != nil {
		return runner.VerdictUnknown, fmt.Errorf("publish %s: %w", topic, err)
	}

	since := time.Now()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return runner.VerdictUnknown, ctx.Err()
		}
		if obs.Saw(topic, data, since) {
			return runner.VerdictAccept, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return runner.VerdictReject, nil
}

func (c *Client) ensureObserver() (*probe.Observer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observer != nil {
		return c.observer, nil
	}
	obs, err := probe.NewObserver(c.probe.Multiaddr(), c.statusV1, c.statusV2)
	if err != nil {
		return nil, err
	}
	c.observer = obs
	return obs, nil
}

// Connect (re-)establishes the connection in the given mode. WithStatus
// reuses the existing connection when alive and performs the handshake;
// NoStatus always builds a fresh connection without any handshake, for
// pre-Status request tests.
func (c *Client) Connect(ctx context.Context, mode runner.ConnectMode) error {
	c.mode = mode
	if mode == ModeNoStatus {
		return c.freshConnect(ctx, false)
	}
	if err := c.probe.EnsureConnected(ctx); err == nil {
		if c.hasState {
			c.statusHandshake(ctx)
		}
		return nil
	}
	return c.freshConnect(ctx, true)
}

func (c *Client) freshConnect(ctx context.Context, handshake bool) error {
	c.mu.Lock()
	if c.observer != nil {
		c.observer.Close()
		c.observer = nil
	}
	c.mu.Unlock()

	newProbe, err := probe.New()
	if err != nil {
		return err
	}
	if c.hasState && handshake {
		newProbe.InstallStatusHandlers(c.statusV1, c.statusV2)
	}
	if err := newProbe.Connect(ctx, c.currentAddr()); err != nil {
		newProbe.Close()
		return err
	}
	c.probe.Close()
	c.probe = newProbe
	return nil
}

// RotateIdentity replaces the probe identity, cycling to the next proxy
// address when proxies are configured.
func (c *Client) RotateIdentity(ctx context.Context) error {
	if len(c.proxies) > 0 {
		c.proxyIdx++
		if c.proxyIdx >= len(c.proxies) {
			c.proxyIdx = 0 // cycle within the proxy list
		}
	} else {
		c.proxyIdx = -1
	}

	c.mu.Lock()
	if c.observer != nil {
		c.observer.Close()
		c.observer = nil
	}
	c.mu.Unlock()

	newProbe, err := probe.New()
	if err != nil {
		return fmt.Errorf("fresh probe: %w", err)
	}
	if c.hasState {
		newProbe.InstallStatusHandlers(c.statusV1, c.statusV2)
	}
	if err := newProbe.Connect(ctx, c.currentAddr()); err != nil {
		newProbe.Close()
		return fmt.Errorf("connect after rotation via %s: %w", c.currentAddr(), err)
	}
	c.probe.Close()
	c.probe = newProbe

	if c.mode == ModeWithStatus && c.hasState {
		c.statusHandshake(ctx)
	}
	return nil
}

func (c *Client) reconnect(ctx context.Context) error {
	if err := c.probe.Connect(ctx, c.currentAddr()); err == nil {
		return nil
	}
	// Fresh host to escape dial backoff.
	newProbe, err := probe.New()
	if err != nil {
		return err
	}
	if c.hasState {
		newProbe.InstallStatusHandlers(c.statusV1, c.statusV2)
	}
	if err := newProbe.Connect(ctx, c.currentAddr()); err != nil {
		newProbe.Close()
		return err
	}
	c.probe.Close()
	c.probe = newProbe
	return nil
}

// Health checks liveness via the Beacon API, falling back to the libp2p
// connection when no API is configured.
func (c *Client) Health(ctx context.Context) error {
	if c.beaconAPI != "" {
		return beacon.New(c.beaconAPI).Health(ctx)
	}
	return c.probe.EnsureConnected(ctx)
}

// State returns the cached chain state, or ErrNoBeaconAPI.
func (c *Client) State(ctx context.Context) (*beacon.NodeState, error) {
	if !c.hasState {
		return nil, runner.ErrNoBeaconAPI
	}
	return c.state, nil
}

// Snapshot collects a resource snapshot from the Beacon API.
func (c *Client) Snapshot(ctx context.Context) (*beacon.ResourceSnapshot, error) {
	if c.beaconAPI == "" {
		snap := &beacon.ResourceSnapshot{Timestamp: time.Now()}
		snap.BeaconAPIError = "no beacon API configured"
		return snap, nil
	}
	return beacon.New(c.beaconAPI).Snapshot(ctx)
}

// Close releases all resources.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.observer != nil {
		c.observer.Close()
		c.observer = nil
	}
	c.mu.Unlock()
	if c.probe != nil {
		return c.probe.Close()
	}
	return nil
}

// Endpoint returns the env.Endpoint describing this client.
func (c *Client) Endpoint() env.Endpoint {
	return env.Endpoint{
		Name:       c.name,
		ClientType: c.clientType,
		Multiaddr:  c.directAddr,
		BeaconAPI:  c.beaconAPI,
		Proxies:    c.proxies,
	}
}
