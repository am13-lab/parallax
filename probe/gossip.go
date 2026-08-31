package probe

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
	pubsubpb "github.com/libp2p/go-libp2p-pubsub/pb"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"

	"parallax/wire"
)

// GossipMessageID computes the spec gossipsub message id; see wire.GossipMessageID.
func GossipMessageID(topic string, data []byte) []byte {
	return wire.GossipMessageID(topic, data)
}

func gossipMsgIDOption() pubsub.Option {
	return pubsub.WithMessageIdFn(func(pmsg *pubsubpb.Message) string {
		return string(GossipMessageID(pmsg.GetTopic(), pmsg.GetData()))
	})
}

// Publisher is a gossipsub router on the probe host for message injection.
type Publisher struct {
	ps     *pubsub.PubSub
	topics map[string]*pubsub.Topic
	subs   map[string]*pubsub.Subscription
	mu     sync.Mutex
}

func newPublisher(h host.Host, peers []peer.AddrInfo) (*Publisher, error) {
	ps, err := pubsub.NewGossipSub(context.Background(), h,
		pubsub.WithDirectPeers(peers),
		pubsub.WithPeerExchange(false),
		pubsub.WithFloodPublish(true),
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		gossipMsgIDOption(),
	)
	if err != nil {
		return nil, fmt.Errorf("create gossipsub: %w", err)
	}
	return &Publisher{
		ps:     ps,
		topics: make(map[string]*pubsub.Topic),
		subs:   make(map[string]*pubsub.Subscription),
	}, nil
}

// PrepareGossipTopic joins the topic and propagates a subscription. The
// first join waits one gossipsub heartbeat so the target can graft us into
// its mesh before any publish.
func (p *Probe) PrepareGossipTopic(topic string) error {
	pub, err := p.ensurePublisher()
	if err != nil {
		return err
	}
	_, created, err := pub.ensureTopic(topic)
	if err == nil && created {
		time.Sleep(meshWarmup)
	}
	return err
}

// Publish sends data on the topic (raw snappy block), joining if needed.
func (p *Probe) Publish(topic string, data []byte) error {
	pub, err := p.ensurePublisher()
	if err != nil {
		return err
	}
	t, created, err := pub.ensureTopic(topic)
	if err != nil {
		return err
	}
	if created {
		time.Sleep(meshWarmup)
	}
	return t.Publish(context.Background(), data)
}

func (p *Probe) ensurePublisher() (*Publisher, error) {
	p.muPub.Lock()
	defer p.muPub.Unlock()
	if p.pub != nil {
		return p.pub, nil
	}
	var peers []peer.AddrInfo
	for _, pid := range p.host.Network().Peers() {
		peers = append(peers, peer.AddrInfo{ID: pid})
	}
	pub, err := newPublisher(p.host, peers)
	if err != nil {
		return nil, err
	}
	p.pub = pub
	return pub, nil
}

func (p *Probe) resetPublisher() {
	p.muPub.Lock()
	defer p.muPub.Unlock()
	if p.pub != nil {
		p.pub.Close()
		p.pub = nil
	}
}

// meshWarmup is one gossipsub heartbeat plus margin: the time a freshly
// joined peer needs before the target grafts it onto the topic mesh.
const meshWarmup = 1200 * time.Millisecond

func (g *Publisher) ensureTopic(topicStr string) (*pubsub.Topic, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if t, ok := g.topics[topicStr]; ok {
		return t, false, nil
	}
	t, err := g.ps.Join(topicStr)
	if err != nil {
		return nil, false, fmt.Errorf("join topic %s: %w", topicStr, err)
	}
	sub, err := t.Subscribe()
	if err != nil {
		t.Close()
		return nil, false, fmt.Errorf("subscribe topic %s: %w", topicStr, err)
	}
	g.topics[topicStr] = t
	g.subs[topicStr] = sub
	return t, true, nil
}

// Close cancels subscriptions and closes topics.
func (g *Publisher) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, sub := range g.subs {
		sub.Cancel()
	}
	for _, t := range g.topics {
		t.Close()
	}
	g.topics = make(map[string]*pubsub.Topic)
	g.subs = make(map[string]*pubsub.Subscription)
}

// Observer is a second libp2p host connected only to the target. Any message
// it receives on a topic must have been re-propagated by the target, which
// means the target validated and accepted it. A negative (nothing received
// within the window) is weaker: reject, ignore, or the target never grafted
// us into the mesh.
type Observer struct {
	inner  *Probe
	ps     *pubsub.PubSub
	target peer.ID

	mu     sync.Mutex
	topics map[string]*pubsub.Topic
	subs   map[string]*pubsub.Subscription
	seen   map[string]time.Time
	warmed bool
}

// NewObserver creates the target-only observer host with optional Status
// responders so the target does not Goodbye it before the mesh forms.
func NewObserver(targetMultiaddr string, statusV1, statusV2 []byte) (*Observer, error) {
	inner, err := New()
	if err != nil {
		return nil, fmt.Errorf("observer probe: %w", err)
	}
	if len(statusV1) > 0 || len(statusV2) > 0 {
		inner.InstallStatusHandlers(statusV1, statusV2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := inner.Connect(ctx, targetMultiaddr); err != nil {
		inner.Close()
		return nil, fmt.Errorf("observer connect: %w", err)
	}

	target := inner.peerInfo.ID
	ps, err := pubsub.NewGossipSub(context.Background(), inner.host,
		pubsub.WithPeerExchange(false),
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		pubsub.WithDirectPeers([]peer.AddrInfo{{ID: target}}),
		gossipMsgIDOption(),
	)
	if err != nil {
		inner.Close()
		return nil, fmt.Errorf("observer gossipsub: %w", err)
	}

	return &Observer{
		inner:  inner,
		ps:     ps,
		target: target,
		topics: make(map[string]*pubsub.Topic),
		subs:   make(map[string]*pubsub.Subscription),
		seen:   make(map[string]time.Time),
	}, nil
}

// Watch joins and subscribes the topic (idempotent). The first watch blocks
// for a mesh warmup so the target has time to graft us.
func (o *Observer) Watch(topicStr string) error {
	o.mu.Lock()
	if _, ok := o.subs[topicStr]; ok {
		o.mu.Unlock()
		return nil
	}
	first := !o.warmed
	o.mu.Unlock()

	topic, err := o.ps.Join(topicStr)
	if err != nil {
		return fmt.Errorf("observer join %s: %w", topicStr, err)
	}
	sub, err := topic.Subscribe()
	if err != nil {
		topic.Close()
		return fmt.Errorf("observer subscribe %s: %w", topicStr, err)
	}

	o.mu.Lock()
	o.topics[topicStr] = topic
	o.subs[topicStr] = sub
	o.warmed = true
	o.mu.Unlock()

	go o.readLoop(sub)

	if first {
		time.Sleep(2 * time.Second)
	} else {
		time.Sleep(700 * time.Millisecond)
	}
	return nil
}

func (o *Observer) readLoop(sub *pubsub.Subscription) {
	for {
		msg, err := sub.Next(context.Background())
		if err != nil {
			return
		}
		key := hex.EncodeToString(GossipMessageID(msg.GetTopic(), msg.GetData()))
		o.mu.Lock()
		o.seen[key] = time.Now()
		o.mu.Unlock()
	}
}

// Saw reports whether the target forwarded the given topic/data at or after
// the given time.
func (o *Observer) Saw(topicStr string, data []byte, since time.Time) bool {
	key := hex.EncodeToString(GossipMessageID(topicStr, data))
	o.mu.Lock()
	t, ok := o.seen[key]
	o.mu.Unlock()
	return ok && !t.Before(since)
}

// Close shuts the observer down.
func (o *Observer) Close() error {
	o.mu.Lock()
	for _, sub := range o.subs {
		sub.Cancel()
	}
	for _, t := range o.topics {
		t.Close()
	}
	o.subs = make(map[string]*pubsub.Subscription)
	o.topics = make(map[string]*pubsub.Topic)
	o.mu.Unlock()
	return o.inner.Close()
}
