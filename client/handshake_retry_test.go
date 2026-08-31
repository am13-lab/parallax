package client_test

import (
	"context"
	"testing"
	"time"

	"parallax/client"
	"parallax/testnode"
)

func TestHandshakeRetriesUntilProtocolServed(t *testing.T) {
	// Node starts WITHOUT the status protocols (a client still
	// initializing); the handshake must retry until it is served.
	statusV1 := "/eth2/beacon_chain/req/status/1/ssz_snappy"
	n, err := testnode.Start(&testnode.Config{
		Protocols: map[string]*testnode.Script{},
		Beacon:    &testnode.BeaconConfig{HeadSlot: 8},
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer n.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c, err := client.New(ctx, &client.Config{
		Name: "n", ClientType: "fake", Multiaddr: n.Multiaddr(), BeaconAPI: n.BeaconURL(),
		HandshakeAttempts: 4, HandshakeBackoff: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	if got := n.Requests(statusV1); len(got) != 0 {
		t.Fatalf("no handshake expected yet: %d", len(got))
	}

	// The protocol comes up late, like a client finishing initialization.
	n.EnableProtocol(statusV1, &testnode.Script{
		Behavior: testnode.Success, Chunks: [][]byte{make([]byte, 84)}, ReadRequest: true,
	})
	if err := c.Connect(ctx, client.ModeWithStatus); err != nil {
		t.Fatalf("connect: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(n.Requests(statusV1)) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := len(n.Requests(statusV1)); got == 0 {
		t.Fatal("retrying handshake must eventually reach the node")
	}
}
