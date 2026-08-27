package staticenv_test

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	"libp2p-difftest/env"
	"libp2p-difftest/env/staticenv"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clients.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func peerIDString(t *testing.T) string {
	t.Helper()
	priv, _, err := crypto.GenerateSecp256k1Key(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := peer.IDFromPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return id.String()
}

func TestLoadAndAttach(t *testing.T) {
	id1 := peerIDString(t)
	path := writeConfig(t, fmt.Sprintf(`clients:
  - name: prysm-1
    client_type: prysm
    multiaddr: /ip4/127.0.0.1/tcp/46562/p2p/%s
    beacon_api: http://127.0.0.1:45554
    proxy_addrs:
      - /ip4/127.0.0.1/tcp/47000/p2p/%s
  - name: lighthouse-1
    client_type: lighthouse
    multiaddr: /ip4/127.0.0.1/tcp/46564/p2p/%s
`, id1, id1, id1))

	cfg, err := staticenv.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("clients: %d", len(cfg.Clients))
	}

	e, err := staticenv.New(cfg)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	eps := e.Endpoints()
	if len(eps) != 2 {
		t.Fatalf("endpoints: %d", len(eps))
	}
	if eps[0].Name != "prysm-1" || eps[0].ClientType != "prysm" {
		t.Fatalf("endpoint 0: %+v", eps[0])
	}
	if len(eps[0].Proxies) != 1 {
		t.Fatalf("proxies must map: %+v", eps[0])
	}
	if e.Info()["provider"] != "static" {
		t.Fatalf("info: %v", e.Info())
	}

	// Logs are unsupported and treated as a capability gap.
	if _, err := e.Logs(context.Background(), eps[0], time.Now()); !errors.Is(err, env.ErrLogsUnsupported) {
		t.Fatalf("logs: %v", err)
	}
	if err := e.Teardown(context.Background()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
}

func TestLoadRejectsBadMultiaddr(t *testing.T) {
	path := writeConfig(t, `clients:
  - name: bad
    client_type: prysm
    multiaddr: totally-not-a-multiaddr
`)
	cfg, err := staticenv.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, err := staticenv.New(cfg); err == nil {
		t.Fatal("invalid multiaddr must fail attach")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := staticenv.Load("/nonexistent/clients.yaml"); err == nil {
		t.Fatal("missing file must error")
	}
}
