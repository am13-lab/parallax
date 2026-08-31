package kurtosisenv_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"parallax/env"
	"parallax/env/kurtosisenv"
)

// fake API client.
type fakeAPI struct {
	mu         sync.Mutex
	services   []kurtosisenv.ServiceInfo
	logs       map[string][]string
	provisions []string // args files seen
	failHTTP   bool
}

func (f *fakeAPI) ListCLServices(ctx context.Context, enclave string) ([]kurtosisenv.ServiceInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failHTTP {
		return nil, errors.New("enclave not found")
	}
	out := make([]kurtosisenv.ServiceInfo, len(f.services))
	copy(out, f.services)
	return out, nil
}

func (f *fakeAPI) Logs(ctx context.Context, enclave, service string, since time.Time) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logs[service], nil
}

func (f *fakeAPI) Provision(ctx context.Context, enclaveName, argsFile string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.provisions = append(f.provisions, argsFile)
	return nil
}

func (f *fakeAPI) Destroy(ctx context.Context, enclaveName string) error { return nil }

// beaconServer answers /eth/v1/node/identity with a fixed peer ID.
func beaconServer(t *testing.T, peerID string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/node/identity", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"peer_id": peerID, "enr": ""},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

const validPeerID = "16Uiu2HAmPDunVHhEmpkswudvcraieeesLQVZrg7RMVgcrotboWqf"

func TestDeriveClientType(t *testing.T) {
	cases := map[string]string{
		"cl-1-prysm-geth":      "prysm",
		"cl-2-lodestar-geth":   "lodestar",
		"cl-1-caplin-erigon":   "caplin",
		"cl-3-grandine-geth":   "grandine",
		"cl-10-nimbus-geth":    "nimbus",
		"cl-1-teku-besu":       "teku",
		"cl-1-lighthouse-geth": "lighthouse",
	}
	for name, want := range cases {
		if got := kurtosisenv.DeriveClientType(name); got != want {
			t.Errorf("DeriveClientType(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestServicesToEndpoints(t *testing.T) {
	_ = beaconServer(t, validPeerID) // not hit: fetcher is injected
	svcs := []kurtosisenv.ServiceInfo{
		{
			Name:     "cl-1-prysm-geth",
			PublicIP: "127.0.0.1",
			Ports:    map[string]uint16{"tcp-discovery": 46562, "http": 45554},
		},
		{
			Name:     "cl-2-lodestar-geth",
			PublicIP: "127.0.0.1",
			Ports:    map[string]uint16{"tcp-discovery": 46566, "http": 45558},
		},
	}

	eps, err := kurtosisenv.ServicesToEndpoints(svcs, func(url string) (string, error) {
		return validPeerID, nil
	})
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("endpoints: %d", len(eps))
	}
	ep := eps[0]
	if ep.Name != "cl-1-prysm-geth" || ep.ClientType != "prysm" {
		t.Fatalf("ep0 identity: %+v", ep)
	}
	if ep.Multiaddr != "/ip4/127.0.0.1/tcp/46562/p2p/"+validPeerID {
		t.Fatalf("multiaddr: %s", ep.Multiaddr)
	}
	if ep.BeaconAPI != "http://127.0.0.1:45554" {
		t.Fatalf("beacon api: %s", ep.BeaconAPI)
	}
	if ep.Service != "cl-1-prysm-geth" {
		t.Fatalf("service id: %s", ep.Service)
	}
}

func TestServicesToEndpointsFetchesPeerID(t *testing.T) {
	srv := beaconServer(t, validPeerID)
	svcs := []kurtosisenv.ServiceInfo{
		{Name: "cl-1-prysm-geth", PublicIP: "127.0.0.1",
			Ports: map[string]uint16{"tcp-discovery": 46562, "http": srvPort(t, srv)}},
	}
	// Default peer-ID fetcher hits the beacon API identity endpoint.
	eps, err := kurtosisenv.ServicesToEndpoints(svcs, nil)
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if !strings.HasSuffix(eps[0].Multiaddr, validPeerID) {
		t.Fatalf("multiaddr must embed the peer id from the identity endpoint: %s", eps[0].Multiaddr)
	}
}

func TestServicesToEndpointsMissingPorts(t *testing.T) {
	svcs := []kurtosisenv.ServiceInfo{
		{Name: "cl-1-prysm-geth", PublicIP: "127.0.0.1", Ports: map[string]uint16{"http": 45554}},
	}
	if _, err := kurtosisenv.ServicesToEndpoints(svcs, nil); err == nil {
		t.Fatal("missing tcp-discovery port must error naming the service")
	}
}

func TestEnvironmentAttachAndLogs(t *testing.T) {
	fake := &fakeAPI{services: []kurtosisenv.ServiceInfo{
		{Name: "cl-1-prysm-geth", PublicIP: "127.0.0.1",
			Ports: map[string]uint16{"tcp-discovery": 46562}},
	}, logs: map[string][]string{"cl-1-prysm-geth": {"line1", "line2"}}}

	e, err := kurtosisenv.Attach(context.Background(), fake, "test-enclave")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	// The prysm service has no http port so no beacon API: endpoint still
	// exists for libp2p-only probing, but multiaddr lacks a peer ID.
	eps := e.Endpoints()
	if len(eps) != 1 || eps[0].BeaconAPI != "" {
		t.Fatalf("endpoints: %+v", eps)
	}

	rc, err := e.Logs(context.Background(), eps[0], time.Now())
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	data, _ := io.ReadAll(rc)
	rc.Close()
	if !strings.Contains(string(data), "line1") || !strings.Contains(string(data), "line2") {
		t.Fatalf("logs content: %s", data)
	}
	if e.Info()["provider"] != "kurtosis" || e.Info()["enclave"] != "test-enclave" {
		t.Fatalf("info: %v", e.Info())
	}
	if err := e.Teardown(context.Background()); err != nil {
		t.Fatalf("teardown: %v", err)
	}
}

func TestProviderProvisionFlow(t *testing.T) {
	fake := &fakeAPI{services: []kurtosisenv.ServiceInfo{}}
	p := kurtosisenv.Provider{API: fake}
	if p.Name() != "kurtosis" {
		t.Fatalf("provider name: %s", p.Name())
	}

	argsPath := "/tmp/args.yaml"
	e, err := p.Setup(context.Background(), kurtosisenv.Config{
		Enclave:   "new-enclave",
		ArgsFile:  argsPath,
		PackageID: "github.com/ethpandaops/ethereum-package",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if len(fake.provisions) != 1 || fake.provisions[0] != argsPath {
		t.Fatalf("provision calls: %v", fake.provisions)
	}
	if _, ok := e.(env.Environment); !ok {
		t.Fatal("setup must return an Environment")
	}
}

func TestAttachFailureSurfaces(t *testing.T) {
	fake := &fakeAPI{failHTTP: true}
	if _, err := kurtosisenv.Attach(context.Background(), fake, "missing"); err == nil {
		t.Fatal("attach to broken enclave must fail")
	}
}

func srvPort(t *testing.T, srv *httptest.Server) uint16 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(port)
}
