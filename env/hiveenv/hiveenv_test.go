package hiveenv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records docker invocations and returns canned output.
type fakeRunner struct {
	calls  [][]string
	out    map[string]string // "port <name> <port>" style keys
	failOn []string          // substrings: when an args join contains one, return error
}

func (f *fakeRunner) Run(args ...string) (string, error) {
	joined := strings.Join(args, " ")
	f.calls = append(f.calls, args)
	for _, frag := range f.failOn {
		if strings.Contains(joined, frag) {
			return "simulated failure: " + joined, context.DeadlineExceeded
		}
	}
	if strings.HasPrefix(joined, "port ") {
		for k, v := range f.out {
			if strings.HasSuffix(joined, k) {
				return v, nil
			}
		}
		return "127.0.0.1:39999", nil
	}
	if strings.HasPrefix(joined, "inspect -f") {
		return "10.5.0.9\n", nil
	}
	return "", nil
}

func (f *fakeRunner) has(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), substr) {
			return true
		}
	}
	return false
}

func identityServer(t *testing.T, peerID string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/v1/node/identity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"peer_id":"` + peerID + `","enr":""}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func genDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"genesis.ssz": "x",
		"config.yaml": "x",
		"genesis.json": `{"timestamp":"0x6aa2785b","config":{"chainId":7}}`,
	}
	for f, body := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestSetupSmokeSequence(t *testing.T) {
	srv := identityServer(t, "16Uiu2HAmTestPeer")
	fake := &fakeRunner{}
	p := &Provider{
		Runner: fake,
		Probe: func(url string) bool { return true },
		Identity: func(base string) (string, error) {
			// point identity at the test server regardless of mapped port
			pid, _, err := fetchIdentity(srv.URL)
			return pid, err
		},
	}
	e, err := p.Setup(context.Background(), Config{
		Enclave:     "smoke",
		GenDir:      genDir(t),
		ClientTypes: []string{"lighthouse"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// orchestration order: sweep leftovers, network, geth, lighthouse
	if !fake.has("ps -aq --filter name=^/smoke-") {
		t.Fatal("missing leftover-container sweep")
	}
	if !fake.has("network create smoke-net") {
		t.Fatal("missing network create")
	}
	if !fake.has("run -d --name smoke-geth") {
		t.Fatal("missing geth launch")
	}
	if !fake.has("HIVE_TERMINAL_TOTAL_DIFFICULTY=0") {
		t.Fatal("geth must run post-merge (TTD env)")
	}
	// The mapper rebuilds the chain config from env, discarding the
	// genesis.json config; fork times must be re-fed.
	if !fake.has("HIVE_SHANGHAI_TIMESTAMP=") || !fake.has("HIVE_CANCUN_TIMESTAMP=") {
		t.Fatal("geth must receive the shanghai/cancun activation times")
	}
	if !fake.has("HIVE_CHAIN_ID=7") {
		t.Fatal("geth must receive the chain id")
	}
	if !fake.has("-p 8545") {
		t.Fatal("geth must publish the http port")
	}
	if !fake.has("genesis.json.src") || !fake.has("exec /geth.sh") {
		t.Fatal("geth genesis must stage-copy then exec the entrypoint script")
	}
	if !fake.has("-p 4000") || !fake.has("-p 9000/udp") {
		t.Fatal("lighthouse must publish api and p2p ports")
	}
	if !fake.has("-v ") && !fake.has("genesis.ssz") && !fake.has("/hive/input/genesis.ssz") {
		t.Fatal("lighthouse must mount /hive/input/genesis.ssz")
	}
	if !fake.has("HIVE_ETH2_MERGE_ENABLED=1") {
		t.Fatal("lighthouse must enable merge mode")
	}
	if !fake.has("HIVE_ETH2_ETH1_ENGINE_RPC_ADDRS=http://10.5.0.9:8551") {
		t.Fatal("lighthouse must dial the engine by container IP (authrpc rejects domain Host headers)")
	}

	eps := e.Endpoints()
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	if eps[0].ClientType != "lighthouse" || eps[0].Name != "smoke-cl-1-lighthouse" {
		t.Fatalf("endpoint mismatch: %+v", eps[0])
	}
	if !strings.HasSuffix(eps[0].Multiaddr, "/p2p/16Uiu2HAmTestPeer") {
		t.Fatalf("multiaddr missing peer id: %s", eps[0].Multiaddr)
	}

	// teardown removes both containers and the network
	if err := e.Teardown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fake.has("rm -f smoke-geth") || !fake.has("rm -f smoke-cl-1-lighthouse") {
		t.Fatal("teardown must remove containers")
	}
	if !fake.has("network rm smoke-net") {
		t.Fatal("teardown must remove the network")
	}
}

func TestSetupMissingGenDirFails(t *testing.T) {
	p := &Provider{Runner: &fakeRunner{}}
	if _, err := p.Setup(context.Background(), Config{
		Enclave: "x",
		GenDir:  filepath.Join(t.TempDir(), "absent"),
	}); err == nil {
		t.Fatal("missing genesis dir must fail with a hivegen hint")
	}
}

func TestSetupUnknownClientFails(t *testing.T) {
	p := &Provider{
		Runner: &fakeRunner{},
		Probe:  func(url string) bool { return true },
	}
	if _, err := p.Setup(context.Background(), Config{
		Enclave:     "x",
		GenDir:      genDir(t),
		ClientTypes: []string{"nosuchclient"},
	}); err == nil || !strings.Contains(err.Error(), "no hive client profile") {
		t.Fatalf("unknown client must fail with profile hint: %v", err)
	}
}
