package beacon_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"libp2p-difftest/beacon"
	"libp2p-difftest/internal/testutil"
	"libp2p-difftest/wire"
)

// beaconServer serves canned responses shaped like the endpoints clients expose.
func beaconServer(t *testing.T, enrStr string, forkVersion string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/eth/v1/node/identity", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"peer_id": "16Uiu2HAmTest", "enr": enrStr},
		})
	})
	mux.HandleFunc("/eth/v1/beacon/genesis", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"genesis_validators_root": "0x" + strings.Repeat("11", 32)},
		})
	})
	mux.HandleFunc("/eth/v1/beacon/states/head/fork", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"previous_version": "0x03000000",
				"current_version":  forkVersion,
				"epoch":            "2",
			},
		})
	})
	mux.HandleFunc("/eth/v1/beacon/headers/head", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"root":      "0x" + strings.Repeat("22", 32),
				"canonical": true,
				"header": map[string]any{
					"message": map[string]any{
						"slot":           "64",
						"proposer_index": "5",
					},
				},
			},
		})
	})
	mux.HandleFunc("/eth/v1/beacon/states/head/finality_checkpoints", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"finalized": map[string]any{"epoch": "1", "root": "0x" + strings.Repeat("33", 32)},
			},
		})
	})
	mux.HandleFunc("/eth/v1/config/spec", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"GENESIS_FORK_VERSION": "0x00000000",
				"ALTAIR_FORK_VERSION":  "0x01000000",
				"ALTAIR_FORK_EPOCH":    "0",
				"SECONDS_PER_SLOT":     "12",
			},
		})
	})
	mux.HandleFunc("/eth/v1/node/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/eth/v1/node/peer_count", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"connected": "17"}})
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("# HELP process_resident_memory_bytes x\n" +
			"process_resident_memory_bytes 1.234567e+08\n" +
			"go_goroutines 42\n" +
			"process_open_fds 55\n" +
			"process_cpu_seconds_total 12.5\n"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestStateFromENRForkDigest(t *testing.T) {
	eth2 := make([]byte, 16)
	copy(eth2[0:4], []byte{0xde, 0xad, 0xbe, 0xef})
	binary.LittleEndian.PutUint64(eth2[8:16], 269568)
	enrStr := testutil.BuildTestENR(eth2, make([]byte, 8))

	srv := beaconServer(t, enrStr, "0x01000000")
	c := beacon.New(srv.URL)

	state, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !state.Valid {
		t.Fatal("state must be valid")
	}
	if state.ForkDigest != [4]byte{0xde, 0xad, 0xbe, 0xef} {
		t.Fatalf("fork digest must come from the ENR eth2 field: %x", state.ForkDigest)
	}
	if state.ENR == "" || !strings.HasPrefix(state.ENR, "enr:") {
		t.Fatalf("raw ENR must be carried on the state: %q", state.ENR)
	}
	var wantRoot [32]byte
	for i := range wantRoot {
		wantRoot[i] = 0x11
	}
	if state.GenesisValidatorRoot != wantRoot {
		t.Fatal("genesis validators root mismatch")
	}
	if state.HeadSlot != 64 {
		t.Fatalf("head slot: %d", state.HeadSlot)
	}
	var wantHead [32]byte
	for i := range wantHead {
		wantHead[i] = 0x22
	}
	if state.HeadRoot != wantHead {
		t.Fatal("head root mismatch")
	}
	if state.FinalizedEpoch != 1 {
		t.Fatalf("finalized epoch: %d", state.FinalizedEpoch)
	}
	// Head epoch = 64/32 = 2; only altair is active -> fork = altair.
	if state.Fork != "altair" {
		t.Fatalf("fork name: %q", state.Fork)
	}
	if state.ForkVersion != [4]byte{0x01, 0x00, 0x00, 0x00} {
		t.Fatalf("fork version: %x", state.ForkVersion)
	}
	if state.GenesisForkVersion != [4]byte{} {
		t.Fatalf("genesis fork version: %x", state.GenesisForkVersion)
	}
}

func TestStateForkDigestFallback(t *testing.T) {
	// Empty ENR: the digest must fall back to ComputeForkDigest(version, root).
	srv := beaconServer(t, "", "0x01000000")
	c := beacon.New(srv.URL)

	state, err := c.State(context.Background())
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	var root [32]byte
	for i := range root {
		root[i] = 0x11
	}
	want := wire.ComputeForkDigest([4]byte{0x01, 0x00, 0x00, 0x00}, root)
	if state.ForkDigest != want {
		t.Fatalf("fallback digest: got %x want %x", state.ForkDigest, want)
	}
}

func TestHealthAndSnapshot(t *testing.T) {
	srv := beaconServer(t, "", "0x01000000")
	c := beacon.New(srv.URL)

	if err := c.Health(context.Background()); err != nil {
		t.Fatalf("health: %v", err)
	}

	snap, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.PeerCount != 17 {
		t.Fatalf("peer count: %d", snap.PeerCount)
	}
	if snap.HeadSlot != 64 {
		t.Fatalf("head slot: %d", snap.HeadSlot)
	}
	if snap.RSSBytes != 123456700 {
		t.Fatalf("rss: %d", snap.RSSBytes)
	}
	if snap.Goroutines != 42 {
		t.Fatalf("goroutines: %d", snap.Goroutines)
	}
	if snap.OpenFDs != 55 {
		t.Fatalf("open fds: %d", snap.OpenFDs)
	}
	if snap.CPUSeconds != 12.5 {
		t.Fatalf("cpu: %v", snap.CPUSeconds)
	}
	if !snap.Healthy {
		t.Fatal("snapshot must report healthy")
	}
}

func TestHealthUnreachable(t *testing.T) {
	srv := beaconServer(t, "", "0x01000000")
	url := srv.URL
	srv.Close()

	c := beacon.New(url)
	if err := c.Health(context.Background()); err == nil {
		t.Fatal("unreachable node must fail health")
	}
}

func TestBuildStatusSSZLayout(t *testing.T) {
	s := &beacon.NodeState{
		ForkDigest:            [4]byte{1, 2, 3, 4},
		FinalizedRoot:         [32]byte{5},
		FinalizedEpoch:        0x1122334455667788,
		HeadRoot:              [32]byte{9},
		HeadSlot:              0x9988776655443322,
		EarliestAvailableSlot: 3,
	}
	v1 := beacon.BuildStatusSSZ(s)
	if len(v1) != 84 {
		t.Fatalf("status v1 must be 84 bytes, got %d", len(v1))
	}
	if got := binary.LittleEndian.Uint64(v1[36:44]); got != 0x1122334455667788 {
		t.Fatalf("finalized epoch field: %x", got)
	}
	if got := binary.LittleEndian.Uint64(v1[76:84]); got != 0x9988776655443322 {
		t.Fatalf("head slot field: %x", got)
	}

	v2 := beacon.BuildStatusSSZV2(s)
	if len(v2) != 92 {
		t.Fatalf("status v2 must be 92 bytes, got %d", len(v2))
	}
	if got := binary.LittleEndian.Uint64(v2[84:92]); got != 3 {
		t.Fatalf("earliest available slot field: %x", got)
	}
	if string(v2[:84]) != string(v1) {
		t.Fatal("v2 must embed v1 in its first 84 bytes")
	}
}
