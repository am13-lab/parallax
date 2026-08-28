// Package beacon is a client for the subset of the beacon node HTTP API the
// differential tests need: chain state (for Status handshakes and context
// bytes), health, and resource snapshots.
package beacon

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"libp2p-difftest/enr"
	"libp2p-difftest/wire"
)

// NodeState is the chain state needed for Status handshakes and requests.
type NodeState struct {
	ForkDigest            [4]byte
	ENR                   string // raw ENR string from the identity endpoint
	Fork                  string  // active fork name, e.g. "fulu"
	ForkVersion           [4]byte // active fork version
	GenesisForkVersion    [4]byte // genesis fork version
	GenesisValidatorRoot  [32]byte
	HeadSlot              uint64
	HeadRoot              [32]byte
	FinalizedEpoch        uint64
	FinalizedRoot         [32]byte
	EarliestAvailableSlot uint64
	Valid                 bool
}

// ResourceSnapshot captures resource utilization at a point in time.
type ResourceSnapshot struct {
	Timestamp      time.Time
	PeerCount      int
	HeadSlot       uint64
	Healthy        bool
	BeaconAPIError string
	RSSBytes       uint64
	Goroutines     int
	Tasks          int
	OpenFDs        int
	CPUSeconds     float64
}

// NodeMetadata is the /eth/v1/node/metadata payload.
type NodeMetadata struct {
	SeqNumber         uint64
	Attnets           string // 0x-hex bitvector
	Syncnets          string // 0x-hex bitvector
	CustodyGroupCount uint64
	HasCGC            bool // false on pre-Fulu nodes
}

// Metadata fetches the node's gossipsub metadata.
func (c *Client) Metadata(ctx context.Context) (*NodeMetadata, error) {
	data := c.getJSON(ctx, "/eth/v1/node/metadata")
	if data == nil {
		return nil, fmt.Errorf("metadata endpoint unavailable")
	}
	m := &NodeMetadata{}
	if v := jsonPath(data, "data", "seq_number"); v != nil {
		m.SeqNumber, _ = strconv.ParseUint(*v, 10, 64)
	}
	if v := jsonPath(data, "data", "attnets"); v != nil {
		m.Attnets = *v
	}
	if v := jsonPath(data, "data", "syncnets"); v != nil {
		m.Syncnets = *v
	}
	if v := jsonPath(data, "data", "custody_group_count"); v != nil {
		m.CustodyGroupCount, _ = strconv.ParseUint(*v, 10, 64)
		m.HasCGC = true
	}
	return m, nil
}

// Client queries one beacon node's HTTP API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New creates a client for the given base URL.
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 5 * time.Second},
	}
}

// State fetches the chain state. It returns an error only when the node is
// unreachable; partial data yields a state with Valid=false.
func (c *Client) State(ctx context.Context) (*NodeState, error) {
	s := &NodeState{}

	// Genesis validators root.
	if data := c.getJSON(ctx, "/eth/v1/beacon/genesis"); data != nil {
		if gvr := jsonPath(data, "data", "genesis_validators_root"); gvr != nil {
			if b, ok := hexBytes(*gvr, 32); ok {
				copy(s.GenesisValidatorRoot[:], b)
			}
		}
	}

	// Fork digest: prefer the ENR eth2 field (BPO forks mix extra data into
	// the digest, so recomputation is only a fallback).
	if data := c.getJSON(ctx, "/eth/v1/node/identity"); data != nil {
		if e := jsonPath(data, "data", "enr"); e != nil {
			s.ENR = *e
			if rec, err := enr.DecodeENR(*e); err == nil {
				if fid, err := rec.GetEth2(); err == nil {
					s.ForkDigest = fid.ForkDigest
				}
			}
		}
	}
	if s.ForkDigest == [4]byte{} {
		if data := c.getJSON(ctx, "/eth/v1/beacon/states/head/fork"); data != nil {
			if cv := jsonPath(data, "data", "current_version"); cv != nil {
				if b, ok := hexBytes(*cv, 4); ok {
					var fv [4]byte
					copy(fv[:], b)
					s.ForkDigest = wire.ComputeForkDigest(fv, s.GenesisValidatorRoot)
				}
			}
		}
	}

	// Head.
	if data := c.getJSON(ctx, "/eth/v1/beacon/headers/head"); data != nil {
		if root := jsonPath(data, "data", "root"); root != nil {
			if b, ok := hexBytes(*root, 32); ok {
				copy(s.HeadRoot[:], b)
			}
		}
		if slot := jsonPath(data, "data", "header", "message", "slot"); slot != nil {
			s.HeadSlot, _ = strconv.ParseUint(*slot, 10, 64)
		}
	}

	// Finality checkpoints.
	if data := c.getJSON(ctx, "/eth/v1/beacon/states/head/finality_checkpoints"); data != nil {
		if epoch := jsonPath(data, "data", "finalized", "epoch"); epoch != nil {
			s.FinalizedEpoch, _ = strconv.ParseUint(*epoch, 10, 64)
		}
		if root := jsonPath(data, "data", "finalized", "root"); root != nil {
			if b, ok := hexBytes(*root, 32); ok {
				copy(s.FinalizedRoot[:], b)
			}
		}
	}

	// Active fork name and versions from the config spec.
	if data := c.getJSON(ctx, "/eth/v1/config/spec"); data != nil {
		if d, ok := data["data"].(map[string]any); ok {
			spec := map[string]string{}
			for k, v := range d {
				if sVal, ok := v.(string); ok {
					spec[k] = sVal
				}
			}
			s.Fork = ActiveForkFromSpec(spec, s.HeadSlot)
			s.GenesisForkVersion = parseVersion4(spec["GENESIS_FORK_VERSION"])
			s.ForkVersion = parseVersion4(spec[strings.ToUpper(s.Fork)+"_FORK_VERSION"])
			if s.ForkVersion == [4]byte{} {
				s.ForkVersion = s.GenesisForkVersion // phase0 uses the genesis version
			}
		}
	}

	s.Valid = s.ForkDigest != [4]byte{}
	return s, nil
}

// Health returns nil when the node answers /eth/v1/node/health.
func (c *Client) Health(ctx context.Context) error {
	resp, err := c.get(ctx, "/eth/v1/node/health")
	if err != nil {
		return fmt.Errorf("beacon API unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 && resp.StatusCode != 206 {
		return fmt.Errorf("beacon API unhealthy: status %d", resp.StatusCode)
	}
	return nil
}

// Snapshot collects peer count, head slot and process metrics.
func (c *Client) Snapshot(ctx context.Context) (*ResourceSnapshot, error) {
	snap := &ResourceSnapshot{Timestamp: time.Now()}

	resp, err := c.get(ctx, "/eth/v1/node/health")
	if err != nil {
		snap.BeaconAPIError = err.Error()
		return snap, nil
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	snap.Healthy = resp.StatusCode == 200 || resp.StatusCode == 206

	if data := c.getJSON(ctx, "/eth/v1/node/peer_count"); data != nil {
		if connected := jsonPath(data, "data", "connected"); connected != nil {
			snap.PeerCount, _ = strconv.Atoi(*connected)
		}
	}
	if data := c.getJSON(ctx, "/eth/v1/beacon/headers/head"); data != nil {
		if slot := jsonPath(data, "data", "header", "message", "slot"); slot != nil {
			snap.HeadSlot, _ = strconv.ParseUint(*slot, 10, 64)
		}
	}
	if resp, err := c.get(ctx, "/metrics"); err == nil {
		parseMetrics(resp.Body, snap)
		resp.Body.Close()
	}
	return snap, nil
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) getJSON(ctx context.Context, path string) map[string]any {
	resp, err := c.get(ctx, path)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	return out
}

// jsonPath walks a decoded JSON object by keys, "" for maps.
func jsonPath(m map[string]any, keys ...string) *string {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = obj[k]
		if !ok {
			return nil
		}
	}
	s, ok := cur.(string)
	if !ok {
		return nil
	}
	return &s
}

func hexBytes(s string, wantLen int) ([]byte, bool) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != wantLen {
		return nil, false
	}
	return b, true
}

func parseVersion4(s string) [4]byte {
	var v [4]byte
	if b, ok := hexBytes(s, 4); ok {
		copy(v[:], b)
	}
	return v
}

// forkEpochKeys maps fork names to config-spec epoch keys, in fork order.
var forkEpochKeys = []struct{ name, key string }{
	{"altair", "ALTAIR_FORK_EPOCH"},
	{"bellatrix", "BELLATRIX_FORK_EPOCH"},
	{"capella", "CAPELLA_FORK_EPOCH"},
	{"deneb", "DENEB_FORK_EPOCH"},
	{"electra", "ELECTRA_FORK_EPOCH"},
	{"fulu", "FULU_FORK_EPOCH"},
	{"gloas", "GLOAS_FORK_EPOCH"},
	{"heze", "HEZE_FORK_EPOCH"},
}

// ActiveForkFromSpec determines the active fork name from a config spec
// object (string values) and the head slot. A fork whose epoch is absent,
// unparseable, or the far-future sentinel is not activated.
func ActiveForkFromSpec(spec map[string]string, headSlot uint64) string {
	slotsPerEpoch := uint64(32)
	if v, ok := spec["SLOTS_PER_EPOCH"]; ok {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
			slotsPerEpoch = n
		}
	}
	headEpoch := headSlot / slotsPerEpoch
	active := "phase0"
	for _, fe := range forkEpochKeys {
		v, ok := spec[fe.key]
		if !ok {
			continue
		}
		epoch, err := strconv.ParseUint(v, 10, 64)
		if err != nil || epoch == math.MaxUint64 {
			continue
		}
		if headEpoch >= epoch {
			active = fe.name
		}
	}
	return active
}

// BuildStatusSSZ encodes the 84-byte Status envelope (V1).
func BuildStatusSSZ(s *NodeState) []byte {
	ssz := make([]byte, 84)
	copy(ssz[0:4], s.ForkDigest[:])
	copy(ssz[4:36], s.FinalizedRoot[:])
	binary.LittleEndian.PutUint64(ssz[36:44], s.FinalizedEpoch)
	copy(ssz[44:76], s.HeadRoot[:])
	binary.LittleEndian.PutUint64(ssz[76:84], s.HeadSlot)
	return ssz
}

// BuildStatusSSZV2 encodes the 92-byte Status envelope (V2, Electra onward):
// the V1 layout plus EarliestAvailableSlot.
func BuildStatusSSZV2(s *NodeState) []byte {
	ssz := make([]byte, 92)
	copy(ssz[0:84], BuildStatusSSZ(s))
	binary.LittleEndian.PutUint64(ssz[84:92], s.EarliestAvailableSlot)
	return ssz
}

func parseMetrics(r io.Reader, snap *ResourceSnapshot) {
	data, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := splitMetricLine(line)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(value, 64)
		if err != nil || v < 0 {
			continue
		}
		switch {
		case snap.RSSBytes == 0 && metricNameMatches(name, "process_resident_memory_bytes", "beacon_process_resident_memory_bytes"):
			snap.RSSBytes = uint64(v)
		case snap.Goroutines == 0 && metricNameMatches(name, "go_goroutines"):
			snap.Goroutines = int(v)
		case snap.Tasks == 0 && metricNameMatches(name, "tokio_num_workers", "tokio_threads_alive", "async_tasks_count", "beacon_processor_work_event_count"):
			snap.Tasks = int(v)
		case snap.OpenFDs == 0 && metricNameMatches(name, "process_open_fds", "process_open_fds_total", "open_file_descriptors"):
			snap.OpenFDs = int(v)
		case snap.CPUSeconds == 0 && metricNameMatches(name, "process_cpu_seconds_total"):
			snap.CPUSeconds = v
		}
	}
}

func splitMetricLine(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", false
	}
	name := fields[0]
	if idx := strings.IndexByte(name, '{'); idx >= 0 {
		name = name[:idx]
	}
	return name, fields[1], true
}

func metricNameMatches(name string, candidates ...string) bool {
	for _, candidate := range candidates {
		if name == candidate || strings.HasSuffix(name, "_"+candidate) {
			return true
		}
	}
	return false
}
