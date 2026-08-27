// Package runner defines the test model (Spec, Client, TestEnv), the
// scheduling loop, and report assembly for differential testing.
package runner

import (
	"context"
	"fmt"
	"math/rand"
	"log/slog"
	"time"

	"libp2p-difftest/beacon"
	"libp2p-difftest/env"
	"libp2p-difftest/wire"
)

// Re-exported shared types: tests speak a single vocabulary.
type (
	ResourceSnapshot = beacon.ResourceSnapshot
	NodeState        = beacon.NodeState
	ResponseChunk    = wire.ResponseChunk
)

// ReqRespResult captures the outcome of one req/resp exchange.
type ReqRespResult struct {
	// ResponseChunks holds parsed response chunks (may be nil on failure).
	ResponseChunks []ResponseChunk
	// RawBytes is the full response as received on the wire.
	RawBytes []byte
	// Duration covers stream open through response completion.
	Duration time.Duration
	// TimeToFirstByte is stream open through the first response byte.
	TimeToFirstByte time.Duration
	// Error is set when the exchange did not complete.
	Error string
	// StreamReset indicates the peer reset the stream with no data returned.
	StreamReset bool
}

// GossipVerdict is the remote acceptance signal for a gossip injection.
type GossipVerdict string

const (
	// VerdictAccept means re-propagation was observed: a strong accept.
	VerdictAccept GossipVerdict = "accept"
	// VerdictReject means nothing was observed within the window. This is
	// a weak negative: reject, ignore, or a missing gossipsub mesh.
	VerdictReject GossipVerdict = "reject"
	// VerdictUnknown means no verdict could be produced (observer setup
	// failed or no way to observe).
	VerdictUnknown GossipVerdict = "unknown"
)

// ConnectMode selects whether the client performs a Status handshake.
type ConnectMode int

const (
	ConnectWithStatus ConnectMode = iota
	ConnectNoStatus
)

// Client is one testable target node.
type Client interface {
	Name() string
	Type() string

	// ReqResp sends one request on a req/resp protocol and reads the full
	// response (all chunks) within the timeout. It never returns a nil
	// result with a nil error; failures are carried in ReqRespResult.Error.
	ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*ReqRespResult, error)

	PublishGossip(ctx context.Context, topic string, data []byte) error
	// ObserveGossip subscribes via a target-only observer host and waits
	// for re-propagation of a message with this content.
	ObserveGossip(ctx context.Context, topic string, data []byte, wait time.Duration) (GossipVerdict, error)

	// Connect (re-)establishes the libp2p connection in the given mode.
	Connect(ctx context.Context, mode ConnectMode) error
	// RotateIdentity replaces the probe identity, cycling to the next proxy
	// address when the endpoint provides proxies.
	RotateIdentity(ctx context.Context) error

	// Health is a cheap liveness check used by the runner between tests.
	Health(ctx context.Context) error

	// State returns the chain state fetched from the Beacon API, or
	// ErrNoBeaconAPI when the endpoint has none.
	State(ctx context.Context) (*NodeState, error)
	Snapshot(ctx context.Context) (*ResourceSnapshot, error)
	Close() error
}

// ErrNoBeaconAPI is returned by Client.State when no Beacon API is configured.
var ErrNoBeaconAPI = fmt.Errorf("no beacon API configured")

// RunClass controls default inclusion of tests.
type RunClass string

const (
	RunClassStandard RunClass = "standard"
	RunClassHeavy    RunClass = "heavy"
	RunClassConfig   RunClass = "config"
)

// Metadata carries traceability and run gating for a test.
type Metadata struct {
	KnowledgeIDs []string `json:"knowledge_ids,omitempty"`
	SpecRules    []string `json:"spec_rules,omitempty"`
	RunClass     RunClass `json:"run_class,omitempty"`
	LogSensitive bool     `json:"log_sensitive,omitempty"`
	// MinClients is a floor: the runner skips the test when fewer clients
	// are usable and passes all usable clients otherwise.
	MinClients int `json:"min_clients,omitempty"`
}

// Spec is one differential test.
type Spec struct {
	ID       string
	Category string
	Metadata Metadata
	// Preflight proves the test is meaningful on the current environment
	// before it consumes a scheduling slot. Nil means always runnable.
	Preflight func(ctx context.Context, cs []Client) PreflightResult
	Run       func(ctx context.Context, te TestEnv) []Divergence
}

// PreflightResult is returned by Spec.Preflight.
type PreflightResult struct {
	Runnable bool
	Reason   string
}

// TestEnv is what a test's Run function receives.
type TestEnv struct {
	Clients []Client
	Env     env.Environment
	Chain   ChainConfig
	Meta    Metadata // the running spec's metadata
	RNG     *rand.Rand
	Log     *slog.Logger
}

// ChainConfig carries everything fork- and preset-dependent that cases need.
type ChainConfig struct {
	Preset                string
	ForkDigest            [4]byte
	GenesisForkVersion    [4]byte
	GenesisValidatorsRoot [32]byte
	GossipMaxSize         uint64
	MaxChunkSize          uint64
}

// DivergenceType classifies how clients diverged.
type DivergenceType string

const (
	DivAcceptReject    DivergenceType = "ACCEPT_REJECT"
	DivErrorCode       DivergenceType = "ERROR_CODE"
	DivResource        DivergenceType = "RESOURCE"
	DivCrash           DivergenceType = "CRASH"
	DivTimeout         DivergenceType = "TIMEOUT"
	DivResponseContent DivergenceType = "RESPONSE_CONTENT"
	DivSkipped         DivergenceType = "SKIPPED"
	DivOperational     DivergenceType = "OPERATIONAL"
	DivConsensusValue  DivergenceType = "CONSENSUS_VALUE_MISMATCH"
	DivValueDiff       DivergenceType = "VALUE_DIFFERENCE"
	DivProperty        DivergenceType = "PROPERTY_VIOLATION"
)

// Severity classifies the importance of a divergence finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Divergence describes one behavioral divergence across clients. JSON field
// names match the previous tool's DivergenceReport so triage tooling and
// allowlist formats keep working.
type Divergence struct {
	TestID          string            `json:"test_id"`
	Category        string            `json:"category"`
	KnowledgeIDs    []string          `json:"knowledge_ids,omitempty"`
	RunClass        RunClass          `json:"run_class,omitempty"`
	Type            DivergenceType    `json:"type"`
	Severity        Severity          `json:"severity"`
	Description     string            `json:"description"`
	ClientResults   map[string]string `json:"client_results"`
	SpecRuleIDs     []string          `json:"spec_rule_ids,omitempty"`
	ExcludedClients []string          `json:"excluded_clients,omitempty"`
	OutlierClients  []string          `json:"outlier_clients,omitempty"`
}
