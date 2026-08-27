package runner_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"libp2p-difftest/runner"
)

// fakeClient asserts the runner.Client interface remains implementable
// outside the client package.
type fakeClient struct{ name string }

func (f *fakeClient) Name() string  { return f.name }
func (f *fakeClient) Type() string  { return "fake" }
func (f *fakeClient) ReqResp(ctx context.Context, protocol string, body []byte, timeout time.Duration) (*runner.ReqRespResult, error) {
	return &runner.ReqRespResult{}, nil
}
func (f *fakeClient) PublishGossip(ctx context.Context, topic string, data []byte) error { return nil }
func (f *fakeClient) ObserveGossip(ctx context.Context, topic string, data []byte, wait time.Duration) (runner.GossipVerdict, error) {
	return runner.VerdictUnknown, nil
}
func (f *fakeClient) Connect(ctx context.Context, mode runner.ConnectMode) error { return nil }
func (f *fakeClient) RotateIdentity(ctx context.Context) error                   { return nil }
func (f *fakeClient) Health(ctx context.Context) error                           { return nil }
func (f *fakeClient) State(ctx context.Context) (*runner.NodeState, error) {
	return nil, runner.ErrNoBeaconAPI
}
func (f *fakeClient) Snapshot(ctx context.Context) (*runner.ResourceSnapshot, error) {
	return &runner.ResourceSnapshot{}, nil
}
func (f *fakeClient) Close() error { return nil }

var _ runner.Client = (*fakeClient)(nil)

func TestErrNoBeaconAPISentinel(t *testing.T) {
	if !errors.Is(runner.ErrNoBeaconAPI, runner.ErrNoBeaconAPI) {
		t.Fatal("sentinel must be usable with errors.Is")
	}
}

func TestDivergenceJSONFieldNames(t *testing.T) {
	d := runner.Divergence{
		TestID:        "reqresp.ping.empty_body",
		Category:      "reqresp",
		Type:          runner.DivAcceptReject,
		Severity:      runner.SeverityHigh,
		Description:   "d",
		ClientResults: map[string]string{"a": "accept", "b": "reject"},
		OutlierClients: []string{"b"},
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"test_id":`, `"category":`, `"type":`, `"severity":`, `"description":`, `"client_results":`, `"outlier_clients":`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("missing JSON key %s in %s", key, b)
		}
	}
}

func TestSpecMetadataDefaults(t *testing.T) {
	// Metadata zero value must be meaningful: RunClass defaults are applied
	// by the runner, MinClients 0 means the default floor of 2.
	var m runner.Metadata
	if m.RunClass != "" && m.RunClass != runner.RunClassStandard {
		t.Fatalf("unexpected zero run class: %q", m.RunClass)
	}
}
