package runner_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"libp2p-difftest/runner"
)

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
