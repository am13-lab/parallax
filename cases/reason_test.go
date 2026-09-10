package cases

import (
	"errors"
	"testing"

	"parallax/runner"
)

// TestOutcomeRejectReasons verifies that outcome() normalizes transport-level
// failures into comparable reject reasons instead of collapsing every failure
// into the bare "reject" label. The failure *mode* is a client characteristic
// and must participate in divergence detection.
func TestOutcomeRejectReasons(t *testing.T) {
	tests := []struct {
		name string
		res  *runner.ReqRespResult
		err  error
		want string
	}{
		{"stream reset", &runner.ReqRespResult{StreamReset: true}, nil, "reject:reset"},
		{"read timeout", &runner.ReqRespResult{Error: "read: connection deadline exceeded"}, nil, "reject:timeout"},
		{"io timeout", &runner.ReqRespResult{Error: "read: i/o timeout"}, nil, "reject:timeout"},
		{"dial refused", &runner.ReqRespResult{Error: "dial tcp 1.2.3.4:9090: connect: connection refused"}, nil, "reject:dial_failed"},
		{"all dials failed", &runner.ReqRespResult{Error: "all dials failed"}, nil, "reject:dial_failed"},
		{"connection failed", &runner.ReqRespResult{Error: "connection failed"}, nil, "reject:connection_error"},
		{
			"error chunk 0x01",
			&runner.ReqRespResult{ResponseChunks: []runner.ResponseChunk{{ResultCode: 0x01, Payload: []byte("invalid")}}},
			nil, "reject:error_chunk:0x01",
		},
		{
			"error chunk 0x02",
			&runner.ReqRespResult{ResponseChunks: []runner.ResponseChunk{{ResultCode: 0x02}}},
			nil, "reject:error_chunk:0x02",
		},
		{
			"error chunk 0x03",
			&runner.ReqRespResult{ResponseChunks: []runner.ResponseChunk{{ResultCode: 0x03}}},
			nil, "reject:error_chunk:0x03",
		},
		{
			"success chunk",
			&runner.ReqRespResult{ResponseChunks: []runner.ResponseChunk{{ResultCode: 0x00, Payload: []byte("ok")}}},
			nil, "accept",
		},
		{"err timeout", nil, errors.New("context deadline exceeded"), "reject:timeout"},
		{"err dial", nil, errors.New("all dials failed"), "reject:dial_failed"},
		{"err other", nil, errors.New("write: broken pipe"), "reject:connection_error"},
		{
			"partial data then timeout",
			&runner.ReqRespResult{RawBytes: []byte{0x00, 0x01}, Error: "read: connection deadline exceeded"},
			nil, "reject:timeout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := outcome(tt.res, tt.err); got != tt.want {
				t.Fatalf("outcome = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOutcomeUnclassifiedStaysOther verifies unclassifiable results keep the
// "other:" prefix with their detail.
func TestOutcomeUnclassifiedStaysOther(t *testing.T) {
	if got := outcome(nil, nil); got != "other:nil result" {
		t.Fatalf("outcome(nil, nil) = %q", got)
	}
	res := &runner.ReqRespResult{ResponseChunks: []runner.ResponseChunk{{ResultCode: 0x7f}}}
	if got := outcome(res, nil); got != "other:unknown result code 127" {
		t.Fatalf("unknown code = %q", got)
	}
	res = &runner.ReqRespResult{}
	if got := outcome(res, nil); got != "other:empty response" {
		t.Fatalf("empty response = %q", got)
	}
}

// TestDivergeRejectReasonMismatch verifies divergence detection treats the
// normalized reject reason as part of the behavior: two clients that both
// reject but in different ways diverge; the same way converges.
func TestDivergeRejectReasonMismatch(t *testing.T) {
	meta := runner.Metadata{}

	same := map[string]string{"A": "reject:reset", "B": "reject:reset"}
	if divs := diverge("t.same", "reqresp", meta, same); len(divs) != 0 {
		t.Fatalf("same reject reason must converge: %+v", divs)
	}

	diff := map[string]string{"A": "reject:reset", "B": "reject:error_chunk:0x01"}
	divs := diverge("t.diff", "reqresp", meta, diff)
	if len(divs) != 1 {
		t.Fatalf("different reject reasons must diverge: %+v", divs)
	}
	d := divs[0]
	if d.Expected != "reject:reset" {
		t.Fatalf("expected class = %q, want reject:reset", d.Expected)
	}
	if d.Severity != runner.SeverityHigh {
		t.Fatalf("reject:reason divergence must stay high severity: %+v", d)
	}
}

// TestClassOfRejectPrefixKeepsThreeWay verifies classOf still folds reject
// variants into the three-way classification used by generated code and
// walker verdict collection.
func TestClassOfRejectPrefixKeepsThreeWay(t *testing.T) {
	for _, in := range []string{"reject", "reject:reset", "reject:timeout", "reject:error_chunk:0x01"} {
		if got := classOf(in); got != "reject" {
			t.Fatalf("classOf(%q) = %q, want reject", in, got)
		}
	}
	if got := classOf("accept"); got != "accept" {
		t.Fatalf("classOf(accept) = %q", got)
	}
	if got := classOf("other:x"); got != "other" {
		t.Fatalf("classOf(other:x) = %q", got)
	}
}

// TestNormalizeGoodbyeRejectPrefix verifies the goodbye normalizer treats
// every reject variant (reset, timeout, error chunk) as a compliant
// no-response.
func TestNormalizeGoodbyeRejectPrefix(t *testing.T) {
	for _, in := range []string{"reject", "reject:reset", "reject:timeout", "reject:dial_failed"} {
		if got := normalizeGoodbye(in); got != "accept" {
			t.Fatalf("normalizeGoodbye(%q) = %q, want accept", in, got)
		}
	}
	if got := normalizeGoodbye("accept"); got != "accept" {
		t.Fatalf("normalizeGoodbye(accept) = %q", got)
	}
}
