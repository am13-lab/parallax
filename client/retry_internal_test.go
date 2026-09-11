package client

import "testing"

// TestIsStreamReset verifies that only peer-initiated stream resets are
// surfaced as StreamReset — a timeout or dial failure must not be
// misreported as a reset.
func TestIsStreamReset(t *testing.T) {
	for _, msg := range []string{
		"read: stream reset by peer",
		"connection reset by peer",
	} {
		if !isStreamReset(msg) {
			t.Errorf("isStreamReset(%q) = false, want true", msg)
		}
	}
	for _, msg := range []string{
		"read: connection deadline exceeded",
		"all dials failed",
		"connection closed",
	} {
		if isStreamReset(msg) {
			t.Errorf("isStreamReset(%q) = true, want false", msg)
		}
	}
}

// TestRetryScopeIsConnectionOnly documents the retry gate: only
// connection-level failures are retried (their retry cost is seconds).
// Timeouts must never be retried — a retry doubles the per-case wait,
// which made full-batch runs take 4x longer.
func TestRetryScopeIsConnectionOnly(t *testing.T) {
	for _, msg := range []string{
		"connection failed",
		"connection closed",
		"all dials failed",
	} {
		if !isStreamOpenFailure(msg) {
			t.Errorf("isStreamOpenFailure(%q) = false, want true", msg)
		}
	}
	if isStreamOpenFailure("read: connection deadline exceeded") {
		t.Error("timeout must not be retried")
	}
}
