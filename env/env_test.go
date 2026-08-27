package env_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"libp2p-difftest/env"
)

func TestErrLogsUnsupportedIsDistinct(t *testing.T) {
	if !errors.Is(env.ErrLogsUnsupported, env.ErrLogsUnsupported) {
		t.Fatal("sentinel must match itself via errors.Is")
	}
	if errors.Is(env.ErrLogsUnsupported, io.EOF) {
		t.Fatal("sentinel must not match unrelated errors")
	}
}

var _ env.Environment = (*fakeEnv)(nil)

type fakeEnv struct{}

func (f *fakeEnv) Endpoints() []env.Endpoint { return nil }
func (f *fakeEnv) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	return nil, env.ErrLogsUnsupported
}
func (f *fakeEnv) Info() map[string]string            { return map[string]string{"provider": "fake"} }
func (f *fakeEnv) Teardown(ctx context.Context) error { return nil }
