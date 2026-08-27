// Package env defines the environment abstraction: a set of reachable
// beacon-node endpoints plus capabilities (log access, teardown) provided by
// a backend such as a static endpoint list, kurtosis, or hive.
package env

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrLogsUnsupported is returned by Environment.Logs when the backend cannot
// provide service logs. The runner treats it as a capability gap, not a failure.
var ErrLogsUnsupported = errors.New("environment does not support log retrieval")

// Endpoint is one reachable beacon node.
type Endpoint struct {
	Name       string   // display name, e.g. "prysm-1"
	ClientType string   // normalized type, e.g. "prysm"
	Multiaddr  string   // libp2p reachable address with peer ID
	BeaconAPI  string   // http URL, may be empty
	Service    string   // backend-specific identifier, used for Logs()
	Proxies    []string // alternate multiaddrs cycled on identity rotation
	Image      string   // optional fingerprint data, backend-provided
	Version    string   // optional fingerprint data, backend-provided
}

// Environment is a live testing target: reachable endpoints plus capabilities.
type Environment interface {
	Endpoints() []Endpoint
	// Logs returns the service log stream since the given time.
	Logs(ctx context.Context, ep Endpoint, since time.Time) (io.ReadCloser, error)
	// Info describes the environment for the report fingerprint.
	Info() map[string]string
	// Teardown releases the environment.
	Teardown(ctx context.Context) error
}

// Provider constructs an Environment from backend-specific configuration.
type Provider interface {
	Name() string
	// Setup attaches to or provisions an environment, depending on backend
	// semantics (static attaches, kurtosis provisions unless told to attach).
	Setup(ctx context.Context, cfg any) (Environment, error)
}
