// Package kurtosisenv provides the kurtosis backend: provisioning a devnet
// via ethpandaops/ethereum-package and attaching to enclaves, with service
// discovery through the kurtosis API instead of CLI text parsing.
package kurtosisenv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"parallax/env"
)

// ServiceInfo is the per-service data the mapping needs, extracted from the
// kurtosis API.
type ServiceInfo struct {
	Name     string
	PublicIP string
	Ports    map[string]uint16 // by kurtosis port name, e.g. "tcp-discovery", "http"
}

// APIClient abstracts the kurtosis API surface this package needs. The real
// implementation lives in kurtosis_api.go; tests inject fakes.
type APIClient interface {
	ListCLServices(ctx context.Context, enclave string) ([]ServiceInfo, error)
	Logs(ctx context.Context, enclave, service string, since time.Time) ([]string, error)
	Provision(ctx context.Context, enclaveName, argsFile string) error
	Destroy(ctx context.Context, enclaveName string) error
}

// Config configures the kurtosis provider.
type Config struct {
	Enclave   string
	ArgsFile  string
	PackageID string // default github.com/ethpandaops/ethereum-package
	// Attach skips provisioning and uses the existing enclave.
	Attach bool
}

// DeriveClientType extracts the CL client type from an ethereum-package
// service name. The rules are pinned by tests so upstream naming changes
// fail loudly: "cl-1-prysm-geth" -> "prysm", "cl-1-caplin-erigon" -> "caplin".
func DeriveClientType(serviceName string) string {
	fields := strings.Split(serviceName, "-")
	if len(fields) < 3 || fields[0] != "cl" {
		return serviceName
	}
	return fields[2]
}

// peerIDFetcher retrieves the target's peer ID from its beacon API
// /eth/v1/node/identity endpoint. Nil selects the default HTTP fetcher.
type peerIDFetcher func(beaconAPIURL string) (string, error)

// ServicesToEndpoints maps CL service infos into environment endpoints.
// A missing tcp-discovery port is fatal; a missing http port only disables
// the beacon API on that endpoint.
func ServicesToEndpoints(svcs []ServiceInfo, fetch peerIDFetcher) ([]env.Endpoint, error) {
	if fetch == nil {
		fetch = fetchPeerIDHTTP
	}
	endpoints := make([]env.Endpoint, 0, len(svcs))
	for _, svc := range svcs {
		ep := env.Endpoint{
			Name:       svc.Name,
			ClientType: DeriveClientType(svc.Name),
			Service:    svc.Name,
		}
		if discPort, ok := svc.Ports["tcp-discovery"]; ok {
			ep.Multiaddr = fmt.Sprintf("/ip4/%s/tcp/%d/p2p/", svc.PublicIP, discPort)
		} else {
			return nil, fmt.Errorf("service %s: no tcp-discovery port exposed", svc.Name)
		}
		if httpPort, ok := svc.Ports["http"]; ok {
			ep.BeaconAPI = fmt.Sprintf("http://%s:%d", svc.PublicIP, httpPort)
			peerID, err := fetch(ep.BeaconAPI)
			if err != nil {
				return nil, fmt.Errorf("service %s: fetch peer id: %w", svc.Name, err)
			}
			if peerID == "" {
				return nil, fmt.Errorf("service %s: empty peer id from identity endpoint", svc.Name)
			}
			ep.Multiaddr += peerID
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

// Environment is an attached kurtosis enclave.
type Environment struct {
	api     APIClient
	enclave string
	eps     []env.Endpoint
}

// Attach connects to an existing enclave and discovers its CL endpoints.
func Attach(ctx context.Context, api APIClient, enclave string) (*Environment, error) {
	e := &Environment{api: api, enclave: enclave}
	if err := e.refresh(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

func (e *Environment) refresh(ctx context.Context) error {
	svcs, err := e.api.ListCLServices(ctx, e.enclave)
	if err != nil {
		return fmt.Errorf("list services in enclave %s: %w", e.enclave, err)
	}
	eps, err := ServicesToEndpoints(svcs, nil)
	if err != nil {
		return err
	}
	e.eps = eps
	return nil
}

func (e *Environment) Endpoints() []env.Endpoint { return e.eps }

func (e *Environment) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	lines, err := e.api.Logs(ctx, e.enclave, ep.Service, since)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewBufferString(strings.Join(lines, "\n") + "\n")), nil
}

func (e *Environment) Info() map[string]string {
	return map[string]string{
		"provider": "kurtosis",
		"enclave":  e.enclave,
	}
}

// Teardown destroys the enclave.
func (e *Environment) Teardown(ctx context.Context) error {
	return e.api.Destroy(ctx, e.enclave)
}

// Provider implements env.Provider for kurtosis.
type Provider struct {
	// API is the kurtosis API client; inject a fake in tests.
	API APIClient
}

// Name returns the provider name.
func (p *Provider) Name() string { return "kurtosis" }

// Setup provisions (or attaches to) an environment per the config.
func (p *Provider) Setup(ctx context.Context, cfg any) (env.Environment, error) {
	kcfg, ok := cfg.(Config)
	if !ok {
		return nil, fmt.Errorf("kurtosis provider expects kurtosisenv.Config, got %T", cfg)
	}
	if !kcfg.Attach {
		// A leftover enclave carries stale client state (peer-score bans
		// can outlive the batch by an hour+), which would poison the run.
		// Always start from a clean slate; a missing enclave is not an
		// error here — Provision below creates it.
		_ = p.API.Destroy(ctx, kcfg.Enclave)
		if err := p.API.Provision(ctx, kcfg.Enclave, kcfg.ArgsFile); err != nil {
			return nil, fmt.Errorf("provision enclave %s: %w", kcfg.Enclave, err)
		}
	}
	return Attach(ctx, p.API, kcfg.Enclave)
}
