// Package staticenv attaches to already-running beacon nodes described in a
// YAML endpoint list (the previous tool's clients.yaml format).
package staticenv

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/multiformats/go-multiaddr"
	"gopkg.in/yaml.v3"

	"libp2p-difftest/env"
)

// ClientEntry is one endpoint in the config file.
type ClientEntry struct {
	Name       string   `yaml:"name"`
	ClientType string   `yaml:"client_type"`
	Multiaddr  string   `yaml:"multiaddr"`
	BeaconAPI  string   `yaml:"beacon_api"`
	ProxyAddrs []string `yaml:"proxy_addrs"`
}

// Config is the top-level config file.
type Config struct {
	Clients []ClientEntry `yaml:"clients"`
}

// Load reads and parses a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Environment is a static set of endpoints.
type Environment struct {
	endpoints []env.Endpoint
}

// New validates the config and returns an attached environment.
func New(cfg *Config) (*Environment, error) {
	e := &Environment{}
	for _, c := range cfg.Clients {
		if _, err := multiaddr.NewMultiaddr(c.Multiaddr); err != nil {
			return nil, fmt.Errorf("client %s: invalid multiaddr: %w", c.Name, err)
		}
		for _, p := range c.ProxyAddrs {
			if _, err := multiaddr.NewMultiaddr(p); err != nil {
				return nil, fmt.Errorf("client %s: invalid proxy multiaddr: %w", c.Name, err)
			}
		}
		e.endpoints = append(e.endpoints, env.Endpoint{
			Name:       c.Name,
			ClientType: c.ClientType,
			Multiaddr:  c.Multiaddr,
			BeaconAPI:  c.BeaconAPI,
			Proxies:    c.ProxyAddrs,
		})
	}
	return e, nil
}

func (e *Environment) Endpoints() []env.Endpoint { return e.endpoints }

func (e *Environment) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	return nil, env.ErrLogsUnsupported
}

func (e *Environment) Info() map[string]string {
	return map[string]string{"provider": "static"}
}

func (e *Environment) Teardown(ctx context.Context) error { return nil }
