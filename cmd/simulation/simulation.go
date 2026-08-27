// Command simulation runs the full seed case set against scripted fake
// consensus nodes and writes real report artifacts. It exercises the exact
// production pipeline (env -> clients -> runner -> report) without a
// devnet, and doubles as a demonstration of the divergence detection.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"libp2p-difftest/cases"
	"libp2p-difftest/client"
	"libp2p-difftest/env/staticenv"
	"libp2p-difftest/internal/testutil"
	"libp2p-difftest/report"
	"libp2p-difftest/runner"
	"libp2p-difftest/testnode"
)

// SimConfig configures the simulation.
type SimConfig struct {
	Out    string
	Stdout writer
}

type writer interface {
	Write(p []byte) (int, error)
}

const (
	pingProto    = "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	statusV1     = "/eth2/beacon_chain/req/status/1/ssz_snappy"
	statusV2     = "/eth2/beacon_chain/req/status/2/ssz_snappy"
	metadataV2   = "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
	goodbyeV1    = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
	bbrV2        = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
	unknownProto = "/eth2/beacon_chain/req/definitely_not_real/1/ssz_snappy"
	gossipTopic  = "/eth2/deadbeef/beacon_block/ssz_snappy"
)

// runSimulation starts three fake nodes with scripted behaviors, runs the
// full seed set through the production pipeline, and writes artifacts.
//
// Scripting: node A (prysm-a) is fully conformant; node B (lighthouse-b)
// matches A; node C (teku-c) deviates on four properties: it resets
// empty-body pings, serves an unknown protocol, rejects gossip, and
// advertises a different fork digest in its ENR.
func runSimulation(cfg SimConfig) (*runner.Report, error) {
	okRead := &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{{0x01}}, ReadRequest: true}
	okNoRead := &testnode.Script{Behavior: testnode.Success}
	resetRead := &testnode.Script{Behavior: testnode.Reset, ReadRequest: true}
	sinkRead := &testnode.Script{Behavior: testnode.Success, Chunks: [][]byte{make([]byte, 84)}, ReadRequest: true}

	digestMain := make([]byte, 16)
	copy(digestMain[0:4], []byte{0xde, 0xad, 0xbe, 0xef})
	digestOther := make([]byte, 16)
	copy(digestOther[0:4], []byte{0x01, 0x02, 0x03, 0x04})

	relayOff := false
	nodeCfgs := []*testnode.Config{
		{
			Protocols: map[string]*testnode.Script{
				pingProto: okRead, statusV1: sinkRead, statusV2: sinkRead,
				metadataV2: okNoRead, goodbyeV1: okNoRead, bbrV2: resetRead,
			},
			Topics: []string{gossipTopic},
			Beacon: &testnode.BeaconConfig{ENR: testutil.BuildTestENR(digestMain, make([]byte, 8)), HeadSlot: 64},
		},
		{
			Protocols: map[string]*testnode.Script{
				pingProto: okRead, statusV1: sinkRead, statusV2: sinkRead,
				metadataV2: okNoRead, goodbyeV1: okNoRead, bbrV2: resetRead,
			},
			Topics: []string{gossipTopic},
			Beacon: &testnode.BeaconConfig{ENR: testutil.BuildTestENR(digestMain, make([]byte, 8)), HeadSlot: 64},
		},
		{
			Protocols: map[string]*testnode.Script{
				pingProto: resetRead, statusV1: sinkRead, statusV2: sinkRead,
				metadataV2: okNoRead, goodbyeV1: okNoRead, bbrV2: resetRead,
				unknownProto: {Behavior: testnode.Success, Chunks: [][]byte{{0x01}}},
			},
			Topics:      []string{gossipTopic},
			RelayGossip: &relayOff,
			Beacon:      &testnode.BeaconConfig{ENR: testutil.BuildTestENR(digestOther, make([]byte, 8)), HeadSlot: 64},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	envCfg := &staticenv.Config{}
	type liveNode struct {
		node *testnode.Node
		cl   *client.Client
	}
	var live []liveNode
	for i, nc := range nodeCfgs {
		n, err := testnode.Start(nc)
		if err != nil {
			return nil, fmt.Errorf("node %d: %w", i, err)
		}
		defer n.Close()
		name := []string{"prysm-a", "lighthouse-b", "teku-c"}[i]
		ctype := []string{"prysm", "lighthouse", "teku"}[i]
		c, err := client.New(ctx, &client.Config{
			Name:       name,
			ClientType: ctype,
			Multiaddr:  n.Multiaddr(),
			BeaconAPI:  n.BeaconURL(),
		})
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", name, err)
		}
		defer c.Close()
		live = append(live, liveNode{n, c})
		envCfg.Clients = append(envCfg.Clients, staticenv.ClientEntry{
			Name: name, ClientType: ctype,
			Multiaddr: n.Multiaddr(), BeaconAPI: n.BeaconURL(),
		})
	}

	envr, err := staticenv.New(envCfg)
	if err != nil {
		return nil, err
	}
	var clients []runner.Client
	for _, ln := range live {
		clients = append(clients, ln.cl)
	}

	chain := runner.ChainConfig{Preset: "mainnet", ForkDigest: [4]byte{0xde, 0xad, 0xbe, 0xef}}
	rep := runner.Run(ctx, cases.All(), clients, envr, chain, runner.Options{
		Seed:           42,
		PerTestTimeout: 2 * time.Minute,
		Progress: func(r runner.TestResult) {
			if cfg.Stdout != nil {
				fmt.Fprintf(cfg.Stdout, "  %-45s %s\n", r.TestID, r.Status)
			}
		},
	})

	if err := os.MkdirAll(cfg.Out, 0o755); err != nil {
		return nil, err
	}
	jsonData, err := report.WriteJSON(rep)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.Out+"/report.json", jsonData, 0o644); err != nil {
		return nil, err
	}
	junit, err := report.WriteJUnit(rep)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(cfg.Out+"/junit.xml", junit, 0o644); err != nil {
		return nil, err
	}
	return rep, nil
}
