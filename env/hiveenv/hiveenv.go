// Package hiveenv implements env.Provider on top of hive-built client
// images orchestrated directly through docker. Unlike the kurtosis path
// there is no provisioning framework: the caller generates the genesis
// files (hivegen, see hive-sim/cmd/hivegen) and this provider launches
// the containers with the HIVE_* conventions the client entrypoints
// expect, then hands the endpoints to the differential runner.
package hiveenv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"parallax/env"
)

// Config configures the hive provider.
type Config struct {
	// Enclave names the docker network and prefixes container names.
	Enclave string
	// GenDir is the hivegen output directory (genesis.json, genesis.ssz,
	// config.yaml, preset_*.yaml).
	GenDir string
	// ClientTypes lists the CL clients to launch. Every entry must have a
	// definition in clientDefs.
	ClientTypes []string
	// ImageRepo is the docker registry namespace images resolve under
	// (e.g. docker.io/am13lab). Empty means the local build names
	// (hive/clients/...), which must already exist in the daemon.
	ImageRepo string
}

// clientDef is one CL client's launch profile: image (built from the hive
// repo's clients/<name> directory), beacon API port and p2p port inside
// the container.
type clientDef struct {
	image   string
	apiPort string
	p2pPort string
}

// clientDefs covers the clients verified under this path; extend after
// building the corresponding hive client image.
var clientDefs = map[string]clientDef{
	"lighthouse": {image: "hive/clients/lighthouse-bn:local", apiPort: "4000", p2pPort: "9000"},
	"teku":       {image: "hive/clients/teku-bn:local", apiPort: "4000", p2pPort: "9000"},
	"prysm":      {image: "hive/clients/prysm-bn:local", apiPort: "4000", p2pPort: "9000"},
	"nimbus":     {image: "hive/clients/nimbus-bn:local", apiPort: "4000", p2pPort: "9000"},
	"lodestar":   {image: "hive/clients/lodestar-bn:local", apiPort: "4000", p2pPort: "9000"},
	"grandine":   {image: "hive/clients/grandine-bn:local", apiPort: "4000", p2pPort: "9000"},
}

// vcDef is the validator-client launch profile paired with each BN.
type vcDef struct {
	image   string
	apiPort string // BN's beacon API port inside the container
	// script is the VC entrypoint inside the image. Only lighthouse needs
	// the genesis.ssz staging wrapper; the other VC scripts read config
	// straight from /hive/input.
	script string
}

var vcDefs = map[string]vcDef{
	"lighthouse": {
		image:   "hive/clients/lighthouse-vc:local",
		apiPort: "4000",
		script:  "/lighthouse_vc.sh",
	},
	"teku":     {image: "hive/clients/teku-vc:local", apiPort: "4000", script: "/teku_vc.sh"},
	"prysm":    {image: "hive/clients/prysm-vc:local", apiPort: "4000", script: "/prysm_vc.sh"},
	"nimbus":   {image: "hive/clients/nimbus-vc:local", apiPort: "4000", script: "/nimbus_vc.sh"},
	"lodestar": {image: "hive/clients/lodestar-vc:local", apiPort: "4000", script: "/lodestar_vc.sh"},
	// Upstream hive has no clients/grandine-vc (only grandine-bn), and
	// grandine.sh wires no validators into the BN — it cannot self-propose.
	// The lighthouse VC drives any BN through the standard validator API,
	// so grandine is paired with it deliberately. The pairing ran live in
	// the six-client hive run of 2026-09-11 (full standard tier, all 215
	// cases executed with grandine participating).
	"grandine": {image: "hive/clients/lighthouse-vc:local", apiPort: "4000", script: "/lighthouse_vc.sh"},
}

// hiveImage resolves a local build name against an optional registry
// repository: with ImageRepo set (e.g. ghcr.io/org/hive-clients) images
// come from there — docker run pulls them automatically — while an empty
// repo keeps the local build names.
func hiveImage(repo, local string) string {
	if repo == "" {
		return local
	}
	return repo + "/" + strings.TrimPrefix(local, "hive/clients/")
}

// EL image and ports: the geth hive client, with authrpc on 8551 (the
// shared hardcoded jwtsecret convention pairs it with the CL scripts).
// depositContractAddr must match the contract embedded by hivegen into
// the EL genesis (BuildExecutionGenesis uses 0x4242...4242).
const depositContractAddr = "0x4242424242424242424242424242424242424242"

const (
	elImage    = "hive/clients/go-ethereum"
	elHTTPPort = "8545"
	elAuthPort = "8551"
	elP2PPort  = "30303"
)

// cmdRunner executes a docker command and returns combined output.
// Injectable so tests can assert the orchestration sequence.
type cmdRunner interface {
	Run(args ...string) (string, error)
}

type dockerCLI struct{}

func (dockerCLI) Run(args ...string) (string, error) {
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Environment is the running hive-provisioned network.
type Environment struct {
	runner   cmdRunner
	enclave  string
	eps      []env.Endpoint
	identity func(base string) (peerID string, err error)
}

func (e *Environment) Endpoints() []env.Endpoint { return e.eps }

func (e *Environment) Logs(ctx context.Context, ep env.Endpoint, since time.Time) (io.ReadCloser, error) {
	out, err := e.runner.Run("logs", "--since", since.Format(time.RFC3339), ep.Service)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(strings.NewReader(out)), nil
}

func (e *Environment) Info() map[string]string {
	return map[string]string{"provider": "hive", "enclave": e.enclave}
}

func (e *Environment) Teardown(ctx context.Context) error {
	for _, ep := range e.eps {
		_, _ = e.runner.Run("rm", "-f", ep.Service)
	}
	_, _ = e.runner.Run("rm", "-f", e.enclave+"-geth")
	_, _ = e.runner.Run("network", "rm", e.enclave+"-net")
	return nil
}

// Provider implements env.Provider for the hive path.
type Provider struct {
	// Runner executes docker commands; nil selects the docker CLI.
	Runner cmdRunner
	// Identity fetches the node's peer ID from its beacon API. Nil selects
	// the default HTTP fetcher.
	Identity func(base string) (string, error)
	// Probe reports whether an HTTP endpoint answers. Nil selects a real
	// GET; tests inject a stub to stay offline.
	Probe func(url string) bool
}

func (p *Provider) probe(url string) bool {
	if p.Probe != nil {
		return p.Probe(url)
	}
	resp, err := http.Get(url)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

func (p *Provider) Name() string { return "hive" }

// Setup launches the EL and the configured CL clients and returns their
// endpoints. The genesis directory must already contain the hivegen
// output.
func (p *Provider) Setup(ctx context.Context, cfg any) (env.Environment, error) {
	hcfg, ok := cfg.(Config)
	if !ok {
		return nil, fmt.Errorf("hive provider expects hiveenv.Config, got %T", cfg)
	}
	// docker bind mounts require absolute host paths.
	abs, err := filepath.Abs(hcfg.GenDir)
	if err != nil {
		return nil, err
	}
	hcfg.GenDir = abs
	for _, f := range []string{"genesis.json", "genesis.ssz", "config.yaml"} {
		if _, err := lookupFile(hcfg.GenDir, f); err != nil {
			return nil, fmt.Errorf("genesis dir %s: %w (generate with hive-sim/cmd/hivegen)", hcfg.GenDir, err)
		}
	}
	if len(hcfg.ClientTypes) == 0 {
		hcfg.ClientTypes = []string{"lighthouse"}
	}
	for _, ct := range hcfg.ClientTypes {
		if _, ok := clientDefs[ct]; !ok {
			return nil, fmt.Errorf("no hive client profile for %q (have: lighthouse)", ct)
		}
	}

	runner := p.Runner
	if runner == nil {
		runner = dockerCLI{}
	}
	repo := hcfg.ImageRepo

	// Image resolution + pre-flight. With ImageRepo empty the images are
	// local builds and must already exist — they cannot be pulled — so a
	// missing one aborts here with the build hint. With ImageRepo set the
	// names live under that repository and missing ones are pulled on the
	// spot (docker run would pull them anyway; doing it up front gives
	// visible progress and clearer errors).
	required := []string{hiveImage(repo, elImage)}
	for _, ct := range hcfg.ClientTypes {
		required = append(required, hiveImage(repo, clientDefs[ct].image), hiveImage(repo, vcDefs[ct].image))
	}
	var missing []string
	seen := map[string]bool{}
	for _, img := range required {
		if seen[img] {
			continue
		}
		seen[img] = true
		if _, err := runner.Run("image", "inspect", img); err != nil {
			missing = append(missing, img)
		}
	}
	if len(missing) > 0 && repo == "" {
		return nil, fmt.Errorf(
			"missing local docker images: %s\n"+
				"they cannot be pulled — build them with scripts/build-hive-images.sh,\n"+
				"or set -hive-image-repo to a repository that carries them\n"+
				"(and make sure docker points at the daemon holding the images: DOCKER_HOST / docker context)",
			strings.Join(missing, ", "))
	}
	for _, img := range missing {
		fmt.Fprintf(os.Stdout, "==> pulling %s\n", img)
		if out, err := runner.Run("pull", img); err != nil {
			return nil, fmt.Errorf("pull %s: %s", img, out)
		}
	}

	// Sweep leftovers from previous runs sharing this enclave name: stale
	// containers keep proposing on an old chain and poison the new one.
	if out, err := runner.Run("ps", "-aq", "--filter", "name=^/"+hcfg.Enclave+"-"); err == nil && strings.TrimSpace(out) != "" {
		for _, id := range strings.Fields(out) {
			_, _ = runner.Run("rm", "-f", id)
		}
	}
	identity := p.Identity
	if identity == nil {
		identity = func(base string) (string, error) {
			pid, _, err := fetchIdentity(base)
			return pid, err
		}
	}
	e := &Environment{runner: runner, enclave: hcfg.Enclave, identity: identity}

	// Network: create if missing (idempotent for restarts).
	if out, err := runner.Run("network", "create", hcfg.Enclave+"-net"); err != nil &&
		!strings.Contains(out, "already exists") {
		return nil, fmt.Errorf("create network: %s", out)
	}

	// EL first: geth.sh initializes from /genesis.json and enables the
	// authrpc endpoint when HIVE_TERMINAL_TOTAL_DIFFICULTY is set. The
	// mapper rebuilds the chain config from HIVE_* env vars, discarding
	// the genesis.json config entirely, so the fork schedule must be
	// re-fed here (read back from the hivegen output).
	genJSON, _ := lookupFile(hcfg.GenDir, "genesis.json")
	genMeta := readGenesisMeta(genJSON)
	gethName := hcfg.Enclave + "-geth"
	_, _ = runner.Run("rm", "-f", gethName)
	if out, err := runner.Run("run", "-d", "--name", gethName,
		"--network", hcfg.Enclave+"-net",
		"-p", elHTTPPort,
		"-p", elAuthPort,
		"-p", elP2PPort,
		"-p", elP2PPort+"/udp",
		"-v", genJSON+":/genesis.json.src:ro",
		"-e", "HIVE_TERMINAL_TOTAL_DIFFICULTY=0",
		"-e", "HIVE_NETWORK_ID=7",
		"-e", fmt.Sprintf("HIVE_CHAIN_ID=%d", genMeta.ChainID),
		"-e", fmt.Sprintf("HIVE_SHANGHAI_TIMESTAMP=%d", genMeta.GenesisTime),
		"-e", fmt.Sprintf("HIVE_CANCUN_TIMESTAMP=%d", genMeta.GenesisTime),
		// pre-merge forks all activate at genesis; leaving any of them
		// unset violates the fork ordering check.
		"-e", "HIVE_FORK_HOMESTEAD=0",
		"-e", "HIVE_FORK_TANGERINE=0",
		"-e", "HIVE_FORK_SPURIOUS=0",
		"-e", "HIVE_FORK_BYZANTIUM=0",
		"-e", "HIVE_FORK_CONSTANTINOPLE=0",
		"-e", "HIVE_FORK_PETERSBURG=0",
		"-e", "HIVE_FORK_ISTANBUL=0",
		"-e", "HIVE_FORK_MUIR_GLACIER=0",
		"-e", "HIVE_FORK_BERLIN=0",
		"-e", "HIVE_FORK_LONDON=0",
		"-e", "HIVE_FORK_ARROW_GLACIER=0",
		"-e", "HIVE_FORK_GRAY_GLACIER=0",
		"-e", "HIVE_MERGE_BLOCK_ID=0",
		"--entrypoint", "sh",
		hiveImage(repo, elImage),
		"-c", "cp /genesis.json.src /genesis.json && exec /geth.sh",
	); err != nil {
		return nil, fmt.Errorf("start geth: %s", out)
	}
	elURL, err := hostPortURL(runner, gethName, elHTTPPort)
	if err != nil {
		return nil, err
	}
	if err := waitProbe(ctx, p, elURL, 60*time.Second); err != nil {
		return nil, fmt.Errorf("geth rpc not ready: %w", err)
	}
	gethIP, err := containerIP(runner, hcfg.Enclave+"-net", gethName)
	if err != nil {
		return nil, err
	}

	// CL clients: each mounts /hive/input and pairs with the EL over the
	// container network (hardcoded shared jwtsecret convention).
	for i, ct := range hcfg.ClientTypes {
		def := clientDefs[ct]
		name := fmt.Sprintf("%s-cl-%d-%s", hcfg.Enclave, i+1, ct)
		_, _ = runner.Run("rm", "-f", name)
		if out, err := runner.Run("run", "-d", "--name", name,
			"--network", hcfg.Enclave+"-net",
			"-p", def.apiPort,
			"-p", def.p2pPort,
			"-p", def.p2pPort+"/udp",
			// read-write: prysm's entrypoint runs sed -i on the config,
			// which renames the file inside the mount
			"-v", hcfg.GenDir+":/hive/input",
			"-e", "HIVE_ETH2_MERGE_ENABLED=1",
			"-e", "HIVE_ETH2_ETH1_ENGINE_RPC_ADDRS=http://"+gethIP+":"+elAuthPort,
			"-e", "HIVE_ETH2_CONFIG_DEPOSIT_CONTRACT_ADDRESS="+depositContractAddr,
			"-e", "HIVE_ETH2_DEPOSIT_DEPLOY_BLOCK_NUMBER=0",
			"-e", "HIVE_ETH2_BEACON_NODE_INDEX="+fmt.Sprint(i),
			"-e", "HIVE_ETH2_BN_API_PORT="+def.apiPort,
			"-e", "HIVE_ETH2_P2P_TCP_PORT="+def.p2pPort,
			"-e", "HIVE_ETH2_P2P_UDP_PORT="+def.p2pPort,
			hiveImage(repo, def.image),
		); err != nil {
			return nil, fmt.Errorf("start %s: %s", ct, out)
		}
		apiBase, err := hostPortURL(runner, name, def.apiPort)
		if err != nil {
			return nil, err
		}
		if err := waitReady(ctx, apiBase, 90*time.Second, identity); err != nil {
			return nil, fmt.Errorf("client %s: %w", ct, err)
		}
		peerID, err := identity(apiBase)
		if err != nil {
			return nil, err
		}
		p2pHost, err := hostPort(runner, name, def.p2pPort)
		if err != nil {
			return nil, err
		}
		e.eps = append(e.eps, env.Endpoint{
			Name:       name,
			ClientType: ct,
			Service:    name,
			Multiaddr:  fmt.Sprintf("/ip4/127.0.0.1/tcp/%s/p2p/%s", p2pHost, peerID),
			BeaconAPI:  apiBase,
		})

		// Validator client so the chain actually progresses: without
		// proposers the head stays at slot 0 and the beacon /health
		// endpoint keeps returning 503 (syncing), which bans every
		// client before any case can run.
		vdef, ok := vcDefs[ct]
		if !ok {
			return nil, fmt.Errorf("no vc profile for %q", ct)
		}
		vc := hiveImage(repo, vdef.image)
		vcName := fmt.Sprintf("%s-vc-%d-%s", hcfg.Enclave, i+1, ct)
		_, _ = runner.Run("rm", "-f", vcName)
		if out, err := runner.Run("run", "-d", "--name", vcName,
			"--network", hcfg.Enclave+"-net",
			"-v", hcfg.GenDir+":/hive/input",
			"-e", "HIVE_ETH2_CONFIG_DEPOSIT_CONTRACT_ADDRESS="+depositContractAddr,
			"-e", "HIVE_ETH2_BN_API_IP="+name,
			"-e", "HIVE_ETH2_BN_API_PORT="+def.apiPort,
			vc,
			vdef.script,
		); err != nil {
			return nil, fmt.Errorf("start vc %s: %s", ct, out)
		}
	}

	// Wait out the pre-genesis window: before genesis the beacon nodes
	// answer inconsistently (VCs are not producing yet), which shows up
	// as flaky first-case verdicts. Genesis time comes from the hivegen
	// output; a couple of extra slots lets the first proposals land.
	if genMeta.GenesisTime > 0 {
		target := time.Unix(int64(genMeta.GenesisTime), 0).Add(12 * time.Second)
		if d := time.Until(target); d > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d):
			}
		}
	}
	return e, nil
}

// genesisMeta carries the values geth's mapper needs to rebuild the chain
// config from HIVE_* env vars (the mapper discards the genesis.json config
// block entirely).
type genesisMeta struct {
	GenesisTime uint64
	ChainID     uint64
}

func readGenesisMeta(path string) genesisMeta {
	var m genesisMeta
	data, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	var g struct {
		Timestamp string `json:"timestamp"`
		Config    struct {
			ChainID uint64 `json:"chainId"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &g) != nil {
		return m
	}
	_, _ = fmt.Sscanf(g.Timestamp, "0x%x", &m.GenesisTime)
	if m.GenesisTime == 0 {
		_, _ = fmt.Sscanf(g.Timestamp, "%d", &m.GenesisTime)
	}
	m.ChainID = g.Config.ChainID
	return m
}

func lookupFile(dir, name string) (string, error) {
	p := filepath.Join(dir, name)
	if _, err := os.Stat(p); err != nil {
		return "", err
	}
	return p, nil
}

// containerIP resolves a container's address on the shared network. The
// engine API rejects requests whose Host header is a domain name
// (authrpc.vhosts defaults to localhost, IP literals are exempt), so the
// CL clients must dial geth by IP.
func containerIP(runner cmdRunner, network, container string) (string, error) {
	out, err := runner.Run("inspect", "-f",
		"{{(index .NetworkSettings.Networks \""+network+"\").IPAddress}}", container)
	ip := strings.TrimSpace(out)
	if err != nil || ip == "" || strings.HasPrefix(ip, "<") {
		return "", fmt.Errorf("resolve ip of %s: %q (%v)", container, ip, err)
	}
	return ip, nil
}

// hostPort returns the host-side port docker mapped for containerPort.
func hostPort(runner cmdRunner, container, containerPort string) (string, error) {
	out, err := runner.Run("port", container, containerPort)
	if err != nil {
		return "", fmt.Errorf("port %s %s: %s", container, containerPort, out)
	}
	line := strings.TrimSpace(strings.Split(out, "\n")[0])
	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected docker port output: %q", out)
	}
	return fields[len(fields)-1], nil
}

func hostPortURL(runner cmdRunner, container, containerPort string) (string, error) {
	p, err := hostPort(runner, container, containerPort)
	if err != nil {
		return "", err
	}
	return "http://localhost:" + p, nil
}

// hostPortOr is hostPort with a container-port fallback when mapping
// cannot be resolved (used pre-mapping for the readiness probe target).
func hostPortOr(runner cmdRunner, container, containerPort string) string {
	p, err := hostPort(runner, container, containerPort)
	if err != nil {
		return containerPort
	}
	return p
}

func waitProbe(ctx context.Context, p *Provider, url string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if p.probe(url) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("not ready within %v", wait)
}

// waitReady polls the beacon API identity endpoint until the client
// answers, then returns nil.
func waitReady(ctx context.Context, base string, wait time.Duration, identity func(string) (string, error)) error {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if _, err := identity(base); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("identity not ready within %v", wait)
}

func fetchIdentity(base string) (peerID string, forkDigest [4]byte, err error) {
	resp, err := http.Get(strings.TrimRight(base, "/") + "/eth/v1/node/identity")
	if err != nil {
		return "", forkDigest, err
	}
	defer resp.Body.Close()
	var body struct {
		Data struct {
			PeerID string `json:"peer_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", forkDigest, err
	}
	if body.Data.PeerID == "" {
		return "", forkDigest, fmt.Errorf("empty peer id")
	}
	return body.Data.PeerID, forkDigest, nil
}
