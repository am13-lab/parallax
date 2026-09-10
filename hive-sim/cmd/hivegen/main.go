// hivegen generates the provisioning files that hive CL client images
// expect under /hive/input: the EL genesis.json, the beacon genesis.ssz,
// and the consensus config/preset YAMLs.
//
// It lives in the hive-sim module because the genesis builder pulls the
// zrnt/marioevz dependency tree; the parallax-side hiveenv provider only
// reads the generated files, keeping the main module dependency-clean.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/hive/simulators/eth2/common/config"
	consensus_config "github.com/ethereum/hive/simulators/eth2/common/config/consensus"
	cl_genesis "github.com/ethereum/hive/simulators/eth2/common/config/consensus/genesis"
	el "github.com/ethereum/hive/simulators/eth2/common/config/execution"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/codec"
	"gopkg.in/yaml.v2"
)

// Classic BIP-39 test mnemonic (valid checksum), for ephemeral testnets only.
const testMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

func main() {
	out := flag.String("out", "", "output directory (required)")
	delay := flag.Duration("genesis-delay", 2*time.Minute, "genesis time = now + delay")
	validators := flag.Uint64("validators", 64, "validator count at genesis")
	slotsPerEpoch := flag.Uint64("slots-per-epoch", 8, "slots per epoch (testnet: small)")
	slotTime := flag.Uint64("slot-time", 4, "seconds per slot")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if err := run(*out, *delay, *validators, *slotsPerEpoch, *slotTime); err != nil {
		fmt.Fprintln(os.Stderr, "hivegen:", err)
		os.Exit(1)
	}
}

func run(out string, delay time.Duration, validators, slotsPerEpoch, slotTime uint64) error {
	genesisTime := time.Now().Add(delay)
	fmt.Printf("genesis at %s (in %s)\n", genesisTime.Format(time.RFC3339), delay)

	// Deneb genesis: every fork epoch 0, merged at genesis.
	forkConfig := &config.ForkConfig{
		TerminalTotalDifficulty: big.NewInt(0),
		AltairForkEpoch:         big.NewInt(0),
		BellatrixForkEpoch:      big.NewInt(0),
		CapellaForkEpoch:        big.NewInt(0),
		DenebForkEpoch:          big.NewInt(0),
	}
	chainConfig, err := el.BuildChainConfig(
		big.NewInt(0), // TTD 0: merged at genesis
		uint64(genesisTime.Unix()), slotsPerEpoch, slotTime, forkConfig,
	)
	if err != nil {
		return fmt.Errorf("build chain config: %w", err)
	}
	execGenesis, err := el.BuildExecutionGenesis(
		uint64(genesisTime.Unix()),
		&el.ExecutionPostMergeGenesis{},
		chainConfig,
		nil,
		big.NewInt(1_000_000_000),
	)
	if err != nil {
		return fmt.Errorf("build execution genesis: %w", err)
	}

	keySource := consensus_config.MnemonicsKeySource{
		From:     0,
		To:       validators,
		Mnemonic: testMnemonic,
	}
	keys, err := keySource.Keys()
	if err != nil {
		return fmt.Errorf("derive validator keys: %w", err)
	}

	spec, err := consensus_config.BuildSpec(
		configs.Mainnet,
		forkConfig,
		&consensus_config.ConsensusConfig{
			ValidatorCount: big.NewInt(int64(validators)),
			SlotsPerEpoch:  big.NewInt(int64(slotsPerEpoch)),
			SlotTime:       big.NewInt(int64(slotTime)),
		},
		common.Eth1Address{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42},
		execGenesis,
	)
	if err != nil {
		return fmt.Errorf("build spec: %w", err)
	}

	state, err := cl_genesis.BuildBeaconState(
		spec, execGenesis.Block, common.Timestamp(genesisTime.Unix()), keys,
	)
	if err != nil {
		return fmt.Errorf("build beacon state: %w", err)
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	write := func(name string, data []byte) error {
		p := filepath.Join(out, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d bytes)\n", p, len(data))
		return nil
	}

	elJSON, err := json.MarshalIndent(execGenesis.Genesis, "", "  ")
	if err != nil {
		return err
	}
	if err := write("genesis.json", elJSON); err != nil {
		return err
	}

	var stateBytes bytes.Buffer
	if err := state.Serialize(codec.NewEncodingWriter(&stateBytes)); err != nil {
		return fmt.Errorf("serialize beacon state: %w", err)
	}
	if err := write("genesis.ssz", stateBytes.Bytes()); err != nil {
		return err
	}

	// Validator client material: /hive/input/keystores/<pub>/keystore.json
	// plus /hive/input/secrets/<pub> (the lighthouse-vc convention).
	ksDir := filepath.Join(out, "keystores")
	secDir := filepath.Join(out, "secrets")
	if err := os.MkdirAll(ksDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(secDir, 0o755); err != nil {
		return err
	}
	for _, k := range keys {
		// lighthouse matches secrets files by the keystore's 0x-prefixed
		// pubkey field; the directory/file names must carry the prefix.
		pub := "0x" + fmt.Sprintf("%x", k.ValidatorPubkey)
		if err := os.MkdirAll(filepath.Join(ksDir, pub), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(ksDir, pub, "keystore.json"), k.ValidatorKeystoreJSON, 0o644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(secDir, pub), []byte(k.ValidatorKeystorePass), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d validator keystores under %s\n", len(keys), out)

	presets := map[string]any{
		"preset_phase0.yaml":    spec.Phase0Preset,
		"preset_altair.yaml":    spec.AltairPreset,
		"preset_bellatrix.yaml": spec.BellatrixPreset,
		"preset_capella.yaml":   spec.CapellaPreset,
		"preset_deneb.yaml":     spec.DenebPreset,
	}
	merged := map[string]any{}
	// Teku's testnet-dir mode reads a single config.yaml that must carry
	// the preset constants too (e.g. MAX_BLOBS_PER_BLOCK); merge every
	// preset into the config document before writing it.
	for _, obj := range presets {
		data, err := yaml.Marshal(obj)
		if err != nil {
			return fmt.Errorf("marshal preset: %w", err)
		}
		pm := map[string]any{}
		if err := yaml.Unmarshal(data, &pm); err != nil {
			return err
		}
		for k, v := range pm {
			merged[k] = v
		}
	}
	cm := map[string]any{}
	configData, err := yaml.Marshal(spec.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := yaml.Unmarshal(configData, &cm); err != nil {
		return err
	}
	for k, v := range cm {
		merged[k] = v
	}
	// Client compatibility (measured against current prysm/teku images):
	// - GOSSIP_MAX_SIZE was renamed MAX_PAYLOAD_SIZE at deneb; prysm
	//   rejects the old name, teku requires the new one.
	// - MAX_CHUNK_SIZE is likewise rejected by current prysm.
	// - An ELECTRA_FORK_VERSION without an epoch trips prysm's
	//   conflicting-fork-schedule check; we only target deneb.
	if v, ok := merged["GOSSIP_MAX_SIZE"]; ok {
		merged["MAX_PAYLOAD_SIZE"] = v
	}
	for _, k := range []string{"GOSSIP_MAX_SIZE", "MAX_CHUNK_SIZE"} {
		delete(merged, k)
	}
	// Prysm fills missing forks with mainnet defaults and then rejects the
	// conflicting schedule; declare electra/fulu explicitly on our custom
	// version chain at a far-future epoch (inactive for a deneb network).
	merged["ELECTRA_FORK_VERSION"] = "0x0500000a"
	merged["ELECTRA_FORK_EPOCH"] = "18446744073709551615"
	merged["FULU_FORK_VERSION"] = "0x0600000a"
	merged["FULU_FORK_EPOCH"] = "18446744073709551615"
	full, err := yaml.Marshal(merged)
	if err != nil {
		return fmt.Errorf("marshal merged config: %w", err)
	}
	if err := write("config.yaml", full); err != nil {
		return err
	}
	for name, obj := range presets {
		data, err := yaml.Marshal(obj)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}
		if err := write(name, data); err != nil {
			return err
		}
	}

	// Summary the orchestrator needs: genesis unix time is passed to
	// containers and the state root doubles as a sanity anchor.
	root := (&[32]byte{})
	_ = root
	fmt.Printf("genesis_unix=%d validators=%d slots_per_epoch=%d slot_time=%ds\n",
		genesisTime.Unix(), validators, slotsPerEpoch, slotTime)
	return nil
}

// keep config import referenced if marshalling of presets covers it
var _ = config.BytesSource
