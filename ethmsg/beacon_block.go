package ethmsg

import (
	"fmt"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
)

// beacon_block.go — a structurally-complete, validly-signed beacon_block
// (electra.SignedBeaconBlock, the structure Fulu reuses) and buildInvalid variants.
// The block body carries empty operation lists and an empty execution payload; the
// RANDAO reveal and proposer signature are real. Gossip block validation checks the
// proposer signature/index/slot/parent — not full state-transition validity — so a
// zeroed body is fine for isolating those rules.

// emptyExecutionPayload returns a structurally-valid deneb ExecutionPayload with
// zero scalars and empty lists (all pointers non-nil so SSZ marshals).
func emptyExecutionPayload() *deneb.ExecutionPayload {
	return &deneb.ExecutionPayload{
		LogsBloom:     [256]byte{},
		ExtraData:     []byte{},
		BaseFeePerGas: uint256.NewInt(0),
		Transactions:  []bellatrix.Transaction{},
		Withdrawals:   []*capella.Withdrawal{},
	}
}

// beaconBlock assembles a block; the proposer signs the RANDAO reveal over the epoch.
func (sc SignContext) beaconBlock(proposerIndex, slot uint64, parentRoot, stateRoot [32]byte, randaoSigner uint64) (*electra.BeaconBlock, error) {
	epoch := slot / slotsPerEpoch
	randao, err := sc.sign(randaoSigner, htrUint64(epoch), DomainRandao)
	if err != nil {
		return nil, fmt.Errorf("sign randao: %w", err)
	}
	body := &electra.BeaconBlockBody{
		RANDAOReveal:          phase0.BLSSignature(mustSig96(randao)),
		ETH1Data:              &phase0.ETH1Data{BlockHash: make([]byte, 32)},
		Graffiti:              [32]byte{},
		ProposerSlashings:     []*phase0.ProposerSlashing{},
		AttesterSlashings:     []*electra.AttesterSlashing{},
		Attestations:          []*electra.Attestation{},
		Deposits:              []*phase0.Deposit{},
		VoluntaryExits:        []*phase0.SignedVoluntaryExit{},
		SyncAggregate:         &altair.SyncAggregate{SyncCommitteeBits: bitfield.NewBitvector512()},
		ExecutionPayload:      emptyExecutionPayload(),
		BLSToExecutionChanges: []*capella.SignedBLSToExecutionChange{},
		BlobKZGCommitments:    []deneb.KZGCommitment{},
		ExecutionRequests: &electra.ExecutionRequests{
			Deposits:       []*electra.DepositRequest{},
			Withdrawals:    []*electra.WithdrawalRequest{},
			Consolidations: []*electra.ConsolidationRequest{},
		},
	}
	return &electra.BeaconBlock{
		Slot:          phase0.Slot(slot),
		ProposerIndex: phase0.ValidatorIndex(proposerIndex),
		ParentRoot:    phase0.Root(parentRoot),
		StateRoot:     phase0.Root(stateRoot),
		Body:          body,
	}, nil
}

// signBlock signs the block under DOMAIN_BEACON_PROPOSER with `signer` and returns
// the SSZ-encoded SignedBeaconBlock.
func (sc SignContext) signBlock(block *electra.BeaconBlock, signer uint64) ([]byte, error) {
	root, err := block.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("block htr: %w", err)
	}
	sig, err := sc.sign(signer, root, DomainBeaconProposer)
	if err != nil {
		return nil, fmt.Errorf("sign block: %w", err)
	}
	signed := &electra.SignedBeaconBlock{Message: block, Signature: phase0.BLSSignature(mustSig96(sig))}
	return signed.MarshalSSZ()
}

// BuildBeaconBlock builds a valid, validly-signed beacon_block for the proposer.
func BuildBeaconBlock(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	block, err := sc.beaconBlock(proposerIndex, slot, sc.HeadRoot, sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	return sc.signBlock(block, proposerIndex)
}

// BuildBeaconBlockVariant builds a validly-signed beacon_block whose graffiti byte
// distinguishes it from other variants at the same (slot, proposer). Two variants
// with different bytes form a proposer-equivocation pair: two distinct blocks (their
// hash tree roots differ via graffiti) sharing one slot and proposer, which is the
// shape Hive's blobber "invalid equivocating block" scenario broadcasts.
func BuildBeaconBlockVariant(sc SignContext, proposerIndex, slot uint64, variant byte) ([]byte, error) {
	block, err := sc.beaconBlock(proposerIndex, slot, sc.HeadRoot, sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	block.Body.Graffiti[0] = variant
	return sc.signBlock(block, proposerIndex)
}

// BuildInvalidBeaconBlockParentKnownValid: the parent root is a fabricated (unknown)
// root, isolating the "parent has been seen / passes validation" rule.
func BuildInvalidBeaconBlockParentKnownValid(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	block, err := sc.beaconBlock(proposerIndex, slot, distinctRoot(0x77), sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	return sc.signBlock(block, proposerIndex)
}

// BuildInvalidBeaconBlockSigInvalid: the block is signed by a different validator, so
// the proposer signature fails verification.
func BuildInvalidBeaconBlockSigInvalid(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	block, err := sc.beaconBlock(proposerIndex, slot, sc.HeadRoot, sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	return sc.signBlock(block, proposerIndex+1) // wrong signer
}

// BuildInvalidBeaconBlockSlotFuture: the block slot is far in the future.
func BuildInvalidBeaconBlockSlotFuture(sc SignContext, proposerIndex uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	block, err := sc.beaconBlock(proposerIndex, futureSlot, sc.HeadRoot, sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	return sc.signBlock(block, proposerIndex)
}

// BuildInvalidBeaconBlockProposerIndexOob sets proposer_index outside the validator
// registry range while signing with a valid local key so the payload still encodes.
func BuildInvalidBeaconBlockProposerIndexOob(sc SignContext, slot uint64) ([]byte, error) {
	const oob = 1 << 40
	block, err := sc.beaconBlock(oob, slot, sc.HeadRoot, sc.HeadRoot, 0)
	if err != nil {
		return nil, err
	}
	return sc.signBlock(block, 0)
}

// BuildInvalidBeaconBlockTimestampCorrect sets an execution payload timestamp that
// cannot be the slot-derived timestamp for a live post-genesis block.
func BuildInvalidBeaconBlockTimestampCorrect(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	block, err := sc.beaconBlock(proposerIndex, slot, sc.HeadRoot, sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	block.Body.ExecutionPayload.Timestamp = 1
	return sc.signBlock(block, proposerIndex)
}

// BuildInvalidBeaconBlockKzgProof adds more blob KZG commitments than the Electra
// per-block limit while staying under the SSZ list maximum.
func BuildInvalidBeaconBlockKzgProof(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	block, err := sc.beaconBlock(proposerIndex, slot, sc.HeadRoot, sc.HeadRoot, proposerIndex)
	if err != nil {
		return nil, err
	}
	block.Body.BlobKZGCommitments = make([]deneb.KZGCommitment, 10)
	return sc.signBlock(block, proposerIndex)
}
