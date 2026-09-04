package ethmsg

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// proposer_slashing.go — a valid ProposerSlashing (two conflicting block headers
// for the same slot+proposer, each validly signed) and buildInvalid variants that
// each break one validity rule while keeping the rest well-formed.

func (sc SignContext) signedHeader(proposerIndex, slot uint64, bodyRoot [32]byte, signer uint64) (*phase0.SignedBeaconBlockHeader, error) {
	h := &phase0.BeaconBlockHeader{
		Slot:          phase0.Slot(slot),
		ProposerIndex: phase0.ValidatorIndex(proposerIndex),
		ParentRoot:    phase0.Root(sc.HeadRoot),
		StateRoot:     phase0.Root(sc.HeadRoot),
		BodyRoot:      phase0.Root(bodyRoot),
	}
	root, err := h.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("header htr: %w", err)
	}
	sig, err := sc.sign(signer, root, DomainBeaconProposer)
	if err != nil {
		return nil, fmt.Errorf("sign header: %w", err)
	}
	return &phase0.SignedBeaconBlockHeader{Message: h, Signature: phase0.BLSSignature(mustSig96(sig))}, nil
}

func distinctRoot(b byte) [32]byte {
	var r [32]byte
	for i := range r {
		r[i] = b
	}
	return r
}

// BuildProposerSlashing builds a valid proposer_slashing: two headers for the same
// (slot, proposer) with different body roots, each signed by the proposer.
func BuildProposerSlashing(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	h1, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x11), proposerIndex)
	if err != nil {
		return nil, err
	}
	h2, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x22), proposerIndex)
	if err != nil {
		return nil, err
	}
	ps := &phase0.ProposerSlashing{SignedHeader1: h1, SignedHeader2: h2}
	return ps.MarshalSSZ()
}

// BuildInvalidProposerSlashingSigInvalid: header 2 is signed by a different
// validator, so its signature fails verification for the named proposer.
func BuildInvalidProposerSlashingSigInvalid(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	h1, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x11), proposerIndex)
	if err != nil {
		return nil, err
	}
	h2, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x22), proposerIndex+1) // wrong signer
	if err != nil {
		return nil, err
	}
	ps := &phase0.ProposerSlashing{SignedHeader1: h1, SignedHeader2: h2}
	return ps.MarshalSSZ()
}

// BuildInvalidProposerSlashingFieldEquality: the two headers are identical, so it is
// not a real (slashable) equivocation — violates "the two headers are different".
func BuildInvalidProposerSlashingFieldEquality(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	h1, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x11), proposerIndex)
	if err != nil {
		return nil, err
	}
	h2, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x11), proposerIndex) // same body root
	if err != nil {
		return nil, err
	}
	ps := &phase0.ProposerSlashing{SignedHeader1: h1, SignedHeader2: h2}
	return ps.MarshalSSZ()
}

// BuildInvalidProposerSlashingIndexOob: the proposer_index field is out of range.
// The headers are signed with a valid key (index 0) — the oob index can't be a
// derivation index — so the client rejects on the index, not a derive failure.
func BuildInvalidProposerSlashingIndexOob(sc SignContext, slot uint64) ([]byte, error) {
	const oob = 1 << 40
	h1, err := sc.signedHeader(oob, slot, distinctRoot(0x11), 0)
	if err != nil {
		return nil, err
	}
	h2, err := sc.signedHeader(oob, slot, distinctRoot(0x22), 0)
	if err != nil {
		return nil, err
	}
	ps := &phase0.ProposerSlashing{SignedHeader1: h1, SignedHeader2: h2}
	return ps.MarshalSSZ()
}
