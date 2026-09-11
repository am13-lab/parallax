package ethmsg

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// attester_slashing.go — a valid AttesterSlashing (two conflicting IndexedAttestations
// by the same validator — a double vote) and buildInvalid variants. For simplicity a
// single attesting index is used, so the aggregate signature is that validator's lone
// signature over the AttestationData under DOMAIN_BEACON_ATTESTER.

func (sc SignContext) indexedAttestation(index, slot, committeeIndex uint64, targetRoot [32]byte, signer uint64) (*electra.IndexedAttestation, error) {
	data := sc.attestationData(slot, committeeIndex)
	data.Target.Root = phase0.Root(targetRoot) // distinguish the two conflicting votes
	root, err := data.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("attestation data htr: %w", err)
	}
	sig, err := sc.sign(signer, root, DomainBeaconAttester)
	if err != nil {
		return nil, fmt.Errorf("sign indexed attestation: %w", err)
	}
	return &electra.IndexedAttestation{
		AttestingIndices: []uint64{index},
		Data:             data,
		Signature:        phase0.BLSSignature(mustSig96(sig)),
	}, nil
}

// BuildAttesterSlashing builds a valid attester_slashing: two indexed attestations by
// the same validator for the same target epoch but different target roots (a double
// vote), each validly signed.
func BuildAttesterSlashing(sc SignContext, index, slot, committeeIndex uint64) ([]byte, error) {
	a1, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x11), index)
	if err != nil {
		return nil, err
	}
	a2, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x22), index)
	if err != nil {
		return nil, err
	}
	as := &electra.AttesterSlashing{Attestation1: a1, Attestation2: a2}
	return as.MarshalSSZ()
}

// BuildInvalidAttesterSlashingSigInvalid: attestation 2 is signed by a different
// validator, so its aggregate signature fails verification.
func BuildInvalidAttesterSlashingSigInvalid(sc SignContext, index, slot, committeeIndex uint64) ([]byte, error) {
	a1, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x11), index)
	if err != nil {
		return nil, err
	}
	a2, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x22), index+1) // wrong signer
	if err != nil {
		return nil, err
	}
	as := &electra.AttesterSlashing{Attestation1: a1, Attestation2: a2}
	return as.MarshalSSZ()
}

// BuildInvalidAttesterSlashingFieldEquality: both attestations are identical, so it is
// not a slashable pair.
func BuildInvalidAttesterSlashingFieldEquality(sc SignContext, index, slot, committeeIndex uint64) ([]byte, error) {
	a1, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x11), index)
	if err != nil {
		return nil, err
	}
	a2, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x11), index) // same data
	if err != nil {
		return nil, err
	}
	as := &electra.AttesterSlashing{Attestation1: a1, Attestation2: a2}
	return as.MarshalSSZ()
}

// BuildInvalidAttesterSlashingIndexOob uses an out-of-range attesting index in the
// second attestation while keeping the container otherwise well-formed.
func BuildInvalidAttesterSlashingIndexOob(sc SignContext, index, slot, committeeIndex uint64) ([]byte, error) {
	a1, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x11), index)
	if err != nil {
		return nil, err
	}
	a2, err := sc.indexedAttestation(1<<40, slot, committeeIndex, distinctRoot(0x22), index)
	if err != nil {
		return nil, err
	}
	as := &electra.AttesterSlashing{Attestation1: a1, Attestation2: a2}
	return as.MarshalSSZ()
}

// BuildInvalidAttesterSlashingNoSlashableIntersection uses two valid indexed
// attestations with disjoint participants, so the slashable intersection is empty.
func BuildInvalidAttesterSlashingNoSlashableIntersection(sc SignContext, index, slot, committeeIndex uint64) ([]byte, error) {
	a1, err := sc.indexedAttestation(index, slot, committeeIndex, distinctRoot(0x11), index)
	if err != nil {
		return nil, err
	}
	a2, err := sc.indexedAttestation(index+1, slot, committeeIndex, distinctRoot(0x22), index+1)
	if err != nil {
		return nil, err
	}
	as := &electra.AttesterSlashing{Attestation1: a1, Attestation2: a2}
	return as.MarshalSSZ()
}
