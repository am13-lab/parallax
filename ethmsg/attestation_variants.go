package ethmsg

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// attestation_variants.go — buildInvalid<BeaconAttestation><Class> variants: each
// constructs a Fulu SingleAttestation that violates exactly one gossip validation
// rule while remaining otherwise well-formed and (except sig_invalid) validly
// signed, so a rejecting client is reacting to the targeted violation. Offline
// tests confirm structure + signature semantics; live acceptance is the runtime
// milestone.

// singleAttWith assembles a SingleAttestation for `attesterIndex` over the given
// data, signed by `signer` (== attesterIndex for a valid signature; a different
// index deliberately yields a signature that fails verification for the claimed
// attester, isolating sig_invalid).
func (sc SignContext) singleAttWith(attesterIndex, committeeIndex, signer uint64, data *phase0.AttestationData) ([]byte, error) {
	root, err := data.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("attestation data htr: %w", err)
	}
	sig, err := sc.sign(signer, root, DomainBeaconAttester)
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	att := &electra.SingleAttestation{
		CommitteeIndex: phase0.CommitteeIndex(committeeIndex),
		AttesterIndex:  phase0.ValidatorIndex(attesterIndex),
		Data:           data,
		Signature:      phase0.BLSSignature(mustSig96(sig)),
	}
	return att.MarshalSSZ()
}

// BuildInvalidBeaconAttestationSlotEpochRange: target.epoch does not match the
// epoch of data.slot (violates the attestation epoch/slot-consistency rule).
func BuildInvalidBeaconAttestationSlotEpochRange(sc SignContext, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	data := sc.attestationData(slot, committeeIndex)
	data.Target.Epoch = phase0.Epoch(sc.CurrentEpoch + 8) // inconsistent with slot's epoch
	return sc.singleAttWith(attesterIndex, committeeIndex, attesterIndex, data)
}

// BuildInvalidBeaconAttestationIndexOob: committee index far above
// MAX_COMMITTEES_PER_SLOT (violates the committee-index range rule).
func BuildInvalidBeaconAttestationIndexOob(sc SignContext, attesterIndex, slot uint64) ([]byte, error) {
	const oob = 1 << 20
	data := sc.attestationData(slot, oob)
	return sc.singleAttWith(attesterIndex, oob, attesterIndex, data)
}

// BuildInvalidBeaconAttestationSigInvalid: valid data, but signed by a different
// validator so the signature fails verification for the claimed attester.
func BuildInvalidBeaconAttestationSigInvalid(sc SignContext, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	data := sc.attestationData(slot, committeeIndex)
	return sc.singleAttWith(attesterIndex, committeeIndex, attesterIndex+1, data)
}

// BuildInvalidBeaconAttestationTargetRootConsistent: the target root is
// inconsistent with the beacon block root the vote references.
func BuildInvalidBeaconAttestationTargetRootConsistent(sc SignContext, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	data := sc.attestationData(slot, committeeIndex)
	var other [32]byte
	for i := range other {
		other[i] = 0xA5 // distinct from HeadRoot
	}
	data.Target.Root = phase0.Root(other)
	return sc.singleAttWith(attesterIndex, committeeIndex, attesterIndex, data)
}

// BuildInvalidBeaconAttestationFinalizedAncestor: the source checkpoint root is not
// the finalized ancestor (a fabricated root).
func BuildInvalidBeaconAttestationFinalizedAncestor(sc SignContext, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	data := sc.attestationData(slot, committeeIndex)
	var other [32]byte
	for i := range other {
		other[i] = 0x5A
	}
	data.Source.Root = phase0.Root(other)
	return sc.singleAttWith(attesterIndex, committeeIndex, attesterIndex, data)
}
