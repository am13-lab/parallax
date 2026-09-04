package ethmsg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// messagefactory.go — builds fully-valid, signed, SSZ-encoded consensus messages
// (and, per the builder-variant model, deliberately-invalid re-signed variants that
// each isolate one gossip validation rule). Types are Fulu-exact: the devnet runs
// electra+fulu at genesis, so beacon_attestation is electra.SingleAttestation and
// aggregates use electra.Attestation (committee_bits).
//
// Signing capability + chain facts are threaded explicitly via SignContext (no
// package singletons), so the runtime passes a context derived from the live devnet.

const slotsPerEpoch = 32 // mainnet preset

// SignContext bundles the keystore and the live chain facts a builder needs to sign
// correctly. Offline tests set fixed values; the runtime fills them from the beacon
// API (fork schedule + /eth/v1/beacon/genesis).
type SignContext struct {
	Keys                  *Keystore
	ForkVersion           [4]byte
	GenesisForkVersion    [4]byte // for domains fixed to genesis (e.g. BLS_TO_EXECUTION_CHANGE)
	GenesisValidatorsRoot [32]byte
	CurrentEpoch          uint64
	HeadRoot              [32]byte
}

// sign signs an object root for validator `index` under the given domain type.
func (sc SignContext) sign(index uint64, objectRoot [32]byte, domainType [4]byte) ([]byte, error) {
	domain := ComputeDomain(domainType, sc.ForkVersion, sc.GenesisValidatorsRoot)
	return sc.Keys.SignObject(index, objectRoot, domain)
}

// --- voluntary_exit (fixed-size, hand-rolled SSZ) ---

func htrUint64Pair(a, b uint64) [32]byte {
	var c0, c1 [32]byte
	binary.LittleEndian.PutUint64(c0[:8], a)
	binary.LittleEndian.PutUint64(c1[:8], b)
	h := sha256.New()
	h.Write(c0[:])
	h.Write(c1[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func htrUint64(v uint64) [32]byte {
	var c [32]byte
	binary.LittleEndian.PutUint64(c[:8], v)
	return c
}

// VoluntaryExitRoot returns hash_tree_root(VoluntaryExit{epoch, validator_index}).
func VoluntaryExitRoot(epoch, validatorIndex uint64) [32]byte {
	return htrUint64Pair(epoch, validatorIndex)
}

// BuildSignedVoluntaryExit builds a valid SignedVoluntaryExit (112 bytes:
// epoch(8) ++ validator_index(8) ++ signature(96)), self-signed under
// DOMAIN_VOLUNTARY_EXIT.
func BuildSignedVoluntaryExit(sc SignContext, validatorIndex uint64) ([]byte, error) {
	return sc.signedVoluntaryExitWith(sc.CurrentEpoch, validatorIndex, validatorIndex)
}

func (sc SignContext) signedVoluntaryExitWith(epoch, validatorIndex, signer uint64) ([]byte, error) {
	root := VoluntaryExitRoot(epoch, validatorIndex)
	sig, err := sc.sign(signer, root, DomainVoluntaryExit)
	if err != nil {
		return nil, fmt.Errorf("sign voluntary exit: %w", err)
	}
	out := make([]byte, 0, 112)
	var num [8]byte
	binary.LittleEndian.PutUint64(num[:], epoch)
	out = append(out, num[:]...)
	binary.LittleEndian.PutUint64(num[:], validatorIndex)
	out = append(out, num[:]...)
	out = append(out, sig...)
	return out, nil
}

func BuildInvalidSignedVoluntaryExitSigInvalid(sc SignContext, validatorIndex uint64) ([]byte, error) {
	return sc.signedVoluntaryExitWith(sc.CurrentEpoch, validatorIndex, validatorIndex+1)
}

func BuildInvalidSignedVoluntaryExitIndexOob(sc SignContext) ([]byte, error) {
	const oob = 1 << 40
	return sc.signedVoluntaryExitWith(sc.CurrentEpoch, oob, 0)
}

func BuildInvalidSignedVoluntaryExitSlotFuture(sc SignContext, validatorIndex uint64) ([]byte, error) {
	return sc.signedVoluntaryExitWith(sc.CurrentEpoch+100, validatorIndex, validatorIndex)
}

// --- beacon_attestation (Fulu: electra.SingleAttestation) ---

func (sc SignContext) attestationData(slot, committeeIndex uint64) *phase0.AttestationData {
	sourceEpoch := sc.CurrentEpoch
	if sourceEpoch > 0 {
		sourceEpoch--
	}
	return &phase0.AttestationData{
		Slot:            phase0.Slot(slot),
		Index:           phase0.CommitteeIndex(committeeIndex),
		BeaconBlockRoot: phase0.Root(sc.HeadRoot),
		Source:          &phase0.Checkpoint{Epoch: phase0.Epoch(sourceEpoch), Root: phase0.Root(sc.HeadRoot)},
		Target:          &phase0.Checkpoint{Epoch: phase0.Epoch(sc.CurrentEpoch), Root: phase0.Root(sc.HeadRoot)},
	}
}

func (sc SignContext) singleAttestation(attesterIndex, slot, committeeIndex uint64) (*electra.SingleAttestation, error) {
	data := sc.attestationData(slot, committeeIndex)
	root, err := data.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("attestation data htr: %w", err)
	}
	sig, err := sc.sign(attesterIndex, root, DomainBeaconAttester)
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	return &electra.SingleAttestation{
		CommitteeIndex: phase0.CommitteeIndex(committeeIndex),
		AttesterIndex:  phase0.ValidatorIndex(attesterIndex),
		Data:           data,
		Signature:      phase0.BLSSignature(mustSig96(sig)),
	}, nil
}

// BuildSingleAttestation builds a valid beacon_attestation (electra.SingleAttestation).
func BuildSingleAttestation(sc SignContext, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	att, err := sc.singleAttestation(attesterIndex, slot, committeeIndex)
	if err != nil {
		return nil, err
	}
	return att.MarshalSSZ()
}

// BuildSingleAttestationFromData builds an Electra SingleAttestation from live
// Beacon API attestation data and signs it with the selected attester key.
func BuildSingleAttestationFromData(sc SignContext, attesterIndex uint64, data *phase0.AttestationData, committeeIndex uint64) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("attestation data is nil")
	}
	liveData := *data
	liveData.Index = 0
	root, err := liveData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("attestation data htr: %w", err)
	}
	sig, err := sc.sign(attesterIndex, root, DomainBeaconAttester)
	if err != nil {
		return nil, fmt.Errorf("sign attestation: %w", err)
	}
	att := &electra.SingleAttestation{
		CommitteeIndex: phase0.CommitteeIndex(committeeIndex),
		AttesterIndex:  phase0.ValidatorIndex(attesterIndex),
		Data:           &liveData,
		Signature:      phase0.BLSSignature(mustSig96(sig)),
	}
	return att.MarshalSSZ()
}

// BuildInvalidBeaconAttestationSlotFuture is the slot_future builder-variant: a
// fully-valid, validly-signed SingleAttestation whose slot is far in the future,
// isolating the "not from a future slot" violation. The signature is valid over the
// corrupted data, so a rejecting client is reacting to the slot, not a malformed
// payload. (Name matches the skeleton's buildInvalid<Topic><Class> convention.)
func BuildInvalidBeaconAttestationSlotFuture(sc SignContext, attesterIndex, committeeIndex uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return BuildSingleAttestation(sc, attesterIndex, futureSlot, committeeIndex)
}

// --- beacon_aggregate_and_proof (Fulu: electra.SignedAggregateAndProof) ---

// BuildSignedAggregateAndProof builds a valid beacon_aggregate_and_proof: an
// aggregated electra.Attestation (with committee_bits), a selection proof over the
// slot, and the outer AggregateAndProof signature — all the aggregator's, except the
// inner attestation which is the attester's.
func BuildSignedAggregateAndProof(sc SignContext, aggregatorIndex, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, committeeIndex, nil, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex)
}

func BuildSignedAggregateAndProofFromData(sc SignContext, aggregatorIndex, attesterIndex uint64, data *phase0.AttestationData, committeeIndex, committeeLength, validatorCommitteeIndex uint64) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("attestation data is nil")
	}
	if committeeLength == 0 {
		return nil, fmt.Errorf("committee length is zero")
	}
	if validatorCommitteeIndex >= committeeLength {
		return nil, fmt.Errorf("validator committee index %d >= committee length %d", validatorCommitteeIndex, committeeLength)
	}
	liveData := *data
	liveData.Index = 0
	aggBits := bitfield.NewBitlist(committeeLength)
	aggBits.SetBitAt(validatorCommitteeIndex, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWithData(aggregatorIndex, attesterIndex, &liveData, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex)
}

func SelectionProof(sc SignContext, validatorIndex, slot uint64) ([]byte, error) {
	return sc.sign(validatorIndex, htrUint64(slot), DomainSelectionProof)
}

func (sc SignContext) signedAggregateAndProofWith(
	aggregatorIndex, attesterIndex, slot, committeeIndex uint64,
	mutateData func(*phase0.AttestationData),
	aggBits bitfield.Bitlist,
	committeeBits bitfield.Bitvector64,
	attestationSigner, selectionSigner, outerSigner uint64,
) ([]byte, error) {
	data := sc.attestationData(slot, committeeIndex)
	if mutateData != nil {
		mutateData(data)
	}
	return sc.signedAggregateAndProofWithData(aggregatorIndex, attesterIndex, data, aggBits, committeeBits, attestationSigner, selectionSigner, outerSigner)
}

func (sc SignContext) signedAggregateAndProofWithData(
	aggregatorIndex, attesterIndex uint64,
	data *phase0.AttestationData,
	aggBits bitfield.Bitlist,
	committeeBits bitfield.Bitvector64,
	attestationSigner, selectionSigner, outerSigner uint64,
) ([]byte, error) {
	root, err := data.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("attestation data htr: %w", err)
	}
	attSig, err := sc.sign(attestationSigner, root, DomainBeaconAttester)
	if err != nil {
		return nil, fmt.Errorf("sign inner attestation: %w", err)
	}
	if aggBits == nil {
		aggBits = bitfield.NewBitlist(64)
		aggBits.SetBitAt(0, true)
	}
	if committeeBits == nil {
		committeeBits = bitfield.NewBitvector64()
		committeeBits.SetBitAt(uint64(data.Index)%64, true)
	}
	att := &electra.Attestation{
		AggregationBits: aggBits,
		Data:            data,
		Signature:       phase0.BLSSignature(mustSig96(attSig)),
		CommitteeBits:   committeeBits,
	}
	slot := uint64(data.Slot)
	selProof, err := sc.sign(aggregatorIndex, htrUint64(slot), DomainSelectionProof)
	if selectionSigner != aggregatorIndex {
		selProof, err = sc.sign(selectionSigner, htrUint64(slot), DomainSelectionProof)
	}
	if err != nil {
		return nil, fmt.Errorf("sign selection proof: %w", err)
	}
	agg := &electra.AggregateAndProof{
		AggregatorIndex: phase0.ValidatorIndex(aggregatorIndex),
		Aggregate:       att,
		SelectionProof:  phase0.BLSSignature(mustSig96(selProof)),
	}
	aggRoot, err := agg.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("aggregate htr: %w", err)
	}
	outer, err := sc.sign(outerSigner, aggRoot, DomainAggregateAndProof)
	if err != nil {
		return nil, fmt.Errorf("sign aggregate and proof: %w", err)
	}
	signed := &electra.SignedAggregateAndProof{Message: agg, Signature: phase0.BLSSignature(mustSig96(outer))}
	return signed.MarshalSSZ()
}

func BuildInvalidBeaconAggregateAndProofAggregateSigInvalid(sc SignContext, aggregatorIndex, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, committeeIndex, nil, aggBits, committeeBits, attesterIndex+1, aggregatorIndex, aggregatorIndex)
}

func BuildInvalidBeaconAggregateAndProofSelectionProofSigInvalid(sc SignContext, aggregatorIndex, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, committeeIndex, nil, aggBits, committeeBits, attesterIndex, aggregatorIndex+1, aggregatorIndex)
}

func BuildInvalidBeaconAggregateAndProofOuterSigInvalid(sc SignContext, aggregatorIndex, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, committeeIndex, nil, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex+1)
}

func BuildInvalidBeaconAggregateAndProofSlotFuture(sc SignContext, aggregatorIndex, attesterIndex, committeeIndex uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return BuildSignedAggregateAndProof(sc, aggregatorIndex, attesterIndex, futureSlot, committeeIndex)
}

func BuildInvalidBeaconAggregateAndProofSlotEpochRange(sc SignContext, aggregatorIndex, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, committeeIndex, func(data *phase0.AttestationData) {
		data.Target.Epoch = phase0.Epoch(sc.CurrentEpoch + 8)
	}, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex)
}

func BuildInvalidBeaconAggregateAndProofDataIndexNonZero(sc SignContext, aggregatorIndex, attesterIndex, slot uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(0, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, 0, func(data *phase0.AttestationData) {
		data.Index = 1
	}, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex)
}

func BuildInvalidBeaconAggregateAndProofMultipleCommitteeBits(sc SignContext, aggregatorIndex, attesterIndex, slot uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	aggBits.SetBitAt(0, true)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(0, true)
	committeeBits.SetBitAt(1, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, 0, nil, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex)
}

func BuildInvalidBeaconAggregateAndProofNoParticipants(sc SignContext, aggregatorIndex, attesterIndex, slot, committeeIndex uint64) ([]byte, error) {
	aggBits := bitfield.NewBitlist(64)
	committeeBits := bitfield.NewBitvector64()
	committeeBits.SetBitAt(committeeIndex%64, true)
	return sc.signedAggregateAndProofWith(aggregatorIndex, attesterIndex, slot, committeeIndex, nil, aggBits, committeeBits, attesterIndex, aggregatorIndex, aggregatorIndex)
}

// --- sync_committee_message ---

// BuildSyncCommitteeMessage builds a valid sync_committee_message: a validator
// signs the head beacon block root under DOMAIN_SYNC_COMMITTEE.
func BuildSyncCommitteeMessage(sc SignContext, validatorIndex, slot uint64) ([]byte, error) {
	sig, err := sc.sign(validatorIndex, sc.HeadRoot, DomainSyncCommittee)
	if err != nil {
		return nil, fmt.Errorf("sign sync committee message: %w", err)
	}
	msg := &altair.SyncCommitteeMessage{
		Slot:            phase0.Slot(slot),
		BeaconBlockRoot: phase0.Root(sc.HeadRoot),
		ValidatorIndex:  phase0.ValidatorIndex(validatorIndex),
		Signature:       phase0.BLSSignature(mustSig96(sig)),
	}
	return msg.MarshalSSZ()
}

func BuildInvalidSyncCommitteeMessageSigInvalid(sc SignContext, validatorIndex, slot uint64) ([]byte, error) {
	sig, err := sc.sign(validatorIndex+1, sc.HeadRoot, DomainSyncCommittee)
	if err != nil {
		return nil, fmt.Errorf("sign sync committee message: %w", err)
	}
	msg := &altair.SyncCommitteeMessage{
		Slot:            phase0.Slot(slot),
		BeaconBlockRoot: phase0.Root(sc.HeadRoot),
		ValidatorIndex:  phase0.ValidatorIndex(validatorIndex),
		Signature:       phase0.BLSSignature(mustSig96(sig)),
	}
	return msg.MarshalSSZ()
}

func BuildInvalidSyncCommitteeMessageIndexOob(sc SignContext, slot uint64) ([]byte, error) {
	const oob = 1 << 40
	sig, err := sc.sign(0, sc.HeadRoot, DomainSyncCommittee)
	if err != nil {
		return nil, fmt.Errorf("sign sync committee message: %w", err)
	}
	msg := &altair.SyncCommitteeMessage{
		Slot:            phase0.Slot(slot),
		BeaconBlockRoot: phase0.Root(sc.HeadRoot),
		ValidatorIndex:  phase0.ValidatorIndex(oob),
		Signature:       phase0.BLSSignature(mustSig96(sig)),
	}
	return msg.MarshalSSZ()
}

func BuildInvalidSyncCommitteeMessageSlotEpochRange(sc SignContext, validatorIndex uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return BuildSyncCommitteeMessage(sc, validatorIndex, futureSlot)
}

// mustSig96 narrows a 96-byte signature slice to the fixed array type.
func mustSig96(sig []byte) [96]byte {
	var s [96]byte
	copy(s[:], sig)
	return s
}
