package ethmsg

import (
	"fmt"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// contribution.go — a valid sync_committee_contribution_and_proof and buildInvalid
// variants. The contribution's signature is (for a single participant) that
// validator's sync signature over the head block root under DOMAIN_SYNC_COMMITTEE;
// the selection proof is over SyncAggregatorSelectionData under
// DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF; the outer signature is over
// ContributionAndProof under DOMAIN_CONTRIBUTION_AND_PROOF. All the aggregator's,
// except the contribution signature which is the participant's.

func (sc SignContext) contribution(participantIndex, slot, subcommitteeIndex uint64) (*altair.SyncCommitteeContribution, error) {
	return sc.contributionWithBit(participantIndex, slot, subcommitteeIndex, 0)
}

func (sc SignContext) contributionWithBit(participantIndex, slot, subcommitteeIndex, participantBitIndex uint64) (*altair.SyncCommitteeContribution, error) {
	if participantBitIndex >= 128 {
		return nil, fmt.Errorf("sync contribution bit index %d out of range", participantBitIndex)
	}
	sig, err := sc.sign(participantIndex, sc.HeadRoot, DomainSyncCommittee)
	if err != nil {
		return nil, fmt.Errorf("sign sync contribution: %w", err)
	}
	bits := bitfield.NewBitvector128()
	bits.SetBitAt(participantBitIndex, true)
	return &altair.SyncCommitteeContribution{
		Slot:              phase0.Slot(slot),
		BeaconBlockRoot:   phase0.Root(sc.HeadRoot),
		SubcommitteeIndex: subcommitteeIndex,
		AggregationBits:   bits,
		Signature:         phase0.BLSSignature(mustSig96(sig)),
	}, nil
}

func (sc SignContext) contributionAndProof(aggregatorIndex, participantIndex, slot, subcommitteeIndex uint64) (*altair.ContributionAndProof, error) {
	return sc.contributionAndProofWithBit(aggregatorIndex, participantIndex, slot, subcommitteeIndex, 0)
}

func (sc SignContext) contributionAndProofWithBit(aggregatorIndex, participantIndex, slot, subcommitteeIndex, participantBitIndex uint64) (*altair.ContributionAndProof, error) {
	contrib, err := sc.contributionWithBit(participantIndex, slot, subcommitteeIndex, participantBitIndex)
	if err != nil {
		return nil, err
	}
	selProof, err := SyncCommitteeSelectionProof(sc, aggregatorIndex, slot, subcommitteeIndex)
	if err != nil {
		return nil, err
	}
	return &altair.ContributionAndProof{
		AggregatorIndex: phase0.ValidatorIndex(aggregatorIndex),
		Contribution:    contrib,
		SelectionProof:  phase0.BLSSignature(mustSig96(selProof)),
	}, nil
}

// SyncCommitteeSelectionProof signs SyncAggregatorSelectionData for the given
// slot/subcommittee under DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF.
func SyncCommitteeSelectionProof(sc SignContext, validatorIndex, slot, subcommitteeIndex uint64) ([]byte, error) {
	selData := &altair.SyncAggregatorSelectionData{Slot: phase0.Slot(slot), SubcommitteeIndex: subcommitteeIndex}
	selRoot, err := selData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("selection data htr: %w", err)
	}
	selProof, err := sc.sign(validatorIndex, selRoot, DomainSyncCommitteeSelectionProof)
	if err != nil {
		return nil, fmt.Errorf("sign selection proof: %w", err)
	}
	return selProof, nil
}

func (sc SignContext) signContributionAndProof(cap *altair.ContributionAndProof, signer uint64) ([]byte, error) {
	root, err := cap.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("contribution-and-proof htr: %w", err)
	}
	outer, err := sc.sign(signer, root, DomainContributionAndProof)
	if err != nil {
		return nil, fmt.Errorf("sign contribution and proof: %w", err)
	}
	signed := &altair.SignedContributionAndProof{Message: cap, Signature: phase0.BLSSignature(mustSig96(outer))}
	return signed.MarshalSSZ()
}

// BuildSignedContributionAndProof builds a valid sync_committee_contribution_and_proof.
func BuildSignedContributionAndProof(sc SignContext, aggregatorIndex, participantIndex, slot, subcommitteeIndex uint64) ([]byte, error) {
	cap, err := sc.contributionAndProof(aggregatorIndex, participantIndex, slot, subcommitteeIndex)
	if err != nil {
		return nil, err
	}
	return sc.signContributionAndProof(cap, aggregatorIndex)
}

// BuildSignedContributionAndProofWithBit builds a signed contribution using the
// participant's actual index within the sync subcommittee.
func BuildSignedContributionAndProofWithBit(sc SignContext, aggregatorIndex, participantIndex, slot, subcommitteeIndex, participantBitIndex uint64) ([]byte, error) {
	cap, err := sc.contributionAndProofWithBit(aggregatorIndex, participantIndex, slot, subcommitteeIndex, participantBitIndex)
	if err != nil {
		return nil, err
	}
	return sc.signContributionAndProof(cap, aggregatorIndex)
}

// BuildInvalidSyncCommitteeContributionAndProofSigInvalid: the outer proof is signed
// by a different validator, so it fails verification for the named aggregator.
func BuildInvalidSyncCommitteeContributionAndProofSigInvalid(sc SignContext, aggregatorIndex, participantIndex, slot, subcommitteeIndex uint64) ([]byte, error) {
	cap, err := sc.contributionAndProof(aggregatorIndex, participantIndex, slot, subcommitteeIndex)
	if err != nil {
		return nil, err
	}
	return sc.signContributionAndProof(cap, aggregatorIndex+1) // wrong signer
}

// BuildInvalidSyncCommitteeContributionAndProofIndexOob: subcommittee index far
// above SYNC_COMMITTEE_SUBNET_COUNT.
func BuildInvalidSyncCommitteeContributionAndProofIndexOob(sc SignContext, aggregatorIndex, participantIndex, slot uint64) ([]byte, error) {
	return BuildSignedContributionAndProof(sc, aggregatorIndex, participantIndex, slot, 1<<20)
}

func BuildInvalidSyncCommitteeContributionAndProofSlotEpochRange(sc SignContext, aggregatorIndex, participantIndex, subcommitteeIndex uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return BuildSignedContributionAndProof(sc, aggregatorIndex, participantIndex, futureSlot, subcommitteeIndex)
}

func BuildInvalidSyncCommitteeContributionAndProofNoParticipants(sc SignContext, aggregatorIndex, participantIndex, slot, subcommitteeIndex uint64) ([]byte, error) {
	cap, err := sc.contributionAndProof(aggregatorIndex, participantIndex, slot, subcommitteeIndex)
	if err != nil {
		return nil, err
	}
	cap.Contribution.AggregationBits = bitfield.NewBitvector128()
	return sc.signContributionAndProof(cap, aggregatorIndex)
}
