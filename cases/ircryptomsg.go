package cases

import (
	"sync"

	"parallax/ethmsg"
	"parallax/wire"
)

// ircryptomsg.go — payload builders for the cryptomsg machine, ported from
// p2p-testing's internal/statemachine/cryptomsg_builders.go. Each wraps an
// ethmsg builder with the irContext signing facts and emits gossip-framed
// (raw snappy) output; nil payload means "no keystore / build error" and
// surfaces as a distinct verdict rather than panicking.

var (
	ksOnce sync.Once
	ksInst *ethmsg.Keystore
)

// defaultKeystore lazily derives the devnet validator keystore (read-only
// after creation).
func defaultKeystore() *ethmsg.Keystore {
	ksOnce.Do(func() { ksInst, _ = ethmsg.NewDevnetKeystore() })
	return ksInst
}

// irSignCtx builds an ethmsg.SignContext from the irContext's signing facts.
func irSignCtx(ctx *irContext) ethmsg.SignContext {
	return ethmsg.SignContext{
		Keys:                  ctx.Keys,
		ForkVersion:           ctx.ForkVersion,
		GenesisForkVersion:    ctx.GenesisForkVersion,
		GenesisValidatorsRoot: ctx.GenesisValidatorsRoot,
		CurrentEpoch:          ctx.CurrentEpoch,
		HeadRoot:              ctx.HeadRoot,
	}
}

// cm runs an ethmsg builder with the irContext's SignContext, guarding a
// missing keystore and mapping (payload, err) to a nil-on-error payload. The
// SSZ output is snappy-block-compressed (GossipSnappyEncode, NOT the req/resp
// framing) because the gossip domain publishes raw snappy(ssz).
func cm(ctx *irContext, fn func(ethmsg.SignContext) ([]byte, error)) []byte {
	if ctx.Keys == nil {
		return nil
	}
	b, err := fn(irSignCtx(ctx))
	if err != nil {
		return nil
	}
	return wire.GossipSnappyEncode(b)
}

// --- beacon_block ---

func buildValidBeaconBlock(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildBeaconBlock(sc, 0, ctx.HeadSlot) })
}
func buildInvalidBeaconBlockParentKnownValid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconBlockParentKnownValid(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidBeaconBlockSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconBlockSigInvalid(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidBeaconBlockSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildInvalidBeaconBlockSlotFuture(sc, 0) })
}
func buildInvalidBeaconBlockProposerIndexWrong(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconBlockProposerIndexOob(sc, ctx.HeadSlot)
	})
}
func buildInvalidBeaconBlockTimestampCorrect(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconBlockTimestampCorrect(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidBeaconBlockKzgProof(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconBlockKzgProof(sc, 0, ctx.HeadSlot)
	})
}

// --- beacon_attestation (electra.SingleAttestation) ---

func buildValidBeaconAttestation(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildSingleAttestation(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAttestationSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAttestationSlotFuture(sc, 0, 0)
	})
}
func buildInvalidBeaconAttestationSlotEpochRange(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAttestationSlotEpochRange(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAttestationIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAttestationIndexOob(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidBeaconAttestationSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAttestationSigInvalid(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAttestationTargetRootConsistent(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAttestationTargetRootConsistent(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAttestationFinalizedAncestor(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAttestationFinalizedAncestor(sc, 0, ctx.HeadSlot, 0)
	})
}

// --- beacon_aggregate_and_proof ---

func buildValidBeaconAggregateAndProof(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildSignedAggregateAndProof(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAggregateAndProofAggregateSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofAggregateSigInvalid(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAggregateAndProofSelectionProofSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofSelectionProofSigInvalid(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAggregateAndProofOuterSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofOuterSigInvalid(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAggregateAndProofSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofSlotFuture(sc, 0, 1, 0)
	})
}
func buildInvalidBeaconAggregateAndProofSlotEpochRange(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofSlotEpochRange(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidBeaconAggregateAndProofDataIndexNonZero(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofDataIndexNonZero(sc, 0, 1, ctx.HeadSlot)
	})
}
func buildInvalidBeaconAggregateAndProofMultipleCommitteeBits(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofMultipleCommitteeBits(sc, 0, 1, ctx.HeadSlot)
	})
}
func buildInvalidBeaconAggregateAndProofNoParticipants(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBeaconAggregateAndProofNoParticipants(sc, 0, 1, ctx.HeadSlot, 0)
	})
}

// --- sync_committee_message ---

func buildValidSyncCommitteeMessage(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildSyncCommitteeMessage(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidSyncCommitteeMessageSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeMessageSigInvalid(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidSyncCommitteeMessageIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeMessageIndexOob(sc, ctx.HeadSlot)
	})
}
func buildInvalidSyncCommitteeMessageSlotEpochRange(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeMessageSlotEpochRange(sc, 0)
	})
}

// --- sync_committee_contribution_and_proof ---

func buildValidSyncCommitteeContributionAndProof(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildSignedContributionAndProof(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidSyncCommitteeContributionAndProofSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeContributionAndProofSigInvalid(sc, 0, 1, ctx.HeadSlot, 0)
	})
}
func buildInvalidSyncCommitteeContributionAndProofIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeContributionAndProofIndexOob(sc, 0, 1, ctx.HeadSlot)
	})
}
func buildInvalidSyncCommitteeContributionAndProofSlotEpochRange(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeContributionAndProofSlotEpochRange(sc, 0, 1, 0)
	})
}
func buildInvalidSyncCommitteeContributionAndProofLengthLimit(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSyncCommitteeContributionAndProofNoParticipants(sc, 0, 1, ctx.HeadSlot, 0)
	})
}

// --- voluntary_exit ---

func buildValidVoluntaryExit(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildSignedVoluntaryExit(sc, 0) })
}
func buildInvalidVoluntaryExitSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSignedVoluntaryExitSigInvalid(sc, 0)
	})
}
func buildInvalidVoluntaryExitIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildInvalidSignedVoluntaryExitIndexOob(sc) })
}
func buildInvalidVoluntaryExitSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidSignedVoluntaryExitSlotFuture(sc, 0)
	})
}

// --- proposer_slashing ---

func buildValidProposerSlashing(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildProposerSlashing(sc, 0, ctx.HeadSlot) })
}
func buildInvalidProposerSlashingSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidProposerSlashingSigInvalid(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidProposerSlashingFieldEquality(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidProposerSlashingFieldEquality(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidProposerSlashingIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidProposerSlashingIndexOob(sc, ctx.HeadSlot)
	})
}

// --- attester_slashing ---

func buildValidAttesterSlashing(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildAttesterSlashing(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidAttesterSlashingSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidAttesterSlashingSigInvalid(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidAttesterSlashingFieldEquality(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidAttesterSlashingFieldEquality(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidAttesterSlashingIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidAttesterSlashingIndexOob(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidAttesterSlashingLengthLimit(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidAttesterSlashingNoSlashableIntersection(sc, 0, ctx.HeadSlot, 0)
	})
}

// --- blob_sidecar ---

func buildValidBlobSidecar(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildBlobSidecar(sc, 0, ctx.HeadSlot, 0) })
}
func buildInvalidBlobSidecarKzgProof(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlobSidecarKzgProof(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidBlobSidecarSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlobSidecarSigInvalid(sc, 0, ctx.HeadSlot, 0)
	})
}
func buildInvalidBlobSidecarSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) { return ethmsg.BuildInvalidBlobSidecarSlotFuture(sc, 0, 0) })
}
func buildInvalidBlobSidecarIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlobSidecarIndexOob(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidBlobSidecarProposerIndexWrong(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlobSidecarProposerIndexOob(sc, ctx.HeadSlot, 0)
	})
}

// --- data_column_sidecar ---

func buildValidDataColumnSidecar(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildDataColumnSidecar(sc, 0, ctx.HeadSlot, 0, 1)
	})
}
func buildInvalidDataColumnSidecarKzgProof(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidDataColumnSidecarKzgProof(sc, 0, ctx.HeadSlot, 0, 1)
	})
}
func buildInvalidDataColumnSidecarSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidDataColumnSidecarSigInvalid(sc, 0, ctx.HeadSlot, 0, 1)
	})
}
func buildInvalidDataColumnSidecarSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidDataColumnSidecarSlotFuture(sc, 0, 0, 1)
	})
}
func buildInvalidDataColumnSidecarIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidDataColumnSidecarIndexOob(sc, 0, ctx.HeadSlot, 1)
	})
}
func buildInvalidDataColumnSidecarProposerIndexWrong(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidDataColumnSidecarProposerIndexOob(sc, ctx.HeadSlot, 0, 1)
	})
}

// --- partial_data_column_sidecar (Fulu partial-columns sub-spec) ---

func buildValidPartialDataColumnSidecar(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildPartialDataColumnSidecar(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnEmpty(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnEmpty(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnHeaderNoCommitments(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnHeaderNoCommitments(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnProofCountMismatch(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnProofCountMismatch(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnCellCountMismatch(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnCellCountMismatch(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnBitmapLenMismatch(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnBitmapLenMismatch(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnKzgProof(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnKzgProof(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnSigInvalid(sc, 0, ctx.HeadSlot)
	})
}
func buildInvalidPartialDataColumnSlotFuture(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidPartialDataColumnSlotFuture(sc, 0)
	})
}

// --- bls_to_execution_change ---

func buildValidBlsToExecutionChange(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildSignedBLSToExecutionChange(sc, 0, [20]byte{})
	})
}
func buildInvalidBlsToExecutionChangeSigInvalid(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlsToExecutionChangeSigInvalid(sc, 0, [20]byte{})
	})
}
func buildInvalidBlsToExecutionChangeFieldEquality(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlsToExecutionChangeFieldEquality(sc, 0, [20]byte{})
	})
}
func buildInvalidBlsToExecutionChangeIndexOob(ctx *irContext) []byte {
	return cm(ctx, func(sc ethmsg.SignContext) ([]byte, error) {
		return ethmsg.BuildInvalidBlsToExecutionChangeIndexOob(sc, [20]byte{})
	})
}
