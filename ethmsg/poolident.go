package ethmsg

import (
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/golang/snappy"
)

// poolident.go — decode a gossip operation payload back to its identifying validator
// index so a client's beacon pool can be searched for it after injection. This is what
// turns local publish-success into a real accept/reject verdict for the operation topics
// (the ones exposed via /eth/v1|v2/beacon/pool/*).

// Operation gossip topic short-names whose acceptance is observable via the pool.
const (
	TopicVoluntaryExit        = "voluntary_exit"
	TopicProposerSlashing     = "proposer_slashing"
	TopicAttesterSlashing     = "attester_slashing"
	TopicBLSToExecutionChange = "bls_to_execution_change"
)

// IsPoolObservableTopic reports whether a gossip topic short-name maps to an operation
// whose accept/reject verdict can be read back from a client's beacon pool.
func IsPoolObservableTopic(topic string) bool {
	switch topic {
	case TopicVoluntaryExit, TopicProposerSlashing, TopicAttesterSlashing, TopicBLSToExecutionChange:
		return true
	}
	return false
}

// OperationIdentity decodes a gossip operation payload (snappy-compressed SSZ, or raw SSZ
// as a fallback) to its identifying validator index. ok is false for non-operation topics
// or on decode failure.
func OperationIdentity(topic string, payload []byte) (index uint64, ok bool) {
	ssz := payload
	if dec, err := snappy.Decode(nil, payload); err == nil {
		ssz = dec
	}
	switch topic {
	case TopicVoluntaryExit:
		var m phase0.SignedVoluntaryExit
		if err := m.UnmarshalSSZ(ssz); err != nil || m.Message == nil {
			return 0, false
		}
		return uint64(m.Message.ValidatorIndex), true
	case TopicProposerSlashing:
		var m phase0.ProposerSlashing
		if err := m.UnmarshalSSZ(ssz); err != nil || m.SignedHeader1 == nil || m.SignedHeader1.Message == nil {
			return 0, false
		}
		return uint64(m.SignedHeader1.Message.ProposerIndex), true
	case TopicAttesterSlashing:
		var m electra.AttesterSlashing
		if err := m.UnmarshalSSZ(ssz); err != nil || m.Attestation1 == nil || len(m.Attestation1.AttestingIndices) == 0 {
			return 0, false
		}
		return m.Attestation1.AttestingIndices[0], true
	case TopicBLSToExecutionChange:
		var m capella.SignedBLSToExecutionChange
		if err := m.UnmarshalSSZ(ssz); err != nil || m.Message == nil {
			return 0, false
		}
		return uint64(m.Message.ValidatorIndex), true
	}
	return 0, false
}
