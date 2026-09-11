package ethmsg

import (
	"github.com/attestantio/go-eth2-client/spec/deneb"
)

// blob_sidecar.go — a blob_sidecar with a valid blob/commitment/proof (real KZG),
// a real kzg_commitment_inclusion_proof (see blob_inclusion.go), and a validly-
// signed block header whose body_root matches the inclusion proof. A kzg_proof
// variant corrupts the proof so it no longer matches the blob, isolating the
// KZG-proof-validity check.

func (sc SignContext) blobSidecar(proposerIndex, slot, index, headerSigner uint64, corruptProof bool) ([]byte, error) {
	blob, commitment, proof, err := ValidBlobCommitmentProof()
	if err != nil {
		return nil, err
	}
	if corruptProof {
		proof[0] ^= 0xFF // blob no longer matches the proof
	}
	kzgCommitment := deneb.KZGCommitment(commitment)
	inclusionProof, bodyRoot, err := blobInclusionProof(kzgCommitment, index)
	if err != nil {
		return nil, err
	}
	header, err := sc.signedHeader(proposerIndex, slot, bodyRoot, headerSigner)
	if err != nil {
		return nil, err
	}
	sidecar := &deneb.BlobSidecar{
		Index:                       deneb.BlobIndex(index),
		Blob:                        deneb.Blob(blob),
		KZGCommitment:               kzgCommitment,
		KZGProof:                    deneb.KZGProof(proof),
		SignedBlockHeader:           header,
		KZGCommitmentInclusionProof: inclusionProof,
	}
	return sidecar.MarshalSSZ()
}

// BuildBlobSidecar builds a blob_sidecar with a valid KZG blob/commitment/proof and a
// validly-signed header (inclusion proof is a placeholder — see caveat).
func BuildBlobSidecar(sc SignContext, proposerIndex, slot, index uint64) ([]byte, error) {
	return sc.blobSidecar(proposerIndex, slot, index, proposerIndex, false)
}

// BuildInvalidBlobSidecarKzgProof builds a blob_sidecar whose KZG proof is corrupted
// so it does not match the blob — isolating the kzg_proof validation rule.
func BuildInvalidBlobSidecarKzgProof(sc SignContext, proposerIndex, slot, index uint64) ([]byte, error) {
	return sc.blobSidecar(proposerIndex, slot, index, proposerIndex, true)
}

func BuildInvalidBlobSidecarSigInvalid(sc SignContext, proposerIndex, slot, index uint64) ([]byte, error) {
	return sc.blobSidecar(proposerIndex, slot, index, proposerIndex+1, false)
}

func BuildInvalidBlobSidecarSlotFuture(sc SignContext, proposerIndex, index uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return sc.blobSidecar(proposerIndex, futureSlot, index, proposerIndex, false)
}

func BuildInvalidBlobSidecarIndexOob(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	return sc.blobSidecar(proposerIndex, slot, 10, proposerIndex, false)
}

func BuildInvalidBlobSidecarProposerIndexOob(sc SignContext, slot, index uint64) ([]byte, error) {
	const oob = 1 << 40
	return sc.blobSidecar(oob, slot, index, 0, false)
}
