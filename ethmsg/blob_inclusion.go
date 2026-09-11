package ethmsg

import (
	"fmt"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
)

// blob_inclusion.go — computes a real kzg_commitment_inclusion_proof for a blob
// sidecar so the valid baseline passes verify_blob_sidecar_inclusion_proof, not
// just the KZG-proof check.
//
// verify_blob_sidecar_inclusion_proof checks a Merkle branch from
// hash_tree_root(kzg_commitment) up to signed_block_header.message.body_root at
// the generalized index of blob_kzg_commitments[index] in BeaconBlockBody. We
// build a BeaconBlockBody whose blob_kzg_commitments[index] holds the commitment,
// take its hash tree, and extract the branch + body root. The proof only needs to
// be self-consistent with the body_root we place in the header — the client never
// re-derives the body from a block — so a zero-filled body of the correct SSZ
// shape is sufficient and works for both Deneb and Electra (blob_kzg_commitments
// is field 11 with limit 4096 in both, so the generalized index and depth are
// identical).

const (
	// KZG_COMMITMENT_INCLUSION_PROOF_DEPTH for Deneb/Electra.
	kzgInclusionProofDepth = 17
	// Generalized index of blob_kzg_commitments[0] in BeaconBlockBody:
	// field 11 in a 16-leaf body tree -> node gindex 27; the List's data root is
	// 27*2 = 54; the data tree (limit 4096) has depth 12, so element[0] sits at
	// gindex 54 * 4096 = 221184. Element[index] is at 221184 + index.
	blobCommitmentsBaseGIndex = 221184
)

// blobInclusionProof returns the inclusion proof for blob_kzg_commitments[index]
// and the corresponding body root to place in the signed block header.
func blobInclusionProof(commitment deneb.KZGCommitment, index uint64) (deneb.KZGCommitmentInclusionProof, [32]byte, error) {
	var proof deneb.KZGCommitmentInclusionProof
	var bodyRoot [32]byte

	commitments := make([]deneb.KZGCommitment, index+1)
	commitments[index] = commitment

	body := &deneb.BeaconBlockBody{
		ETH1Data:           &phase0.ETH1Data{BlockHash: make([]byte, 32)},
		SyncAggregate:      &altair.SyncAggregate{SyncCommitteeBits: bitfield.NewBitvector512()},
		ExecutionPayload:   &deneb.ExecutionPayload{BaseFeePerGas: uint256.NewInt(0)},
		BlobKZGCommitments: commitments,
	}

	tree, err := body.GetTree()
	if err != nil {
		return proof, bodyRoot, fmt.Errorf("body tree: %w", err)
	}
	copy(bodyRoot[:], tree.Hash())

	gindex := blobCommitmentsBaseGIndex + int(index)
	p, err := tree.Prove(gindex)
	if err != nil {
		return proof, bodyRoot, fmt.Errorf("prove blob commitment inclusion: %w", err)
	}
	if len(p.Hashes) != kzgInclusionProofDepth {
		return proof, bodyRoot, fmt.Errorf("inclusion proof depth = %d, want %d", len(p.Hashes), kzgInclusionProofDepth)
	}
	for i, h := range p.Hashes {
		copy(proof[i][:], h)
	}
	return proof, bodyRoot, nil
}
