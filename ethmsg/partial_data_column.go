package ethmsg

import (
	"encoding/binary"
	"fmt"
)

// partial_data_column.go — a typed PartialDataColumnSidecar (Fulu partial-columns
// sub-spec, consensus-specs/specs/fulu/partial-columns/p2p-interface.md) with
// hand-written SSZ marshaling. go-eth2-client does not yet model this container,
// so we serialize it directly.
//
//	class PartialDataColumnSidecar(Container):
//	    cells_present_bitmap: Bitlist[MAX_BLOB_COMMITMENTS_PER_BLOCK]
//	    partial_column:       List[Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK]
//	    kzg_proofs:           List[KZGProof, MAX_BLOB_COMMITMENTS_PER_BLOCK]
//	    header:               List[PartialDataColumnHeader, 1]
//
//	class PartialDataColumnHeader(Container):
//	    kzg_commitments:                 List[KZGCommitment, MAX_BLOB_COMMITMENTS_PER_BLOCK]
//	    signed_block_header:             SignedBeaconBlockHeader
//	    kzg_commitments_inclusion_proof: Vector[Bytes32, KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH]
//
// The valid baseline is structurally well-formed (offsets, list lengths, bitmap
// popcount all consistent); it is not proof-valid on the inclusion-proof/KZG axes
// (no client implements this sub-spec yet), so rules on those axes are exercised
// as differential probes, and only the purely structural rules assert REJECT.

const (
	bytesPerCell       = 2048 // FIELD_ELEMENTS_PER_CELL(64) * BYTES_PER_FIELD_ELEMENT(32)
	kzgCommitmentBytes = 48
	kzgProofBytes      = 48
	// KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH (mainnet fulu preset).
	kzgCommitmentsInclusionProofDepth = 4
	signedHeaderSSZLen                = 208 // BeaconBlockHeader(112) + BLSSignature(96)
)

// partialSidecarOpts controls how a PartialDataColumnSidecar is assembled so a
// single marshaller can produce the valid baseline and each invalid variant.
type partialSidecarOpts struct {
	hasHeader      bool
	numCommitments int // header.kzg_commitments length (header present only)
	bitmapLen      int // cells_present_bitmap length in bits
	cellsPresent   int // number of set bits (from bit 0) = num_cells_present
	numColumnCells int // len(partial_column)
	numProofs      int // len(kzg_proofs)
	corruptProof   bool
	badSig         bool
}

func encodeBitlist(length, setBits int) []byte {
	// Bitlist SSZ: pack `length` data bits, then set a delimiter bit at index
	// `length`. Byte length = length/8 + 1.
	n := length/8 + 1
	out := make([]byte, n)
	for i := 0; i < setBits && i < length; i++ {
		out[i/8] |= 1 << (uint(i) % 8)
	}
	out[length/8] |= 1 << (uint(length) % 8) // delimiter
	return out
}

func u32le(v int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

func (sc SignContext) marshalPartialDataColumnHeader(o partialSidecarOpts, proposerIndex, slot uint64) ([]byte, error) {
	_, commitment, _, err := ValidBlobCommitmentProof()
	if err != nil {
		return nil, err
	}
	signer := proposerIndex
	if o.badSig {
		signer = proposerIndex + 1
	}
	header, err := sc.signedHeader(proposerIndex, slot, distinctRoot(0x44), signer)
	if err != nil {
		return nil, err
	}
	sbh, err := header.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("signed header ssz: %w", err)
	}
	if len(sbh) != signedHeaderSSZLen {
		return nil, fmt.Errorf("signed header ssz len = %d, want %d", len(sbh), signedHeaderSSZLen)
	}
	inclProof := make([]byte, kzgCommitmentsInclusionProofDepth*32) // placeholder branch

	// Fixed part: offset(kzg_commitments) + signed_block_header + inclusion_proof.
	fixed := 4 + len(sbh) + len(inclProof)
	out := make([]byte, 0, fixed+o.numCommitments*kzgCommitmentBytes)
	out = append(out, u32le(fixed)...)
	out = append(out, sbh...)
	out = append(out, inclProof...)
	for i := 0; i < o.numCommitments; i++ {
		out = append(out, commitment[:]...)
	}
	return out, nil
}

func (sc SignContext) marshalPartialDataColumnSidecar(o partialSidecarOpts, proposerIndex, slot uint64) ([]byte, error) {
	_, _, proof, err := ValidBlobCommitmentProof()
	if err != nil {
		return nil, err
	}

	bitmap := encodeBitlist(o.bitmapLen, o.cellsPresent)

	column := make([]byte, 0, o.numColumnCells*bytesPerCell)
	for i := 0; i < o.numColumnCells; i++ {
		cell := make([]byte, bytesPerCell)
		cell[0] = byte(i + 1) // deterministic non-zero filler
		column = append(column, cell...)
	}

	proofs := make([]byte, 0, o.numProofs*kzgProofBytes)
	for i := 0; i < o.numProofs; i++ {
		p := proof
		if o.corruptProof {
			p[0] ^= 0xFF
		}
		proofs = append(proofs, p[:]...)
	}

	var headerList []byte
	if o.hasHeader {
		hdr, err := sc.marshalPartialDataColumnHeader(o, proposerIndex, slot)
		if err != nil {
			return nil, err
		}
		// List[PartialDataColumnHeader, 1] with one variable-size element: a single
		// 4-byte offset table followed by the element.
		headerList = append(headerList, u32le(4)...)
		headerList = append(headerList, hdr...)
	}

	// Container with four variable-size fields: a 16-byte offset table then each
	// field's bytes in order.
	o1 := 16
	o2 := o1 + len(bitmap)
	o3 := o2 + len(column)
	o4 := o3 + len(proofs)
	out := make([]byte, 0, o4+len(headerList))
	out = append(out, u32le(o1)...)
	out = append(out, u32le(o2)...)
	out = append(out, u32le(o3)...)
	out = append(out, u32le(o4)...)
	out = append(out, bitmap...)
	out = append(out, column...)
	out = append(out, proofs...)
	out = append(out, headerList...)
	return out, nil
}

func validPartialOpts() partialSidecarOpts {
	return partialSidecarOpts{
		hasHeader: true, numCommitments: 1,
		bitmapLen: 1, cellsPresent: 1, numColumnCells: 1, numProofs: 1,
	}
}

// BuildPartialDataColumnSidecar builds a structurally valid baseline: a present
// header with one commitment, a 1-bit bitmap with one cell present, one cell, and
// one proof.
func BuildPartialDataColumnSidecar(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	return sc.marshalPartialDataColumnSidecar(validPartialOpts(), proposerIndex, slot)
}

// BuildInvalidPartialDataColumnEmpty: neither header nor cells present.
func BuildInvalidPartialDataColumnEmpty(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	return sc.marshalPartialDataColumnSidecar(partialSidecarOpts{}, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnHeaderNoCommitments: header present but empty
// kzg_commitments.
func BuildInvalidPartialDataColumnHeaderNoCommitments(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	o := validPartialOpts()
	o.numCommitments = 0
	o.bitmapLen = 0
	o.cellsPresent = 0
	o.numColumnCells = 0
	o.numProofs = 0
	return sc.marshalPartialDataColumnSidecar(o, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnProofCountMismatch: len(kzg_proofs) != num_cells_present.
func BuildInvalidPartialDataColumnProofCountMismatch(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	o := validPartialOpts()
	o.numProofs = o.cellsPresent + 1
	return sc.marshalPartialDataColumnSidecar(o, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnCellCountMismatch: len(partial_column) != num_cells_present.
func BuildInvalidPartialDataColumnCellCountMismatch(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	o := validPartialOpts()
	o.numColumnCells = o.cellsPresent + 1
	return sc.marshalPartialDataColumnSidecar(o, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnBitmapLenMismatch: len(cells_present_bitmap) != len(kzg_commitments).
func BuildInvalidPartialDataColumnBitmapLenMismatch(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	o := validPartialOpts()
	o.bitmapLen = o.numCommitments + 1
	return sc.marshalPartialDataColumnSidecar(o, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnKzgProof: cells present with a corrupted proof.
func BuildInvalidPartialDataColumnKzgProof(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	o := validPartialOpts()
	o.corruptProof = true
	return sc.marshalPartialDataColumnSidecar(o, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnSigInvalid: header signed by the wrong key.
func BuildInvalidPartialDataColumnSigInvalid(sc SignContext, proposerIndex, slot uint64) ([]byte, error) {
	o := validPartialOpts()
	o.badSig = true
	return sc.marshalPartialDataColumnSidecar(o, proposerIndex, slot)
}

// BuildInvalidPartialDataColumnSlotFuture: valid structure at a far-future slot.
func BuildInvalidPartialDataColumnSlotFuture(sc SignContext, proposerIndex uint64) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return sc.marshalPartialDataColumnSidecar(validPartialOpts(), proposerIndex, futureSlot)
}
