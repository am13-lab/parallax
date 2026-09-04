package ethmsg

import (
	"encoding/binary"
	"fmt"
)

// data_column_sidecar.go — a Fulu/PeerDAS data_column_sidecar with a valid column
// (real cells + cell KZG proofs from go-eth-kzg) and a validly-signed block header,
// plus a kzg_proof variant that corrupts a cell proof.
//
// CAVEAT (same as blob_sidecar): KZGCommitmentsInclusionProof is a placeholder
// (zeros); a valid branch requires building the block body and extracting the
// Merkle proof — deferred. The kzg_proof variant specifically exercises the
// cell-proof validity check.

func (sc SignContext) dataColumnSidecar(proposerIndex, slot, columnIndex, headerSigner uint64, numBlobs int, corruptProof bool) ([]byte, error) {
	col, err := ValidColumn(numBlobs, columnIndex)
	if err != nil {
		return nil, err
	}
	var column [][2048]byte
	var commitments, proofs [][48]byte
	for i := range col.Cells {
		column = append(column, [2048]byte(*col.Cells[i]))
		commitments = append(commitments, [48]byte(col.Commitments[i]))
		p := [48]byte(col.Proofs[i])
		if corruptProof && i == 0 {
			p[0] ^= 0xFF // cell proof no longer matches the cell
		}
		proofs = append(proofs, p)
	}

	hdr := &ColumnBlockHeader{
		Slot:          slot,
		ProposerIndex: proposerIndex,
		ParentRoot:    sc.HeadRoot,
		StateRoot:     sc.HeadRoot,
		BodyRoot:      distinctRoot(0x44),
	}
	hroot, err := hdr.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("header htr: %w", err)
	}
	sig, err := sc.sign(headerSigner, hroot, DomainBeaconProposer)
	if err != nil {
		return nil, fmt.Errorf("sign header: %w", err)
	}

	sidecar := &DataColumnSidecar{
		Index:                        columnIndex,
		Column:                       column,
		KZGCommitments:               commitments,
		KZGProofs:                    proofs,
		SignedBlockHeader:            &ColumnSignedBlockHeader{Message: hdr, Signature: mustSig96(sig)},
		KZGCommitmentsInclusionProof: make([][32]byte, 4), // Vector[Bytes32,4] placeholder
	}
	return sidecar.MarshalSSZ()
}

// BuildDataColumnSidecar builds a data_column_sidecar with valid cells + cell proofs
// and a validly-signed header (inclusion proof is a placeholder — see caveat).
func BuildDataColumnSidecar(sc SignContext, proposerIndex, slot, columnIndex uint64, numBlobs int) ([]byte, error) {
	return sc.dataColumnSidecar(proposerIndex, slot, columnIndex, proposerIndex, numBlobs, false)
}

// BuildInvalidDataColumnSidecarKzgProof builds a data_column_sidecar whose first
// cell proof is corrupted, isolating the cell-proof validity (kzg_proof) rule.
func BuildInvalidDataColumnSidecarKzgProof(sc SignContext, proposerIndex, slot, columnIndex uint64, numBlobs int) ([]byte, error) {
	return sc.dataColumnSidecar(proposerIndex, slot, columnIndex, proposerIndex, numBlobs, true)
}

func BuildInvalidDataColumnSidecarSigInvalid(sc SignContext, proposerIndex, slot, columnIndex uint64, numBlobs int) ([]byte, error) {
	return sc.dataColumnSidecar(proposerIndex, slot, columnIndex, proposerIndex+1, numBlobs, false)
}

func BuildInvalidDataColumnSidecarSlotFuture(sc SignContext, proposerIndex, columnIndex uint64, numBlobs int) ([]byte, error) {
	futureSlot := (sc.CurrentEpoch + 100) * slotsPerEpoch
	return sc.dataColumnSidecar(proposerIndex, futureSlot, columnIndex, proposerIndex, numBlobs, false)
}

func BuildInvalidDataColumnSidecarIndexOob(sc SignContext, proposerIndex, slot uint64, numBlobs int) ([]byte, error) {
	payload, err := sc.dataColumnSidecar(proposerIndex, slot, 0, proposerIndex, numBlobs, false)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(payload[0:8], 1<<20)
	return payload, nil
}

func BuildInvalidDataColumnSidecarProposerIndexOob(sc SignContext, slot, columnIndex uint64, numBlobs int) ([]byte, error) {
	const oob = 1 << 40
	return sc.dataColumnSidecar(oob, slot, columnIndex, 0, numBlobs, false)
}

// columnFromSidecar reconstructs the ColumnKZG (for verification) from a decoded
// DataColumnSidecar.
func columnFromSidecar(s *DataColumnSidecar) ColumnKZG {
	var col ColumnKZG
	for i := range s.Column {
		cell := goethkzgCell(s.Column[i])
		col.Cells = append(col.Cells, &cell)
		col.Commitments = append(col.Commitments, goethkzgCommitment(s.KZGCommitments[i]))
		col.Proofs = append(col.Proofs, goethkzgProof(s.KZGProofs[i]))
	}
	return col
}
