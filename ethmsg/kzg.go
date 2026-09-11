package ethmsg

import (
	"fmt"
	"sync"

	goethkzg "github.com/crate-crypto/go-eth-kzg"
)

// kzg.go — KZG-4844 + PeerDAS cell foundation for blob and data-column sidecar
// builders. Uses the pure-Go go-eth-kzg with its embedded (mainnet) trusted setup:
// blob commitments/proofs (blob_sidecar) and cell commitments/proofs
// (data_column_sidecar). No CGO, no external setup file.

var (
	kzgOnce sync.Once
	kzgCtx  *goethkzg.Context
	kzgErr  error
)

func kzgContext() (*goethkzg.Context, error) {
	kzgOnce.Do(func() { kzgCtx, kzgErr = goethkzg.NewContext4096Secure() })
	return kzgCtx, kzgErr
}

// ValidBlobCommitmentProof returns a valid (blob, commitment, proof) triple. The
// zero blob (all field elements zero) is valid, and its commitment/proof verify.
func ValidBlobCommitmentProof() (goethkzg.Blob, goethkzg.KZGCommitment, goethkzg.KZGProof, error) {
	var blob goethkzg.Blob
	ctx, err := kzgContext()
	if err != nil {
		return blob, goethkzg.KZGCommitment{}, goethkzg.KZGProof{}, fmt.Errorf("kzg context: %w", err)
	}
	commitment, err := ctx.BlobToKZGCommitment(&blob, 0)
	if err != nil {
		return blob, goethkzg.KZGCommitment{}, goethkzg.KZGProof{}, fmt.Errorf("blob commitment: %w", err)
	}
	proof, err := ctx.ComputeBlobKZGProof(&blob, commitment, 0)
	if err != nil {
		return blob, commitment, goethkzg.KZGProof{}, fmt.Errorf("blob proof: %w", err)
	}
	return blob, commitment, proof, nil
}

// VerifyBlob checks a blob/commitment/proof triple (nil error == valid).
func VerifyBlob(blob goethkzg.Blob, commitment goethkzg.KZGCommitment, proof goethkzg.KZGProof) error {
	ctx, err := kzgContext()
	if err != nil {
		return err
	}
	return ctx.VerifyBlobKZGProof(&blob, commitment, proof)
}

// ColumnKZG is the KZG material for one data column (index columnIndex) across a
// block's blobs: one commitment, cell, and proof per blob.
type ColumnKZG struct {
	Commitments []goethkzg.KZGCommitment
	Cells       []*goethkzg.Cell
	Proofs      []goethkzg.KZGProof
}

// ValidColumn builds a valid data column at columnIndex over numBlobs zero blobs:
// each blob's cell at that index plus its cell proof and blob commitment.
func ValidColumn(numBlobs int, columnIndex uint64) (ColumnKZG, error) {
	var out ColumnKZG
	ctx, err := kzgContext()
	if err != nil {
		return out, fmt.Errorf("kzg context: %w", err)
	}
	for b := 0; b < numBlobs; b++ {
		var blob goethkzg.Blob
		commitment, err := ctx.BlobToKZGCommitment(&blob, 0)
		if err != nil {
			return out, fmt.Errorf("blob commitment: %w", err)
		}
		cells, proofs, err := ctx.ComputeCellsAndKZGProofs(&blob, 0)
		if err != nil {
			return out, fmt.Errorf("compute cells: %w", err)
		}
		out.Commitments = append(out.Commitments, commitment)
		out.Cells = append(out.Cells, cells[columnIndex])
		out.Proofs = append(out.Proofs, proofs[columnIndex])
	}
	return out, nil
}

// Conversions between the SSZ byte-array fields and go-eth-kzg types.
func goethkzgCell(b [2048]byte) goethkzg.Cell              { return goethkzg.Cell(b) }
func goethkzgCommitment(b [48]byte) goethkzg.KZGCommitment { return goethkzg.KZGCommitment(b) }
func goethkzgProof(b [48]byte) goethkzg.KZGProof           { return goethkzg.KZGProof(b) }

// VerifyColumn checks a data column's cell proofs at columnIndex (nil == valid).
func VerifyColumn(col ColumnKZG, columnIndex uint64) error {
	ctx, err := kzgContext()
	if err != nil {
		return err
	}
	idx := make([]uint64, len(col.Cells))
	for i := range idx {
		idx[i] = columnIndex
	}
	return ctx.VerifyCellKZGProofBatch(col.Commitments, idx, col.Cells, col.Proofs)
}
