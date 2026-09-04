package ethmsg

// datacolumn.go — the Fulu/PeerDAS DataColumnSidecar SSZ container (EIP-7594),
// which no released library provides. Types are self-contained (local header copy)
// so fastssz's sszgen generates MarshalSSZ/HashTreeRoot without cross-package
// container references. Run `go generate ./internal/ethmsg/...` to regenerate the
// SSZ methods after editing these structs.
//
//go:generate go run github.com/ferranbt/fastssz/sszgen --path datacolumn.go --objs ColumnBlockHeader,ColumnSignedBlockHeader,DataColumnSidecar

// ColumnBlockHeader mirrors phase0.BeaconBlockHeader (identical SSZ layout).
type ColumnBlockHeader struct {
	Slot          uint64
	ProposerIndex uint64
	ParentRoot    [32]byte `ssz-size:"32"`
	StateRoot     [32]byte `ssz-size:"32"`
	BodyRoot      [32]byte `ssz-size:"32"`
}

// ColumnSignedBlockHeader mirrors phase0.SignedBeaconBlockHeader.
type ColumnSignedBlockHeader struct {
	Message   *ColumnBlockHeader
	Signature [96]byte `ssz-size:"96"`
}

// DataColumnSidecar is the EIP-7594 data_column_sidecar gossip message: a single
// column (one cell per blob) with its per-blob commitments and cell proofs, the
// signed block header, and the commitments inclusion proof.
type DataColumnSidecar struct {
	Index                        uint64
	Column                       [][2048]byte `ssz-max:"4096" ssz-size:"?,2048"` // Cell = ByteVector[BYTES_PER_CELL]
	KZGCommitments               [][48]byte   `ssz-max:"4096" ssz-size:"?,48"`
	KZGProofs                    [][48]byte   `ssz-max:"4096" ssz-size:"?,48"`
	SignedBlockHeader            *ColumnSignedBlockHeader
	KZGCommitmentsInclusionProof [][32]byte `ssz-size:"4,32"` // Vector[Bytes32, 4]
}
