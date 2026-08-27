package wire

import "crypto/sha256"

// ComputeForkDigest computes the base 4-byte fork digest:
// hash_tree_root(ForkData(current_version, genesis_validators_root))[:4],
// i.e. SHA256(version zero-padded to 32 bytes || genesis_validators_root)[:4].
// BPO-fork networks (Fulu and later) XOR further schedule data into the
// digest; for those, take the digest from the client's ENR or Beacon API
// instead of computing it here.
func ComputeForkDigest(forkVersion [4]byte, genesisValidatorsRoot [32]byte) [4]byte {
	var data [64]byte
	copy(data[0:4], forkVersion[:])
	copy(data[32:64], genesisValidatorsRoot[:])
	h := sha256.Sum256(data[:])
	var digest [4]byte
	copy(digest[:], h[:4])
	return digest
}
