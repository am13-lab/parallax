package ethmsg

import "crypto/sha256"

// domains.go — BLS signing-domain computation (consensus-specs "phase0/beacon-chain":
// compute_fork_data_root, compute_domain, compute_signing_root). The ForkData and
// SigningData containers each have exactly two 32-byte-chunk fields, so their
// hash_tree_root is a single SHA-256 of the two chunks concatenated — no general SSZ
// merkleization is needed here.

// Domain-type constants (DomainType = Bytes4). The leading byte carries the value.
var (
	DomainBeaconProposer              = [4]byte{0x00, 0x00, 0x00, 0x00}
	DomainBeaconAttester              = [4]byte{0x01, 0x00, 0x00, 0x00}
	DomainRandao                      = [4]byte{0x02, 0x00, 0x00, 0x00}
	DomainVoluntaryExit               = [4]byte{0x04, 0x00, 0x00, 0x00}
	DomainSelectionProof              = [4]byte{0x05, 0x00, 0x00, 0x00}
	DomainAggregateAndProof           = [4]byte{0x06, 0x00, 0x00, 0x00}
	DomainSyncCommittee               = [4]byte{0x07, 0x00, 0x00, 0x00}
	DomainSyncCommitteeSelectionProof = [4]byte{0x08, 0x00, 0x00, 0x00}
	DomainContributionAndProof        = [4]byte{0x09, 0x00, 0x00, 0x00}
	DomainBLSToExecutionChange        = [4]byte{0x0a, 0x00, 0x00, 0x00}
)

// ComputeForkDataRoot returns hash_tree_root(ForkData{current_version,
// genesis_validators_root}). Fields: version (Bytes4, right-padded to a 32-byte
// chunk) and the 32-byte genesis root; HTR = SHA256(chunk0 || gvr).
func ComputeForkDataRoot(forkVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	var chunk0 [32]byte
	copy(chunk0[:4], forkVersion[:])
	h := sha256.New()
	h.Write(chunk0[:])
	h.Write(genesisValidatorsRoot[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ComputeDomain returns domain_type ++ compute_fork_data_root(...)[:28].
func ComputeDomain(domainType [4]byte, forkVersion [4]byte, genesisValidatorsRoot [32]byte) [32]byte {
	fdr := ComputeForkDataRoot(forkVersion, genesisValidatorsRoot)
	var d [32]byte
	copy(d[:4], domainType[:])
	copy(d[4:], fdr[:28])
	return d
}

// ComputeSigningRoot returns hash_tree_root(SigningData{object_root, domain}) =
// SHA256(object_root || domain).
func ComputeSigningRoot(objectRoot [32]byte, domain [32]byte) [32]byte {
	h := sha256.New()
	h.Write(objectRoot[:])
	h.Write(domain[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SignObject signs an SSZ object's hash_tree_root for validator `index` under the
// given domain: it computes the signing root and returns the 96-byte BLS signature.
func (k *Keystore) SignObject(index uint64, objectRoot, domain [32]byte) ([]byte, error) {
	sr := ComputeSigningRoot(objectRoot, domain)
	return k.Sign(index, sr[:])
}
