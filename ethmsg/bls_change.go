package ethmsg

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// bls_change.go — a valid bls_to_execution_change and buildInvalid variants. The
// change is signed by the validator's WITHDRAWAL key (not the signing key) under
// DOMAIN_BLS_TO_EXECUTION_CHANGE, whose domain uses the GENESIS fork version (the
// message is valid across forks). from_bls_pubkey is the withdrawal public key.

func (sc SignContext) blsChange(validatorIndex uint64, toAddr [20]byte, fromPub []byte, signer uint64) ([]byte, error) {
	msg := &capella.BLSToExecutionChange{
		ValidatorIndex:     phase0.ValidatorIndex(validatorIndex),
		FromBLSPubkey:      phase0.BLSPubKey(must48(fromPub)),
		ToExecutionAddress: bellatrix.ExecutionAddress(toAddr),
	}
	root, err := msg.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("bls change htr: %w", err)
	}
	domain := ComputeDomain(DomainBLSToExecutionChange, sc.GenesisForkVersion, sc.GenesisValidatorsRoot)
	sr := ComputeSigningRoot(root, domain)
	sig, err := sc.Keys.SignWithdrawal(signer, sr[:])
	if err != nil {
		return nil, fmt.Errorf("sign bls change: %w", err)
	}
	signed := &capella.SignedBLSToExecutionChange{Message: msg, Signature: phase0.BLSSignature(mustSig96(sig))}
	return signed.MarshalSSZ()
}

// BuildSignedBLSToExecutionChange builds a valid bls_to_execution_change:
// from_bls_pubkey is the validator's withdrawal pubkey and it is signed by that key.
func BuildSignedBLSToExecutionChange(sc SignContext, validatorIndex uint64, toAddr [20]byte) ([]byte, error) {
	fromPub, err := sc.Keys.WithdrawalPublicKey(validatorIndex)
	if err != nil {
		return nil, err
	}
	return sc.blsChange(validatorIndex, toAddr, fromPub, validatorIndex)
}

// BuildInvalidBlsToExecutionChangeSigInvalid: from_bls_pubkey is the validator's
// withdrawal pubkey but the message is signed by a different withdrawal key, so the
// signature does not match from_bls_pubkey.
func BuildInvalidBlsToExecutionChangeSigInvalid(sc SignContext, validatorIndex uint64, toAddr [20]byte) ([]byte, error) {
	fromPub, err := sc.Keys.WithdrawalPublicKey(validatorIndex)
	if err != nil {
		return nil, err
	}
	return sc.blsChange(validatorIndex, toAddr, fromPub, validatorIndex+1) // wrong signer
}

// BuildInvalidBlsToExecutionChangeFieldEquality: from_bls_pubkey belongs to a
// different validator, so it does not match validator_index's withdrawal credential.
func BuildInvalidBlsToExecutionChangeFieldEquality(sc SignContext, validatorIndex uint64, toAddr [20]byte) ([]byte, error) {
	otherPub, err := sc.Keys.WithdrawalPublicKey(validatorIndex + 1)
	if err != nil {
		return nil, err
	}
	// Signed consistently by the other key so only the credential-match rule breaks.
	return sc.blsChange(validatorIndex, toAddr, otherPub, validatorIndex+1)
}

func BuildInvalidBlsToExecutionChangeIndexOob(sc SignContext, toAddr [20]byte) ([]byte, error) {
	fromPub, err := sc.Keys.WithdrawalPublicKey(0)
	if err != nil {
		return nil, err
	}
	const oob = 1 << 40
	return sc.blsChange(oob, toAddr, fromPub, 0)
}

// must48 narrows a 48-byte pubkey slice to the fixed array type.
func must48(b []byte) [48]byte {
	var a [48]byte
	copy(a[:], b)
	return a
}
