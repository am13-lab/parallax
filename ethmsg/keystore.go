// Package ethmsg is the crypto/message foundation for spec-rule-driven state
// machine payloads: it derives the devnet validator BLS keys, computes signing
// domains, and (in later files) builds valid signed/encoded consensus messages
// that mutators corrupt to exercise individual gossip validation rules.
package ethmsg

import (
	"fmt"
	"sync"

	bip39 "github.com/tyler-smith/go-bip39"
	e2types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
)

// DevnetMnemonic is the Kurtosis preregistered validator mnemonic
// (configs/eth-package-template.yaml). Every devnet validator signing key is
// derived from it via EIP-2333/2334, so we can sign messages AS the specific
// proposer/attester a spec rule requires.
const DevnetMnemonic = "giant issue aisle success illegal bike spike question tent bar rely arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky have athlete"

var (
	blsInitOnce sync.Once
	blsInitErr  error
)

// initBLS initializes the herumi BLS backend exactly once (required before any
// key derivation or signing).
func initBLS() error {
	blsInitOnce.Do(func() { blsInitErr = e2types.InitBLS() })
	return blsInitErr
}

// Keystore derives and caches validator BLS keys from a BIP-39 mnemonic. It caches
// both the signing key (EIP-2334 path .../i/0/0) and the withdrawal key (.../i/0),
// the latter used to sign BLSToExecutionChange messages.
type Keystore struct {
	seed  []byte
	mu    sync.Mutex
	keys  map[uint64]e2types.PrivateKey
	wkeys map[uint64]e2types.PrivateKey
}

// NewKeystore builds a keystore from a BIP-39 mnemonic. Per the eth2 keystore
// convention the derivation passphrase is empty.
func NewKeystore(mnemonic string) (*Keystore, error) {
	if err := initBLS(); err != nil {
		return nil, fmt.Errorf("init bls: %w", err)
	}
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic")
	}
	return &Keystore{
		seed:  bip39.NewSeed(mnemonic, ""),
		keys:  map[uint64]e2types.PrivateKey{},
		wkeys: map[uint64]e2types.PrivateKey{},
	}, nil
}

// NewDevnetKeystore builds the keystore for the committed Kurtosis devnet mnemonic.
func NewDevnetKeystore() (*Keystore, error) { return NewKeystore(DevnetMnemonic) }

// validatorPath returns the EIP-2334 signing-key path for a validator index.
func validatorPath(index uint64) string {
	return fmt.Sprintf("m/12381/3600/%d/0/0", index)
}

// SecretKey returns the validator signing key for the given index, deriving and
// caching it on first use.
func (k *Keystore) SecretKey(index uint64) (e2types.PrivateKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if sk, ok := k.keys[index]; ok {
		return sk, nil
	}
	sk, err := util.PrivateKeyFromSeedAndPath(k.seed, validatorPath(index))
	if err != nil {
		return nil, fmt.Errorf("derive %s: %w", validatorPath(index), err)
	}
	k.keys[index] = sk
	return sk, nil
}

// PublicKey returns the 48-byte compressed BLS public key for a validator index.
func (k *Keystore) PublicKey(index uint64) ([]byte, error) {
	sk, err := k.SecretKey(index)
	if err != nil {
		return nil, err
	}
	return sk.PublicKey().Marshal(), nil
}

// Sign signs msg with the validator's key (raw BLS sign over msg bytes; callers
// pass the signing root from compute_signing_root). Returns the 96-byte signature.
func (k *Keystore) Sign(index uint64, msg []byte) ([]byte, error) {
	sk, err := k.SecretKey(index)
	if err != nil {
		return nil, err
	}
	return sk.Sign(msg).Marshal(), nil
}

// withdrawalPath returns the EIP-2334 withdrawal-key path for a validator index.
func withdrawalPath(index uint64) string {
	return fmt.Sprintf("m/12381/3600/%d/0", index)
}

// WithdrawalSecretKey returns the validator's withdrawal signing key (path
// m/12381/3600/i/0), deriving and caching on first use.
func (k *Keystore) WithdrawalSecretKey(index uint64) (e2types.PrivateKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if sk, ok := k.wkeys[index]; ok {
		return sk, nil
	}
	sk, err := util.PrivateKeyFromSeedAndPath(k.seed, withdrawalPath(index))
	if err != nil {
		return nil, fmt.Errorf("derive %s: %w", withdrawalPath(index), err)
	}
	k.wkeys[index] = sk
	return sk, nil
}

// WithdrawalPublicKey returns the 48-byte BLS withdrawal public key (the from_bls_pubkey
// of a BLSToExecutionChange).
func (k *Keystore) WithdrawalPublicKey(index uint64) ([]byte, error) {
	sk, err := k.WithdrawalSecretKey(index)
	if err != nil {
		return nil, err
	}
	return sk.PublicKey().Marshal(), nil
}

// SignWithdrawal signs msg with the validator's withdrawal key.
func (k *Keystore) SignWithdrawal(index uint64, msg []byte) ([]byte, error) {
	sk, err := k.WithdrawalSecretKey(index)
	if err != nil {
		return nil, err
	}
	return sk.Sign(msg).Marshal(), nil
}
