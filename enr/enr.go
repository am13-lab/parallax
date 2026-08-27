package enr

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// ENRRecord represents a decoded Ethereum Node Record.
type ENRRecord struct {
	Signature []byte
	Seq       uint64
	Pairs     map[string][]byte // key → raw value bytes
	Raw       []byte            // original decoded bytes
}

// ENRForkID represents the SSZ-encoded ENRForkID (16 bytes).
type ENRForkID struct {
	ForkDigest      [4]byte
	NextForkVersion [4]byte
	NextForkEpoch   uint64
}

// DecodeENR decodes an ENR string ("enr:..." base64url) into an ENRRecord.
func DecodeENR(enrString string) (*ENRRecord, error) {
	enrString = strings.TrimSpace(enrString)
	if !strings.HasPrefix(enrString, "enr:") {
		return nil, fmt.Errorf("ENR must start with 'enr:' prefix")
	}
	encoded := enrString[4:]

	// Base64url decode (no padding).
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}

	if len(data) > 300 {
		return nil, fmt.Errorf("ENR exceeds 300 byte maximum: %d bytes", len(data))
	}

	// RLP decode: top-level list.
	items, err := rlpDecodeList(data)
	if err != nil {
		return nil, fmt.Errorf("RLP decode: %w", err)
	}

	if len(items) < 2 {
		return nil, fmt.Errorf("ENR too short: need at least signature and seq, got %d items", len(items))
	}
	if len(items)%2 != 0 {
		return nil, fmt.Errorf("ENR has odd number of items (%d): expected signature, seq, then key-value pairs", len(items))
	}

	record := &ENRRecord{
		Signature: items[0],
		Raw:       data,
		Pairs:     make(map[string][]byte),
	}

	// Seq is the second item, encoded as RLP integer (big-endian, no leading zeros).
	record.Seq = rlpBytesToUint64(items[1])

	// Key-value pairs start at index 2.
	for i := 2; i+1 < len(items); i += 2 {
		key := string(items[i])
		value := items[i+1]
		record.Pairs[key] = value
	}

	return record, nil
}

// HasKey checks if the ENR contains a given key.
func (r *ENRRecord) HasKey(key string) bool {
	_, ok := r.Pairs[key]
	return ok
}

// KeySize returns the byte length of a key's value, or -1 if not present.
func (r *ENRRecord) KeySize(key string) int {
	v, ok := r.Pairs[key]
	if !ok {
		return -1
	}
	return len(v)
}

// GetEth2 parses the 16-byte eth2 field into an ENRForkID.
func (r *ENRRecord) GetEth2() (*ENRForkID, error) {
	data, ok := r.Pairs["eth2"]
	if !ok {
		return nil, fmt.Errorf("eth2 key not found in ENR")
	}
	if len(data) != 16 {
		return nil, fmt.Errorf("eth2 field is %d bytes, expected 16", len(data))
	}
	fid := &ENRForkID{}
	copy(fid.ForkDigest[:], data[0:4])
	copy(fid.NextForkVersion[:], data[4:8])
	fid.NextForkEpoch = binary.LittleEndian.Uint64(data[8:16])
	return fid, nil
}

// GetAttnets returns the raw attnets bitvector, or nil if not present.
func (r *ENRRecord) GetAttnets() []byte {
	return r.Pairs["attnets"]
}

// GetSyncnets returns the raw syncnets bitvector, or nil if not present.
func (r *ENRRecord) GetSyncnets() []byte {
	return r.Pairs["syncnets"]
}

// GetCGC returns the custody group count from the cgc field.
// Returns 0 if not present, and the raw bytes for validation.
func (r *ENRRecord) GetCGC() (uint64, []byte, bool) {
	data, ok := r.Pairs["cgc"]
	if !ok {
		return 0, nil, false
	}
	if len(data) == 0 {
		return 0, data, true // 0 encoded as empty byte string
	}
	return rlpBigEndianToUint64(data), data, true
}

// GetNFD returns the next fork digest (4 bytes), or nil if not present.
func (r *ENRRecord) GetNFD() []byte {
	return r.Pairs["nfd"]
}

// --- Lightweight RLP decoder ---

// rlpDecodeList decodes an RLP-encoded list and returns its items as byte slices.
func rlpDecodeList(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty RLP data")
	}

	// Decode the outer list envelope.
	_, contentStart, contentLen, err := rlpDecodeHeader(data)
	if err != nil {
		return nil, fmt.Errorf("outer list: %w", err)
	}

	// Verify it's a list (prefix >= 0xc0).
	if data[0] < 0xc0 {
		return nil, fmt.Errorf("expected RLP list, got string prefix 0x%02x", data[0])
	}

	content := data[contentStart : contentStart+contentLen]
	var items [][]byte
	offset := 0

	for offset < len(content) {
		itemType, itemStart, itemLen, err := rlpDecodeHeader(content[offset:])
		if err != nil {
			return nil, fmt.Errorf("item at offset %d: %w", offset, err)
		}

		var item []byte
		if itemType == rlpTypeString {
			item = content[offset+itemStart : offset+itemStart+itemLen]
		} else {
			// Nested list — return raw bytes including header.
			totalLen := itemStart + itemLen
			item = content[offset : offset+totalLen]
		}

		items = append(items, item)
		offset += itemStart + itemLen
	}

	return items, nil
}

const (
	rlpTypeString = 0
	rlpTypeList   = 1
)

// rlpDecodeHeader decodes the RLP header and returns (type, contentOffset, contentLength, error).
func rlpDecodeHeader(data []byte) (int, int, int, error) {
	if len(data) == 0 {
		return 0, 0, 0, fmt.Errorf("empty data")
	}

	prefix := data[0]

	switch {
	case prefix <= 0x7f:
		// Single byte.
		return rlpTypeString, 0, 1, nil

	case prefix <= 0xb7:
		// Short string: 0-55 bytes.
		strLen := int(prefix - 0x80)
		if 1+strLen > len(data) {
			return 0, 0, 0, fmt.Errorf("short string truncated: need %d, have %d", 1+strLen, len(data))
		}
		return rlpTypeString, 1, strLen, nil

	case prefix <= 0xbf:
		// Long string: length of length follows.
		lenOfLen := int(prefix - 0xb7)
		if 1+lenOfLen > len(data) {
			return 0, 0, 0, fmt.Errorf("long string length truncated")
		}
		strLen := rlpReadLen(data[1:1+lenOfLen], lenOfLen)
		if 1+lenOfLen+strLen > len(data) {
			return 0, 0, 0, fmt.Errorf("long string truncated: need %d, have %d", 1+lenOfLen+strLen, len(data))
		}
		return rlpTypeString, 1 + lenOfLen, strLen, nil

	case prefix <= 0xf7:
		// Short list: 0-55 bytes total payload.
		listLen := int(prefix - 0xc0)
		if 1+listLen > len(data) {
			return 0, 0, 0, fmt.Errorf("short list truncated: need %d, have %d", 1+listLen, len(data))
		}
		return rlpTypeList, 1, listLen, nil

	default:
		// Long list: length of length follows.
		lenOfLen := int(prefix - 0xf7)
		if 1+lenOfLen > len(data) {
			return 0, 0, 0, fmt.Errorf("long list length truncated")
		}
		listLen := rlpReadLen(data[1:1+lenOfLen], lenOfLen)
		if 1+lenOfLen+listLen > len(data) {
			return 0, 0, 0, fmt.Errorf("long list truncated: need %d, have %d", 1+lenOfLen+listLen, len(data))
		}
		return rlpTypeList, 1 + lenOfLen, listLen, nil
	}
}

// rlpReadLen reads a big-endian integer from n bytes.
func rlpReadLen(data []byte, n int) int {
	var result int
	for i := 0; i < n; i++ {
		result = result<<8 | int(data[i])
	}
	return result
}

// rlpBytesToUint64 converts RLP-encoded integer bytes (big-endian, no leading zeros) to uint64.
func rlpBytesToUint64(data []byte) uint64 {
	var result uint64
	for _, b := range data {
		result = result<<8 | uint64(b)
	}
	return result
}

// rlpBigEndianToUint64 converts big-endian bytes to uint64.
func rlpBigEndianToUint64(data []byte) uint64 {
	return rlpBytesToUint64(data)
}

// GetSecp256k1 returns the raw secp256k1 public key bytes from the ENR, or nil if not present.
func (r *ENRRecord) GetSecp256k1() []byte {
	return r.Pairs["secp256k1"]
}

// NodeIDFromSecp256k1 computes the Discv5 node ID from a compressed secp256k1 public key.
// The node ID is keccak256(uncompressed_pubkey_x || uncompressed_pubkey_y) where x,y are 32 bytes each.
func NodeIDFromSecp256k1(compressedPubkey []byte) ([]byte, error) {
	if len(compressedPubkey) != 33 {
		return nil, fmt.Errorf("expected 33-byte compressed pubkey, got %d bytes", len(compressedPubkey))
	}

	// Parse the compressed public key.
	pubKey, err := secp256k1.ParsePubKey(compressedPubkey)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 pubkey: %w", err)
	}

	// SerializeUncompressed returns 65 bytes: 0x04 || x(32) || y(32).
	uncompressed := pubKey.SerializeUncompressed()

	// Keccak256 of the 64-byte uncompressed point (skip the 0x04 prefix).
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	return h.Sum(nil), nil
}
