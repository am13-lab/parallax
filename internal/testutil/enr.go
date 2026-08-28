package testutil

import (
	"encoding/base64"
	"sort"
)

// BuildTestENRFields constructs a syntactically valid ENR string from the
// given key-value fields, plus the mandatory id/secp256k1 pair. Keys are
// sorted per EIP-778. The signature is fake; decoders under test do not
// verify signatures.
func BuildTestENRFields(fields map[string][]byte) string {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = 0xAA
	}
	items := [][]byte{
		EncodeRLPItem(sig),
		EncodeRLPItem([]byte{0x01}), // seq = 1
		EncodeRLPString("id"), EncodeRLPString("v4"),
		EncodeRLPString("secp256k1"), EncodeRLPItem(fakeCompressedKey()),
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		items = append(items, EncodeRLPString(k), EncodeRLPItem(fields[k]))
	}
	record := EncodeRLPList(items...)
	return "enr:" + base64.RawURLEncoding.EncodeToString(record)
}

// BuildTestENR builds a record with eth2 and attnets fields, the common
// case for the beacon-state fakes.
func BuildTestENR(eth2 []byte, attnets []byte) string {
	return BuildTestENRFields(map[string][]byte{
		"eth2":    eth2,
		"attnets": attnets,
	})
}
