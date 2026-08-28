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

// EncodeRLPItem encodes one RLP item (string or single byte).
func EncodeRLPItem(payload []byte) []byte {
	if len(payload) == 1 && payload[0] < 0x80 {
		return payload
	}
	if len(payload) <= 55 {
		return append([]byte{byte(0x80 + len(payload))}, payload...)
	}
	lenBytes := minimalBE(uint64(len(payload)))
	return append(append([]byte{byte(0xb7 + len(lenBytes))}, lenBytes...), payload...)
}

// EncodeRLPString encodes a string item.
func EncodeRLPString(s string) []byte { return EncodeRLPItem([]byte(s)) }

// EncodeRLPList encodes items as one RLP list.
func EncodeRLPList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	if len(payload) <= 55 {
		return append([]byte{byte(0xc0 + len(payload))}, payload...)
	}
	lenBytes := minimalBE(uint64(len(payload)))
	return append(append([]byte{byte(0xf7 + len(lenBytes))}, lenBytes...), payload...)
}

func minimalBE(v uint64) []byte {
	var out []byte
	for i := 7; i >= 0; i-- {
		b := byte(v >> (8 * i))
		if b != 0 || len(out) > 0 {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		out = []byte{0}
	}
	return out
}

func fakeCompressedKey() []byte {
	out := make([]byte, 33)
	out[0] = 0x02
	for i := 1; i < len(out); i++ {
		out[i] = byte(i)
	}
	return out
}
