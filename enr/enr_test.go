package enr_test

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"libp2p-difftest/enr"
)

// encodeRLP encodes per the RLP rules needed to build an ENR list, kept
// independent of the package under test (EIP-778 wire format knowledge).
func encodeRLP(payload []byte) []byte {
	if len(payload) == 1 && payload[0] < 0x80 {
		return payload
	}
	if len(payload) <= 55 {
		return append([]byte{byte(0x80 + len(payload))}, payload...)
	}
	lenBytes := minimalBE(uint64(len(payload)))
	return append(append([]byte{byte(0xb7+len(lenBytes))}, lenBytes...), payload...)
}

func encodeString(s string) []byte {
	b := []byte(s)
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	if len(b) <= 55 {
		return append([]byte{byte(0x80 + len(b))}, b...)
	}
	lenBytes := minimalBE(uint64(len(b)))
	return append(append([]byte{byte(0xb7+len(lenBytes))}, lenBytes...), b...)
}

func encodeList(items ...[]byte) []byte {
	var payload []byte
	for _, it := range items {
		payload = append(payload, it...)
	}
	if len(payload) <= 55 {
		return append([]byte{byte(0xc0 + len(payload))}, payload...)
	}
	lenBytes := minimalBE(uint64(len(payload)))
	return append(append([]byte{byte(0xf7+len(lenBytes))}, lenBytes...), payload...)
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

// buildTestENR constructs a syntactically valid record the way a client
// would: [signature(64) seq k1 v1 k2 v2 ...] base64url, enr: prefix.
func buildTestENR(t *testing.T, eth2 []byte, attnets []byte) string {
	t.Helper()
	sig := bytes64(0xAA)
	seq := encodeRLP([]byte{0x01})
	record := encodeList(
		encodeRLP(sig),
		seq,
		encodeString("id"), encodeString("v4"),
		encodeString("secp256k1"), encodeRLP(bytes33(0x02)),
		encodeString("eth2"), encodeRLP(eth2),
		encodeString("attnets"), encodeRLP(attnets),
	)
	return "enr:" + base64.RawURLEncoding.EncodeToString(record)
}

func bytes64(b byte) []byte {
	out := make([]byte, 64)
	for i := range out {
		out[i] = b
	}
	return out
}

func bytes33(b byte) []byte {
	out := make([]byte, 33)
	out[0] = b
	for i := 1; i < len(out); i++ {
		out[i] = byte(i)
	}
	return out
}

func TestDecodeENRFields(t *testing.T) {
	eth2 := make([]byte, 16)
	copy(eth2[0:4], []byte{0x12, 0x34, 0x56, 0x78})          // fork digest
	copy(eth2[4:8], []byte{0x04, 0x00, 0x00, 0x00})          // next fork version
	binary.LittleEndian.PutUint64(eth2[8:16], 7)             // next fork epoch
	attnets := []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	enrStr := buildTestENR(t, eth2, attnets)
	rec, err := enr.DecodeENR(enrStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !rec.HasKey("eth2") || !rec.HasKey("attnets") || !rec.HasKey("id") {
		t.Fatal("eth2/attnets/id keys must be present")
	}
	if rec.HasKey("nope") {
		t.Fatal("unknown key must not be present")
	}

	forkID, err := rec.GetEth2()
	if err != nil {
		t.Fatalf("get eth2: %v", err)
	}
	if forkID.ForkDigest != [4]byte{0x12, 0x34, 0x56, 0x78} {
		t.Fatalf("fork digest: %x", forkID.ForkDigest)
	}
	if forkID.NextForkVersion != [4]byte{0x04, 0x00, 0x00, 0x00} {
		t.Fatalf("next fork version: %x", forkID.NextForkVersion)
	}
	if forkID.NextForkEpoch != 7 {
		t.Fatalf("next fork epoch: %d", forkID.NextForkEpoch)
	}
	if got := rec.GetAttnets(); len(got) != 8 || got[0] != 0xff {
		t.Fatalf("attnets: %x", got)
	}
	if rec.Seq != 1 {
		t.Fatalf("sequence: %d", rec.Seq)
	}
	if len(rec.Signature) != 64 {
		t.Fatalf("signature length: %d", len(rec.Signature))
	}
}

func TestDecodeENRInvalidInputs(t *testing.T) {
	if _, err := enr.DecodeENR("not-an-enr"); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("missing prefix must be rejected: %v", err)
	}
	if _, err := enr.DecodeENR("enr:!!!not-base64!!!"); err == nil {
		t.Fatal("bad base64 must be rejected")
	}
	if _, err := enr.DecodeENR("enr:" + base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02})); err == nil {
		t.Fatal("truncated record must be rejected")
	}
}

func TestNodeIDFromSecp256k1(t *testing.T) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pk := priv.PubKey().SerializeCompressed()
	id, err := enr.NodeIDFromSecp256k1(pk)
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	if len(id) != 32 {
		t.Fatalf("node id must be 32 bytes, got %d", len(id))
	}
	again, _ := enr.NodeIDFromSecp256k1(pk)
	if string(id) != string(again) {
		t.Fatal("node id must be deterministic")
	}
}
