package enr_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"libp2p-difftest/enr"
	"libp2p-difftest/internal/testutil"
)

func TestDecodeENRFields(t *testing.T) {
	eth2 := make([]byte, 16)
	copy(eth2[0:4], []byte{0x12, 0x34, 0x56, 0x78}) // fork digest
	copy(eth2[4:8], []byte{0x04, 0x00, 0x00, 0x00}) // next fork version
	binary.LittleEndian.PutUint64(eth2[8:16], 7)    // next fork epoch
	attnets := []byte{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	enrStr := testutil.BuildTestENR(t, eth2, attnets)
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
	if _, err := enr.DecodeENR("enr:AAAA"); err == nil {
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
