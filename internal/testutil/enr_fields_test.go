package testutil

import (
	"testing"

	"parallax/enr"
)

func TestBuildTestENRFieldsDecodes(t *testing.T) {
	eth2 := make([]byte, 16)
	attnets := make([]byte, 8)
	syncnets := []byte{0x0f}
	cgc := []byte{8}
	nfd := []byte{1, 2, 3, 4}
	ip := []byte{127, 0, 0, 1}
	tcp := []byte{0x23, 0x28} // 9000

	enrStr := BuildTestENRFields(map[string][]byte{
		"eth2": eth2, "attnets": attnets, "syncnets": syncnets,
		"cgc": cgc, "nfd": nfd, "ip": ip, "tcp": tcp,
	})
	rec, err := enr.DecodeENR(enrStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"eth2", "attnets", "syncnets", "cgc", "nfd", "ip", "tcp", "id", "secp256k1"} {
		if !rec.HasKey(key) {
			t.Fatalf("key %s missing", key)
		}
	}
	if got := rec.KeySize("syncnets"); got != 1 {
		t.Fatalf("syncnets size: %d", got)
	}
	if val, _, ok := rec.GetCGC(); !ok || val != 8 {
		t.Fatalf("cgc: %d %v", val, ok)
	}
	if nfd := rec.GetNFD(); len(nfd) != 4 {
		t.Fatalf("nfd: %x", nfd)
	}
}
