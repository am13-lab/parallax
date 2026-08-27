package wire

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/golang/snappy"
)

// Gossip message-id domains (consensus-specs p2p-interface, Altair onward).
var (
	MessageDomainValidSnappy   = []byte{0x01, 0x00, 0x00, 0x00}
	MessageDomainInvalidSnappy = []byte{0x00, 0x00, 0x00, 0x00}
)

// GossipMessageID computes the Altair+ gossipsub message-id for a
// snappy-compressed message on the given topic. Compressible data is hashed
// under MESSAGE_DOMAIN_VALID_SNAPPY over the decompressed payload; anything
// that fails to decompress falls to MESSAGE_DOMAIN_INVALID_SNAPPY over the
// raw bytes alone (the topic is not mixed in for the invalid domain).
func GossipMessageID(topic string, data []byte) []byte {
	h := sha256.New()
	if decompressed, err := snappy.Decode(nil, data); err == nil {
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(topic)))
		h.Write(MessageDomainValidSnappy)
		h.Write(lenBuf[:])
		h.Write([]byte(topic))
		h.Write(decompressed)
	} else {
		h.Write(MessageDomainInvalidSnappy)
		h.Write(data)
	}
	return h.Sum(nil)[:20]
}
