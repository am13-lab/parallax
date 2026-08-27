package wire

import (
	"bytes"
	"errors"
	"io"

	"github.com/golang/snappy"
)

// maxSnappyUncompressedChunk is the maximum uncompressed data per snappy
// framing chunk, per the framing format spec.
const maxSnappyUncompressedChunk = 65536

// SnappyEncode encodes data using the snappy framing format (uncompressed
// chunks). Large payloads are split into chunks of at most 65536 bytes.
func SnappyEncode(data []byte) []byte {
	streamID := []byte{0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59}
	result := make([]byte, 0, len(streamID)+len(data))
	result = append(result, streamID...)

	for offset := 0; offset < len(data); offset += maxSnappyUncompressedChunk {
		end := offset + maxSnappyUncompressedChunk
		if end > len(data) {
			end = len(data)
		}
		piece := data[offset:end]

		chunkLen := uint32(4 + len(piece))
		chunk := []byte{0x01}
		chunk = append(chunk, byte(chunkLen), byte(chunkLen>>8), byte(chunkLen>>16))
		cs := MaskedCRC32c(piece)
		chunk = append(chunk, byte(cs), byte(cs>>8), byte(cs>>16), byte(cs>>24))
		chunk = append(chunk, piece...)
		result = append(result, chunk...)
	}

	return result
}

// SnappyDecode decodes snappy framing format data, validating stream id,
// chunk headers and CRCs via the reference implementation.
func SnappyDecode(data []byte) ([]byte, error) {
	reader := snappy.NewReader(bytes.NewReader(data))
	return io.ReadAll(reader)
}

// GossipSnappyEncode encodes gossip payloads as a raw snappy block (gossip
// does not use the req/resp varint-plus-framing scheme).
func GossipSnappyEncode(sszData []byte) []byte {
	return snappy.Encode(nil, sszData)
}

// MaskedCRC32c computes the masked CRC32c used in snappy framing chunks.
func MaskedCRC32c(data []byte) uint32 {
	crc := CRC32c(data)
	return ((crc >> 15) | (crc << 17)) + 0xa282ead8
}

// CRC32c computes Castagnoli CRC32.
func CRC32c(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0x82F63B78
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}

// ErrCRCMismatch reports a snappy framing chunk whose CRC did not match.
var ErrCRCMismatch = errors.New("snappy chunk crc mismatch")
