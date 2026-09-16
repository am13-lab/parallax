package wire

import (
	"encoding/binary"
	"fmt"
)

// ResponseChunk is one parsed req/resp response chunk.
type ResponseChunk struct {
	ResultCode byte   // 0=success, 1=invalid, 2=error, 3=unavailable
	Context    []byte // 4-byte ForkDigest context (V2+), nil for V1
	Payload    []byte // decoded body (SSZ on success, UTF-8 message on error)
	Malformed  bool   // framing or decoded length was invalid
}

// ParseReqRespResponse parses raw response bytes into chunks, assuming V2+
// framing (4-byte context after the result code).
func ParseReqRespResponse(data []byte) []ResponseChunk {
	return parseReqRespChunks(data, true)
}

// ParseReqRespResponseV1 parses V1 framing (no context bytes).
func ParseReqRespResponseV1(data []byte) []ResponseChunk {
	return parseReqRespChunks(data, false)
}

func parseReqRespChunks(data []byte, hasContext bool) []ResponseChunk {
	if len(data) == 0 {
		return nil
	}

	var chunks []ResponseChunk
	offset := 0

	for offset < len(data) {
		chunk := ResponseChunk{
			ResultCode: data[offset],
		}
		offset++

		// Error responses carry a UTF-8 message with its own varint prefix;
		// chunk boundaries after an error are not recoverable.
		if chunk.ResultCode != 0x00 {
			msgLen, n := binary.Uvarint(data[offset:])
			if n > 0 && uint64(len(data)-offset-n) >= msgLen {
				chunk.Payload = data[offset+n : offset+n+int(msgLen)]
			} else {
				chunk.Malformed = true
				chunk.Payload = data[offset:]
			}
			chunks = append(chunks, chunk)
			break
		}

		if hasContext {
			if offset+4 > len(data) {
				chunk.Malformed = true
				chunk.Payload = data[offset:]
				chunks = append(chunks, chunk)
				break
			}
			chunk.Context = data[offset : offset+4]
			offset += 4
		}

		sszLen, varintN := binary.Uvarint(data[offset:])
		if varintN <= 0 || sszLen == 0 {
			chunk.Malformed = true
			chunk.Payload = data[offset:]
			chunks = append(chunks, chunk)
			break
		}
		offset += varintN

		consumed := scanSnappyFrameSize(data[offset:], sszLen)
		if consumed <= 0 || offset+consumed > len(data) {
			chunk.Malformed = true
			chunk.Payload = data[offset:]
			chunks = append(chunks, chunk)
			break
		}

		decoded, err := SnappyDecode(data[offset : offset+consumed])
		if err != nil {
			chunk.Malformed = true
			chunk.Payload = data[offset : offset+consumed]
		} else if uint64(len(decoded)) != sszLen {
			chunk.Malformed = true
			chunk.Payload = decoded
		} else {
			chunk.Payload = decoded
		}

		offset += consumed
		chunks = append(chunks, chunk)
	}

	return chunks
}

// scanSnappyFrameSize scans snappy framing chunks and returns the total byte
// count needed to decode at least sszLen bytes, or -1 on error.
func scanSnappyFrameSize(data []byte, sszLen uint64) int {
	offset := 0
	var decoded uint64

	for offset < len(data) && decoded < sszLen {
		chunkType := data[offset]
		offset++

		if offset+3 > len(data) {
			return -1
		}
		chunkLen := int(data[offset]) | int(data[offset+1])<<8 | int(data[offset+2])<<16
		offset += 3

		if offset+chunkLen > len(data) {
			return -1
		}

		switch chunkType {
		case 0xFF:
			// Stream identifier: skip.
		case 0x00:
			if chunkLen > 4 {
				compressedData := data[offset+4 : offset+chunkLen]
				if decompLen, _, err := snappyBlockDecodedLen(compressedData); err == nil {
					decoded += uint64(decompLen)
				} else {
					return -1
				}
			}
		case 0x01:
			if chunkLen > 4 {
				decoded += uint64(chunkLen - 4)
			}
		default:
			// Unknown chunk type: skip per the snappy framing spec.
		}

		offset += chunkLen
	}
	if decoded < sszLen {
		return -1
	}

	return offset
}

// snappyBlockDecodedLen reads the varint-encoded uncompressed length at the
// start of a snappy compressed block.
func snappyBlockDecodedLen(compressed []byte) (int, int, error) {
	var x uint64
	var s uint
	for i := 0; i < len(compressed) && i < 10; i++ {
		b := compressed[i]
		if b < 0x80 {
			return int(x | uint64(b)<<s), i + 1, nil
		}
		x |= uint64(b&0x7f) << s
		s += 7
	}
	return 0, 0, fmt.Errorf("invalid snappy block header")
}
