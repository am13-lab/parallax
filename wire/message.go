package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Uint64ToSSZ encodes a uint64 as 8-byte little-endian SSZ.
func Uint64ToSSZ(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}

// BuildSSZSnappy wraps SSZ data as a req/resp frame: varint(uncompressed
// length) followed by the snappy framing of the data.
func BuildSSZSnappy(sszData []byte) []byte {
	varint := EncodeVarint(uint64(len(sszData)))
	framed := SnappyEncode(sszData)
	buf := make([]byte, 0, len(varint)+len(framed))
	buf = append(buf, varint...)
	buf = append(buf, framed...)
	return buf
}

// BuildReqRespRequest is BuildSSZSnappy under the req/resp name.
func BuildReqRespRequest(sszData []byte) []byte {
	return BuildSSZSnappy(sszData)
}

// ParseReqRespRequest decodes a complete req/resp request frame (buffered
// form) and returns the SSZ body. Trailing bytes after the frame are ignored.
func ParseReqRespRequest(data []byte) ([]byte, error) {
	sszLen, n := binary.Uvarint(data)
	if n <= 0 {
		return nil, fmt.Errorf("invalid request varint (n=%d)", n)
	}
	if sszLen == 0 {
		return []byte{}, nil
	}
	if len(data) < n {
		return nil, fmt.Errorf("request varint claims %d bytes, %d available", sszLen, len(data)-n)
	}
	body := data[n:]
	consumed := scanSnappyFrameSize(body, sszLen)
	if consumed <= 0 {
		return nil, fmt.Errorf("cannot find snappy frame boundary for claimed length %d", sszLen)
	}
	decoded, err := SnappyDecode(body[:consumed])
	if err != nil {
		return nil, fmt.Errorf("decode request body: %w", err)
	}
	if uint64(len(decoded)) != sszLen {
		return nil, fmt.Errorf("decoded length %d does not match claimed %d", len(decoded), sszLen)
	}
	return decoded, nil
}

// ReadFrame reads one req/resp frame from a stream and returns the raw
// snappy-framed body (not decoded). maxLen bounds the claimed uncompressed
// size so a hostile varint cannot force an unbounded read. Chunk CRCs are
// validated while reading, so corrupt frames fail here rather than at decode.
func ReadFrame(r io.Reader, maxLen uint64) ([]byte, error) {
	sszLen, err := DecodeVarint(r)
	if err != nil {
		return nil, err
	}
	if sszLen > maxLen {
		return nil, fmt.Errorf("claimed length %d exceeds max %d", sszLen, maxLen)
	}

	br := newPeekReader(r)
	var out []byte
	var decoded uint64
	for decoded < sszLen {
		header, err := br.readFull(4)
		if err != nil {
			return nil, fmt.Errorf("read snappy chunk header: %w", err)
		}
		chunkType := header[0]
		chunkLen := int(header[1]) | int(header[2])<<8 | int(header[3])<<16
		body, err := br.readFull(chunkLen)
		if err != nil {
			return nil, fmt.Errorf("read snappy chunk body: %w", err)
		}
		out = append(out, header...)
		out = append(out, body...)

		switch chunkType {
		case 0x00:
			if chunkLen < 5 {
				return nil, fmt.Errorf("compressed chunk too short (%d bytes)", chunkLen)
			}
			if MaskedCRC32c(body[4:]) != leUint32(body[:4]) {
				return nil, ErrCRCMismatch
			}
			n, _, err := snappyBlockDecodedLen(body[4:])
			if err != nil {
				return nil, fmt.Errorf("compressed chunk header: %w", err)
			}
			decoded += uint64(n)
		case 0x01:
			if chunkLen < 5 {
				return nil, fmt.Errorf("uncompressed chunk too short (%d bytes)", chunkLen)
			}
			if MaskedCRC32c(body[4:]) != leUint32(body[:4]) {
				return nil, ErrCRCMismatch
			}
			decoded += uint64(chunkLen - 4)
		case 0xFF:
			// Stream identifier chunk: nothing to count.
		default:
			// Unknown chunk type: skip per the snappy framing spec.
		}
	}
	return out, nil
}

func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// peekReader provides readFull with one-byte lookahead so a stream-id chunk
// at the start of a frame body is handled uniformly.
type peekReader struct {
	r   io.Reader
	buf bytes.Buffer
}

func newPeekReader(r io.Reader) *peekReader { return &peekReader{r: r} }

func (p *peekReader) readFull(n int) ([]byte, error) {
	for p.buf.Len() < n {
		var tmp [512]byte
		m, err := p.r.Read(tmp[:])
		if m > 0 {
			p.buf.Write(tmp[:m])
		}
		if err != nil {
			if p.buf.Len() < n {
				return nil, err
			}
			break
		}
	}
	out := make([]byte, n)
	copy(out, p.buf.Bytes()[:n])
	rest := append([]byte{}, p.buf.Bytes()[n:]...)
	p.buf.Reset()
	p.buf.Write(rest)
	return out, nil
}

// BuildVarintLengthMismatch creates a frame whose varint claims claimedLength
// while the body is the snappy framing of sszData.
func BuildVarintLengthMismatch(sszData []byte, claimedLength uint64) []byte {
	varint := EncodeVarint(claimedLength)
	framed := SnappyEncode(sszData)
	buf := make([]byte, 0, len(varint)+len(framed))
	buf = append(buf, varint...)
	buf = append(buf, framed...)
	return buf
}

// BuildRawVarintOnly returns just a varint-encoded length with no data.
func BuildRawVarintOnly(length uint64) []byte {
	return EncodeVarint(length)
}

// BuildVarintPlusRawBytes returns a varint followed by arbitrary raw bytes.
func BuildVarintPlusRawBytes(varintVal uint64, trailing []byte) []byte {
	varint := EncodeVarint(varintVal)
	buf := make([]byte, 0, len(varint)+len(trailing))
	buf = append(buf, varint...)
	buf = append(buf, trailing...)
	return buf
}

// BuildSnappySizeBomb creates a frame whose varint claims claimedSize bytes
// while the snappy frame contains actualData.
func BuildSnappySizeBomb(claimedSize uint64, actualData []byte) []byte {
	return BuildVarintLengthMismatch(actualData, claimedSize)
}
