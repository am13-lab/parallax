package wire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// EncodeVarint encodes a uint64 as an unsigned varint.
func EncodeVarint(x uint64) []byte {
	var buf [10]byte
	n := binary.PutUvarint(buf[:], x)
	return buf[:n]
}

// DecodeVarint reads an unsigned varint from a reader. A truncated varint
// yields io.ErrUnexpectedEOF.
func DecodeVarint(r io.Reader) (uint64, error) {
	var x uint64
	var s uint
	for i := 0; i < 10; i++ {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			if err == io.EOF {
				return 0, fmt.Errorf("read varint byte: %w", io.ErrUnexpectedEOF)
			}
			return 0, fmt.Errorf("read varint byte: %w", err)
		}
		if b[0] < 0x80 {
			return x | uint64(b[0])<<s, nil
		}
		x |= uint64(b[0]&0x7f) << s
		s += 7
	}
	return 0, fmt.Errorf("varint too long")
}
