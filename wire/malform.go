package wire

import "math/rand"

// MalformationType describes how to corrupt SSZ-snappy data.
type MalformationType int

const (
	MalformTruncateOne MalformationType = iota
	MalformTruncateHalf
	MalformTruncateAll
	MalformRandomBytes
	MalformBreakSnappyStreamID
	MalformBreakSnappyCRC
	MalformAppendGarbage
)

// BuildMalformedSSZSnappy produces a corrupted SSZ-snappy frame for testing
// target behavior. A nil rng falls back to a deterministic source so runs
// stay reproducible.
func BuildMalformedSSZSnappy(sszData []byte, corruption MalformationType, rng *rand.Rand) []byte {
	if rng == nil {
		rng = rand.New(rand.NewSource(0))
	}

	switch corruption {
	case MalformTruncateOne:
		if len(sszData) > 0 {
			sszData = sszData[:len(sszData)-1]
		}
		return BuildSSZSnappy(sszData)

	case MalformTruncateHalf:
		if len(sszData) > 1 {
			sszData = sszData[:len(sszData)/2]
		}
		return BuildSSZSnappy(sszData)

	case MalformTruncateAll:
		return BuildSSZSnappy(nil)

	case MalformRandomBytes:
		garbage := make([]byte, len(sszData))
		rng.Read(garbage)
		return BuildSSZSnappy(garbage)

	case MalformBreakSnappyStreamID:
		encoded := BuildSSZSnappy(sszData)
		varintLen := len(EncodeVarint(uint64(len(sszData))))
		if len(encoded) > varintLen+5 {
			encoded[varintLen+4] ^= 0xFF
		}
		return encoded

	case MalformBreakSnappyCRC:
		encoded := BuildSSZSnappy(sszData)
		varintLen := len(EncodeVarint(uint64(len(sszData))))
		crcOffset := varintLen + 10 + 4
		if len(encoded) > crcOffset+4 {
			encoded[crcOffset] ^= 0xFF
			encoded[crcOffset+1] ^= 0xFF
		}
		return encoded

	case MalformAppendGarbage:
		encoded := BuildSSZSnappy(sszData)
		garbage := make([]byte, 32)
		rng.Read(garbage)
		return append(encoded, garbage...)

	default:
		return BuildSSZSnappy(sszData)
	}
}
