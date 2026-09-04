package cases

import (
	"encoding/binary"
	"math/rand"

	"parallax/wire"
)

// irmutators.go — payload mutators ported from p2p-testing (mutators.go and
// gossip_mutators.go), reduced to the ten mutators referenced by the IR.
// Simplification: the Mutator struct's taxonomy metadata (Level/Family) is
// dropped; a name -> transform map is all the walker and renderer need.
//
// Semantics: the transform receives the builder output and returns the FINAL
// wire bytes. req/resp mutators corrupt the framed payload; gossip mutators
// produce snappy(ssz) themselves.

const irMaxRequestBlocksDeneb = 128

var irMutators = map[string]func(payload []byte, rng *rand.Rand) []byte{
	// --- req/resp (operate on varint+snappy framed payloads) ---
	"truncate_half": func(payload []byte, rng *rand.Rand) []byte {
		return wire.BuildMalformedSSZSnappy(payload, wire.MalformTruncateHalf, rng)
	},
	"random_bytes": func(payload []byte, rng *rand.Rand) []byte {
		return wire.BuildMalformedSSZSnappy(payload, wire.MalformRandomBytes, rng)
	},
	"break_snappy": func(payload []byte, rng *rand.Rand) []byte {
		return wire.BuildMalformedSSZSnappy(payload, wire.MalformBreakSnappyStreamID, rng)
	},
	"append_garbage": func(payload []byte, rng *rand.Rand) []byte {
		return wire.BuildMalformedSSZSnappy(payload, wire.MalformAppendGarbage, rng)
	},
	"count_zero": func(_ []byte, _ *rand.Rand) []byte {
		// BlocksByRange: set count to 0.
		return buildRangeCountBody(0, 0)
	},
	"count_over_max": func(_ []byte, _ *rand.Rand) []byte {
		// BlocksByRange: count beyond MAX_REQUEST_BLOCKS_DENEB.
		return buildRangeCountBody(0, irMaxRequestBlocksDeneb+1)
	},

	// --- gossip (produce snappy(ssz) themselves) ---
	"gossip_truncate": func(payload []byte, _ *rand.Rand) []byte {
		encoded := wire.SnappyEncode(payload)
		if len(encoded) > 1 {
			return encoded[:len(encoded)/2]
		}
		return encoded
	},
	"gossip_random_bytes": func(payload []byte, rng *rand.Rand) []byte {
		size := 100
		if len(payload) > 0 {
			size = len(payload)
		}
		garbage := make([]byte, size)
		rng.Read(garbage)
		return wire.SnappyEncode(garbage)
	},
	"gossip_append_garbage": func(payload []byte, rng *rand.Rand) []byte {
		encoded := wire.SnappyEncode(payload)
		garbage := make([]byte, 32)
		rng.Read(garbage)
		return append(encoded, garbage...)
	},
	"gossip_cross_type": func(payload []byte, rng *rand.Rand) []byte {
		// Cross-type injection: small payload -> large data-column-shaped
		// garbage; large payload -> small attestation-shaped garbage.
		if len(payload) < 300 {
			big := make([]byte, 500)
			rng.Read(big)
			return wire.SnappyEncode(big)
		}
		small := make([]byte, 100)
		rng.Read(small)
		return wire.SnappyEncode(small)
	},
}

// irApplyMutator applies the named mutator; unknown names return the payload
// unchanged (the renderer only emits known names).
func irApplyMutator(name string, payload []byte, rng *rand.Rand) []byte {
	if m, ok := irMutators[name]; ok {
		return m(payload, rng)
	}
	return payload
}

// buildRangeCountBody builds a 16-byte BlocksByRange {start_slot, count} body,
// framed for req/resp.
func buildRangeCountBody(start, count uint64) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], start)
	binary.LittleEndian.PutUint64(buf[8:16], count)
	return wire.BuildSSZSnappy(buf)
}
