package cases

import (
	"context"
	"encoding/binary"
	"math"
	"strings"

	"parallax/runner"
	"parallax/wire"
)

// Batch 2: the old repo's parameterized reqresp families (boundary,
// malformed, trailing bytes, length bombs) ported as table-driven
// constructors. IDs keep the old repo's family-first naming.

const (
	blocksByRangeV2   = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
	blobsByRangeV1    = "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
	dataColsByRangeV1 = "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
	dataColsByRootV1  = "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
)

const maxPayloadSize = 10 * 1024 * 1024 // GOSSIP_MAX_SIZE also bounds req/resp payloads

// whatFor derives a one-sentence explanation from a batch-2 case ID so the
// report can tell a reader what the test probes without code access.
func whatFor(id string) string {
	f := familyOf(id)
	rest := strings.TrimPrefix(id, "reqresp."+f+".")
	parts := strings.SplitN(rest, ".", 2)
	proto := parts[0]
	detail := ""
	if len(parts) > 1 {
		detail = strings.ReplaceAll(parts[1], "_", " ")
	}
	switch f {
	case "boundary":
		return "Range/counter boundary probe (" + detail + "); the client must handle the edge case without crashing, and all clients must agree."
	case "malformed":
		if proto == "" {
			return "Malformed payload (" + detail + "); the client must reject it, identically across clients."
		}
		return "Malformed " + proto + " payload (" + detail + "); the client must reject it, identically across clients."
	case "trailing_bytes":
		return "Valid " + proto + " request with trailing garbage bytes appended; framing rules require rejection, identically across clients."
	case "length_bomb":
		return proto + " with an oversized or lying length prefix (" + detail + "); the client must reject it without allocating."
	case "cryptomsg":
		rest = strings.TrimPrefix(id, "cryptomsg.")
		parts := strings.SplitN(rest, ".", 3)
		if len(parts) == 3 {
			return "Malformed " + parts[0] + " payload (" + strings.ReplaceAll(parts[1], "_", " ") + ", " + parts[2] + " body); the client must reject it, identically across clients."
		}
		return "Malformed payload probe; the client must reject it, identically across clients."
	}
	return ""
}

// exchangeSpec is the shared shape of every batch-2 case: one fixed request
// body per run, sent to all clients, verdicts classified and compared.
func exchangeSpec(id, protocol string, buildBody func(te runner.TestEnv) []byte,
	normalize func(string) string) runner.Spec {

	return runner.Spec{
		ID:       id,
		Category: "reqresp",
		What:     whatFor(id),
		Metadata: runner.Metadata{SpecRules: []string{"reqresp:" + familyOf(id)}},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			body := buildBody(te)
			results, details := map[string]string{}, map[string]string{}
			for _, c := range te.Clients {
				res, err := c.ReqResp(ctx, protocol, body, reqTimeout)
				out := outcome(res, err)
				if normalize != nil {
					out = normalize(out)
				}
				results[c.Name()] = out
			}
			return diverge(id, "reqresp", te.Meta, results, details)
		},
	}
}

func familyOf(id string) string {
	// reqresp.<family>.<rest> -> <family>
	rest := strings.TrimPrefix(id, "reqresp.")
	if dot := strings.Index(rest, "."); dot > 0 {
		return rest[:dot]
	}
	return rest
}

// rangeRequest builds the 16/24-byte fixed range containers.
func rangeRequest(start, count uint64, withStep bool) []byte {
	size := 16
	if withStep {
		size = 24
	}
	buf := make([]byte, size)
	binary.LittleEndian.PutUint64(buf[0:8], start)
	binary.LittleEndian.PutUint64(buf[8:16], count)
	if withStep {
		binary.LittleEndian.PutUint64(buf[16:24], 1) // step, deprecated, must be 1
	}
	return buf
}

// dataColumnsByRangeRequest builds the variable-length
// DataColumnsByRange container: (start, count, columns: List[uint64,64]).
func dataColumnsByRangeRequest(start, count uint64, columns []uint64) []byte {
	const fixed = 20
	buf := make([]byte, fixed+len(columns)*8)
	binary.LittleEndian.PutUint64(buf[0:8], start)
	binary.LittleEndian.PutUint64(buf[8:16], count)
	binary.LittleEndian.PutUint32(buf[16:20], uint32(fixed))
	for i, col := range columns {
		binary.LittleEndian.PutUint64(buf[fixed+i*8:fixed+(i+1)*8], col)
	}
	return buf
}

// batch2Specs returns the four ported families.
func batch2Specs() []runner.Spec {
	var specs []runner.Spec

	// --- boundary: arithmetic overflow in range processing ---
	boundaries := []struct {
		label    string
		protocol string
		body     func(te runner.TestEnv) []byte
	}{
		{"blocks_by_range.start_max_uint64", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(math.MaxUint64, 1, true))
		}},
		{"blocks_by_range.count_zero", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(0, 0, true))
		}},
		{"blocks_by_range.both_max", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(math.MaxUint64, math.MaxUint64, true))
		}},
		{"blobs_by_range.count_zero", blobsByRangeV1, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(0, 0, false))
		}},
		{"blobs_by_range.start_max_uint64", blobsByRangeV1, func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(rangeRequest(math.MaxUint64, 1, false))
		}},
		{"data_columns_by_range.count_zero", dataColsByRangeV1, func(te runner.TestEnv) []byte {
			return dataColumnsByRangeRequest(0, 0, []uint64{0})
		}},
		{"data_columns_by_range.start_max_uint64", dataColsByRangeV1, func(te runner.TestEnv) []byte {
			return dataColumnsByRangeRequest(math.MaxUint64, 1, []uint64{0})
		}},
		{"ping.varint_max_payload_boundary", pingV1, func(te runner.TestEnv) []byte {
			return wire.BuildVarintLengthMismatch(wire.Uint64ToSSZ(1), maxPayloadSize+1)
		}},
	}
	for _, b := range boundaries {
		id := "reqresp.boundary." + b.label
		specs = append(specs, exchangeSpec(id, b.protocol, b.body, nil))
	}

	// --- malformed: corrupted SSZ-snappy bodies ---
	malformations := []struct {
		label string
		mt    wire.MalformationType
	}{
		{"truncate_one", wire.MalformTruncateOne},
		{"truncate_half", wire.MalformTruncateHalf},
		{"truncate_all", wire.MalformTruncateAll},
		{"break_snappy_stream_id", wire.MalformBreakSnappyStreamID},
		{"break_snappy_crc", wire.MalformBreakSnappyCRC},
		{"append_garbage", wire.MalformAppendGarbage},
		// random_bytes on status is covered by the seed's
		// reqresp.status.malformed, so only ping gets it here.
		{"random_bytes", wire.MalformRandomBytes},
	}
	for _, m := range malformations {
		mt, label := m.mt, m.label
		specs = append(specs,
			exchangeSpec("reqresp.malformed.ping."+label, pingV1,
				func(te runner.TestEnv) []byte {
					return wire.BuildMalformedSSZSnappy(wire.Uint64ToSSZ(1), mt, te.RNG)
				}, nil))
		if label != "random_bytes" {
			specs = append(specs,
				exchangeSpec("reqresp.malformed.status."+label, statusV2,
					func(te runner.TestEnv) []byte {
						return wire.BuildMalformedSSZSnappy(make([]byte, 92), mt, te.RNG)
					}, nil))
		}
	}
	varintMismatches := []struct {
		label   string
		claimed uint64
	}{
		{"varint_zero", 0},
		{"varint_oversize", 1024 * 1024},
		{"varint_over_max_payload", maxPayloadSize + 1},
	}
	for _, vm := range varintMismatches {
		claimed := vm.claimed
		specs = append(specs, exchangeSpec(
			"reqresp.malformed.ping."+vm.label, pingV1,
			func(te runner.TestEnv) []byte {
				return wire.BuildVarintLengthMismatch(wire.Uint64ToSSZ(1), claimed)
			}, nil))
	}
	// A Status-sized body on the Ping stream (expects 8 bytes).
	specs = append(specs, exchangeSpec("reqresp.malformed.wrong_method_body", pingV1,
		func(te runner.TestEnv) []byte {
			return wire.BuildSSZSnappy(make([]byte, 92))
		}, nil))

	// --- trailing bytes: valid frame plus garbage ---
	trailing := []struct {
		label    string
		protocol string
		body     func(te runner.TestEnv) []byte
		// goodbye responses may legitimately be resets
		normalize func(string) string
	}{
		{"blocks_by_range.32", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return append(wire.BuildSSZSnappy(rangeRequest(0, 1, false)), make([]byte, 32)...)
		}, nil},
		{"blobs_by_range.32", blobsByRangeV1, func(te runner.TestEnv) []byte {
			return append(wire.BuildSSZSnappy(rangeRequest(0, 1, false)), make([]byte, 32)...)
		}, nil},
		{"data_columns_by_range.32", dataColsByRangeV1, func(te runner.TestEnv) []byte {
			return append(dataColumnsByRangeRequest(0, 1, nil), make([]byte, 32)...)
		}, nil},
		{"data_columns_by_root.32", dataColsByRootV1, func(te runner.TestEnv) []byte {
			return append(wire.BuildSSZSnappy(make([]byte, 40)), make([]byte, 32)...)
		}, nil},
		{"goodbye.32", goodbyeV1, func(te runner.TestEnv) []byte {
			return append(wire.BuildSSZSnappy(wire.Uint64ToSSZ(1)), make([]byte, 32)...)
		}, normalizeGoodbye},
		{"metadata.32", metadataV2, func(te runner.TestEnv) []byte {
			// Metadata has no request body: any bytes are unsolicited.
			return make([]byte, 32)
		}, nil},
		{"ping.extra_snappy_chunk", pingV1, func(te runner.TestEnv) []byte {
			body := wire.BuildSSZSnappy(wire.Uint64ToSSZ(1))
			garbage := make([]byte, 16)
			te.RNG.Read(garbage)
			extra := wire.SnappyEncode(garbage)
			if len(extra) > 10 {
				body = append(body, extra[10:]...) // strip stream id: data chunk only
			}
			return body
		}, nil},
	}
	for _, tcase := range trailing {
		id := "reqresp.trailing_bytes." + tcase.label
		specs = append(specs, exchangeSpec(id, tcase.protocol, tcase.body, tcase.normalize))
	}

	// --- length bombs: enormous or lying length claims ---
	bombs := []struct {
		label    string
		protocol string
		body     func(te runner.TestEnv) []byte
	}{
		{"ping.varint_max_uint64", pingV1, func(te runner.TestEnv) []byte {
			return wire.BuildVarintPlusRawBytes(math.MaxUint64, wire.SnappyEncode(wire.Uint64ToSSZ(1)))
		}},
		{"status.varint_max_uint64", statusV2, func(te runner.TestEnv) []byte {
			return wire.BuildVarintPlusRawBytes(math.MaxUint64, wire.SnappyEncode(make([]byte, 92)))
		}},
		{"blocks_by_range.varint_max_uint64", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildVarintPlusRawBytes(math.MaxUint64, wire.SnappyEncode(make([]byte, 16)))
		}},
		{"ping.varint_max_payload_exact", pingV1, func(te runner.TestEnv) []byte {
			return wire.BuildVarintLengthMismatch(wire.Uint64ToSSZ(1), maxPayloadSize)
		}},
		{"ping.snappy_size_bomb", pingV1, func(te runner.TestEnv) []byte {
			return wire.BuildSnappySizeBomb(1024*1024*1024, wire.Uint64ToSSZ(1))
		}},
		{"blocks_by_range.snappy_size_bomb", blocksByRangeV2, func(te runner.TestEnv) []byte {
			return wire.BuildSnappySizeBomb(100*1024*1024, make([]byte, 16))
		}},
	}
	for _, b := range bombs {
		id := "reqresp.length_bomb." + b.label
		specs = append(specs, exchangeSpec(id, b.protocol, b.body, nil))
	}

	return specs
}

// normalizeGoodbye maps any reject variant to accept: clients may disconnect
// on goodbye without answering, which is compliant.
func normalizeGoodbye(out string) string {
	if strings.HasPrefix(out, "reject") {
		return "accept"
	}
	return out
}
