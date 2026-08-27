package wire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"

	"github.com/golang/snappy"
)

func TestUint64ToSSZ(t *testing.T) {
	got := Uint64ToSSZ(0x0102030405060708)
	want := []byte{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01}
	if !bytes.Equal(got, want) {
		t.Fatalf("Uint64ToSSZ little-endian: got %x want %x", got, want)
	}
}

func TestVarintRoundTrip(t *testing.T) {
	for _, x := range []uint64{0, 1, 127, 128, 300, 16383, 16384, 1 << 32, ^uint64(0)} {
		enc := EncodeVarint(x)
		got, err := DecodeVarint(bytes.NewReader(enc))
		if err != nil {
			t.Fatalf("DecodeVarint(%d): %v", x, err)
		}
		if got != x {
			t.Fatalf("round trip: got %d want %d", got, x)
		}
	}
}

func TestDecodeVarintTooLong(t *testing.T) {
	ten := bytes.Repeat([]byte{0x80}, 10)
	_, err := DecodeVarint(bytes.NewReader(ten))
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("want too-long error, got %v", err)
	}
}

func TestDecodeVarintEOF(t *testing.T) {
	_, err := DecodeVarint(bytes.NewReader([]byte{0x80}))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("want wrapped EOF, got %v", err)
	}
}

func TestCRC32cKnownVector(t *testing.T) {
	// Castagnoli check value for "123456789" is 0xE3069283.
	if got := CRC32c([]byte("123456789")); got != 0xE3069283 {
		t.Fatalf("CRC32c check value: got %#x", got)
	}
	if CRC32c(nil) != 0 {
		t.Fatal("CRC32c of empty must be 0")
	}
}

func TestSnappyFramingRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, size := range []int{0, 1, 100, 65536, 65537, 200000} {
		data := make([]byte, size)
		rng.Read(data)
		framed := SnappyEncode(data)
		// golang/snappy is the independent implementation: it validates
		// stream id, chunk headers and CRCs, so this is a real cross-check.
		got, err := io.ReadAll(snappy.NewReader(bytes.NewReader(framed)))
		if err != nil {
			t.Fatalf("size %d: independent decode failed: %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: round trip mismatch (%d vs %d bytes)", size, len(got), len(data))
		}
		if size == 0 {
			// Our encoder always emits the stream ID, even for empty input.
			if len(framed) != 10 {
				t.Fatalf("empty input: want 10-byte stream id, got %d bytes", len(framed))
			}
		}
	}
}

func TestSSZSnappyRoundTrip(t *testing.T) {
	payload := []byte("hello ssz world")
	frame := BuildSSZSnappy(payload)

	got, err := ParseReqRespRequest(frame)
	if err != nil {
		t.Fatalf("ParseReqRespRequest: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip: got %q want %q", got, payload)
	}
}

func TestBuildSSZSnappyLayout(t *testing.T) {
	payload := []byte("abc")
	frame := BuildSSZSnappy(payload)
	if frame[0] != 3 { // varint(3)
		t.Fatalf("first byte must be varint length 3, got %d", frame[0])
	}
	if !bytes.Equal(frame[1:11], []byte{0xff, 0x06, 0x00, 0x00, 0x73, 0x4e, 0x61, 0x50, 0x70, 0x59}) {
		t.Fatalf("snappy stream id missing: %x", frame[1:11])
	}
}

func TestParseReqRespRequestRejectsLengthMismatch(t *testing.T) {
	frame := BuildVarintLengthMismatch([]byte("hello"), 999)
	_, err := ParseReqRespRequest(frame)
	if err == nil {
		t.Fatal("claimed length 999 with 5-byte body must error")
	}
}

func TestParseReqRespRequestEmptyBody(t *testing.T) {
	frame := BuildSSZSnappy(nil)
	got, err := ParseReqRespRequest(frame)
	if err != nil {
		t.Fatalf("empty body must parse: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty body round trip: got %x", got)
	}
}

func TestGossipSnappyEncodeIsRawBlock(t *testing.T) {
	payload := []byte("gossip data")
	enc := GossipSnappyEncode(payload)
	if bytes.Contains(enc, []byte("sNaPpY")) {
		t.Fatal("gossip encoding must be a raw snappy block, not framing")
	}
	dec, err := snappy.Decode(nil, enc)
	if err != nil || !bytes.Equal(dec, payload) {
		t.Fatalf("raw block round trip failed: %v", err)
	}
}

func TestParseResponseChunksSuccess(t *testing.T) {
	p1 := []byte{0xaa, 0xbb}
	p2 := []byte{0xcc}
	ctxB := []byte{1, 2, 3, 4}
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	buf.Write(ctxB)
	buf.Write(BuildSSZSnappy(p1))
	buf.WriteByte(0x00)
	buf.Write(ctxB)
	buf.Write(BuildSSZSnappy(p2))

	chunks := ParseReqRespResponse(buf.Bytes())
	if len(chunks) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(chunks))
	}
	if chunks[0].ResultCode != 0 || !bytes.Equal(chunks[0].Context, ctxB) || !bytes.Equal(chunks[0].Payload, p1) {
		t.Fatalf("chunk 0 mismatch: %+v", chunks[0])
	}
	if chunks[0].Malformed {
		t.Fatal("chunk 0 must not be malformed")
	}
	if !bytes.Equal(chunks[1].Payload, p2) {
		t.Fatalf("chunk 1 payload mismatch: %x", chunks[1].Payload)
	}
}

func TestParseResponseChunksErrorChunk(t *testing.T) {
	msg := "Invalid request"
	var buf bytes.Buffer
	buf.WriteByte(0x01)
	buf.WriteString(msg)

	chunks := ParseReqRespResponse(buf.Bytes())
	if len(chunks) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(chunks))
	}
	if chunks[0].ResultCode != 0x01 {
		t.Fatalf("result code: got %d", chunks[0].ResultCode)
	}
	if string(chunks[0].Payload) != msg {
		t.Fatalf("error message: got %q", chunks[0].Payload)
	}
}

func TestParseResponseChunksV1NoContext(t *testing.T) {
	p := []byte{0x01, 0x02}
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	buf.Write(BuildSSZSnappy(p))

	chunks := ParseReqRespResponseV1(buf.Bytes())
	if len(chunks) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(chunks))
	}
	if chunks[0].Context != nil {
		t.Fatalf("V1 chunk must have nil context, got %x", chunks[0].Context)
	}
	if !bytes.Equal(chunks[0].Payload, p) {
		t.Fatalf("payload mismatch: %x", chunks[0].Payload)
	}
}

func TestParseResponseChunksV2AgainstV1Fails(t *testing.T) {
	// A V1-framed chunk parsed as V2 must be flagged malformed: the first
	// 4 payload bytes are consumed as context and the varint lands wrong.
	p := Uint64ToSSZ(8)
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	buf.Write(BuildSSZSnappy(p))

	chunks := ParseReqRespResponse(buf.Bytes())
	if len(chunks) != 1 || !chunks[0].Malformed {
		t.Fatalf("V1 body parsed as V2 must be malformed, got %+v", chunks)
	}
}

func TestParseResponseTruncated(t *testing.T) {
	full := BuildSSZSnappy([]byte("payload"))
	truncated := full[:len(full)-3]
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	buf.Write(make([]byte, 4)) // context
	buf.Write(truncated)

	chunks := ParseReqRespResponse(buf.Bytes())
	if len(chunks) == 0 || !chunks[0].Malformed {
		t.Fatalf("truncated frame must be malformed, got %+v", chunks)
	}
}

func TestBuildSnappySizeBomb(t *testing.T) {
	actual := []byte{0xde, 0xad}
	frame := BuildSnappySizeBomb(1<<30, actual)
	// The harness decoder rejects lying frames; bombs exist to attack
	// targets, whose allocation behavior is what the differential tests
	// observe remotely.
	if _, err := ParseReqRespRequest(frame); err == nil {
		t.Fatal("harness decoder must reject a frame claiming 1GiB with 2 bytes")
	}
	if len(frame) > 64 {
		t.Fatalf("bomb frame must stay tiny, got %d bytes", len(frame))
	}
}

func TestBuildRawVarintOnlyAndPlusRaw(t *testing.T) {
	if !bytes.Equal(BuildRawVarintOnly(0x0400), []byte{0x80, 0x08}) {
		t.Fatalf("raw varint: %x", BuildRawVarintOnly(0x0400))
	}
	got := BuildVarintPlusRawBytes(5, []byte{0xff, 0xee})
	want := append(EncodeVarint(5), 0xff, 0xee)
	if !bytes.Equal(got, want) {
		t.Fatalf("varint+raw: got %x want %x", got, want)
	}
}

func TestComputeForkDigestLayout(t *testing.T) {
	// hash_tree_root(ForkData(current_version, genesis_validators_root))[:4]
	// with version zero-padded to 32 bytes, then the root.
	var version [4]byte = [4]byte{0x04, 0x00, 0x00, 0x00}
	var root [32]byte
	for i := range root {
		root[i] = byte(i)
	}
	var data [64]byte
	copy(data[0:4], version[:])
	copy(data[32:64], root[:])
	want := sha256.Sum256(data[:])

	got := ComputeForkDigest(version, root)
	if !bytes.Equal(got[:], want[:4]) {
		t.Fatalf("fork digest: got %x want %x", got[:4], want[:4])
	}
}

func TestBuildMalformedSSZSnappy(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	payload := make([]byte, 64)
	rng.Read(payload)

	t.Run("truncate_one", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformTruncateOne, rng)
		got, err := ParseReqRespRequest(frame)
		if err != nil || len(got) != len(payload)-1 {
			t.Fatalf("truncate one: len=%d err=%v", len(got), err)
		}
	})
	t.Run("truncate_half", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformTruncateHalf, rng)
		got, err := ParseReqRespRequest(frame)
		if err != nil || len(got) != len(payload)/2 {
			t.Fatalf("truncate half: len=%d err=%v", len(got), err)
		}
	})
	t.Run("truncate_all", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformTruncateAll, rng)
		got, err := ParseReqRespRequest(frame)
		if err != nil || len(got) != 0 {
			t.Fatalf("truncate all: len=%d err=%v", len(got), err)
		}
	})
	t.Run("random_bytes", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformRandomBytes, rng)
		got, err := ParseReqRespRequest(frame)
		if err != nil || len(got) != len(payload) || bytes.Equal(got, payload) {
			t.Fatalf("random bytes: len=%d err=%v", len(got), err)
		}
	})
	t.Run("break_stream_id", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformBreakSnappyStreamID, rng)
		_, err := ParseReqRespRequest(frame)
		if err == nil {
			t.Fatal("broken stream id must fail to decode")
		}
	})
	t.Run("break_crc", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformBreakSnappyCRC, rng)
		_, err := ParseReqRespRequest(frame)
		if err == nil {
			t.Fatal("broken CRC must fail to decode")
		}
	})
	t.Run("append_garbage", func(t *testing.T) {
		frame := BuildMalformedSSZSnappy(payload, MalformAppendGarbage, rng)
		// The valid prefix decodes fine; extra trailing bytes are ignored by
		// this reader (clients vary, which is exactly what the tests probe).
		got, err := ParseReqRespRequest(frame)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("append garbage: err=%v", err)
		}
		if len(frame) <= len(BuildSSZSnappy(payload)) {
			t.Fatal("append garbage frame must be larger than the valid frame")
		}
	})
}

// TestReadFrameStreamingAndLimits covers the streaming reader used by both
// the probe and the testnode.
func TestReadFrameStreamingAndLimits(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, 1000)
	frame := BuildSSZSnappy(payload)

	got, err := ReadFrame(bytes.NewReader(frame), 4096)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	decoded, err := SnappyDecode(got)
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("streamed frame decode failed: %v", err)
	}

	_, err = ReadFrame(bytes.NewReader(frame), 10)
	if err == nil {
		t.Fatal("frame exceeding maxLen must be rejected")
	}

	_, err = ReadFrame(bytes.NewReader(nil), 4096)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("empty stream must yield EOF, got %v", err)
	}
}

// TestParseReqRespRequestIsFramingOnly pins that ParseReqRespRequest validates
// framing (varint + snappy) but does not enforce varint/snappy consistency
// beyond what snappy itself checks.
func TestParseReqRespRequestIsFramingOnly(t *testing.T) {
	// Valid frame whose snappy content is arbitrary garbage bytes.
	garbage := bytes.Repeat([]byte{0x5a}, 32)
	frame := BuildSSZSnappy(garbage)
	got, err := ParseReqRespRequest(frame)
	if err != nil || !bytes.Equal(got, garbage) {
		t.Fatalf("arbitrary body bytes must decode: err=%v", err)
	}
}
