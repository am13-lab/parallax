package ethmsg

import (
	"fmt"
	"reflect"
	"strings"

	bitfield "github.com/OffchainLabs/go-bitfield"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

// fieldpath.go — a generic reflective SSZ field-path setter plus per-topic typed
// base constructors. This turns "hand-write a builder per mutated field" into
// "declare a typed base per topic": the SMT synthesizer emits the solved field's
// dotted path (e.g. aggregate.data.index) and value, and BuildWithFieldOverride
// builds the valid typed message, sets that field by path, re-signs, and marshals.
//
// Scope: integer scalar leaves inside go-eth2-client typed structs. Containers
// go-eth2-client does not model (PartialDataColumnSidecar) keep hand-written
// builders. Fork variants that change the wire struct need their own base here.

// normalizeName lowercases and strips underscores so a spec SSZ field name
// (snake_case: "signed_block_header", "kzg_commitments") matches the corresponding
// go-eth2-client Go field name regardless of its irregular casing
// ("SignedBlockHeader", "KZGCommitments").
func normalizeName(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "_", ""))
}

func looseField(v reflect.Value, name string) reflect.Value {
	want := normalizeName(name)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if normalizeName(t.Field(i).Name) == want {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}

// setUintPath walks a dotted field path from root (a pointer to a struct) and sets
// the unsigned-integer leaf to value. Named integer types (phase0.Slot,
// phase0.CommitteeIndex, ...) are handled since their Kind is Uint64.
func setUintPath(root any, path string, value uint64) error {
	v := reflect.ValueOf(root)
	segs := strings.Split(path, ".")
	for _, seg := range segs {
		for v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return fmt.Errorf("nil pointer before segment %q", seg)
			}
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return fmt.Errorf("segment %q: parent is %s, not a struct", seg, v.Kind())
		}
		f := looseField(v, seg)
		if !f.IsValid() {
			return fmt.Errorf("field %q not found on %s", seg, v.Type())
		}
		v = f
	}
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return fmt.Errorf("nil leaf pointer for path %q", path)
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if !v.CanSet() {
			return fmt.Errorf("leaf %q is not settable", path)
		}
		v.SetUint(value)
		return nil
	default:
		return fmt.Errorf("leaf %q has kind %s, not an unsigned integer", path, v.Kind())
	}
}

// attestationDataRelPath returns the sub-path relative to AttestationData (the tail
// after the "data" segment). "aggregate.data.index" -> "index"; "data.index" ->
// "index"; "aggregate.data.target.epoch" -> "target.epoch".
func attestationDataRelPath(path string) (string, bool) {
	segs := strings.Split(path, ".")
	for i, s := range segs {
		if strings.EqualFold(s, "data") {
			return strings.Join(segs[i+1:], "."), true
		}
	}
	return "", false
}

// BuildWithFieldOverride builds a valid typed message for topic, sets the integer
// field at fieldPath to value, re-signs, and returns raw SSZ (gossip snappy is
// applied by the caller). Supported topics whose mutable region is AttestationData:
// beacon_attestation and beacon_aggregate_and_proof. The re-sign keeps every
// signature consistent with the mutated data, so a rejecting client is reacting to
// the targeted field, not a stale signature.
func BuildWithFieldOverride(sc SignContext, topic string, slot, value uint64, fieldPath string) ([]byte, error) {
	switch topic {
	case "beacon_attestation":
		rel, ok := attestationDataRelPath(fieldPath)
		if !ok {
			return nil, fmt.Errorf("beacon_attestation override path %q has no data.* segment", fieldPath)
		}
		data := sc.attestationData(slot, 0)
		if err := setUintPath(data, rel, value); err != nil {
			return nil, err
		}
		root, err := data.HashTreeRoot()
		if err != nil {
			return nil, fmt.Errorf("attestation data htr: %w", err)
		}
		sig, err := sc.sign(0, root, DomainBeaconAttester)
		if err != nil {
			return nil, fmt.Errorf("sign attestation: %w", err)
		}
		att := &electra.SingleAttestation{
			Data:      data,
			Signature: phase0.BLSSignature(mustSig96(sig)),
		}
		return att.MarshalSSZ()

	case "beacon_aggregate_and_proof":
		rel, ok := attestationDataRelPath(fieldPath)
		if !ok {
			return nil, fmt.Errorf("beacon_aggregate_and_proof override path %q has no data.* segment", fieldPath)
		}
		aggBits := bitfield.NewBitlist(64)
		aggBits.SetBitAt(0, true)
		committeeBits := bitfield.NewBitvector64()
		committeeBits.SetBitAt(0, true)
		return sc.signedAggregateAndProofWith(0, 0, slot, 0,
			func(d *phase0.AttestationData) { _ = setUintPath(d, rel, value) },
			aggBits, committeeBits, 0, 0, 0)

	default:
		return nil, fmt.Errorf("no typed-override base constructor for topic %q", topic)
	}
}
