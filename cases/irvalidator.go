package cases

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"time"

	"parallax/enr"
	"parallax/wire"
)

// irvalidator.go — response-order validation and custody column selection,
// ported from p2p-testing's executor.go (validateBlockOrdering,
// validateDataColumnOrdering, parseDataColumnSidecarSlotCol) and
// peerscoring_custody.go (GetCustodyGroups, ComputeColumnsForCustodyGroup).

const (
	irNumberOfColumns        = 128
	irNumberOfCustodyGroups  = 128
	irCustodyGroupWraparound = "115792089237316195423570985008687907853269984665640564039457584007913129639935" // 2^256 - 1
)

// Verdict classes for the order-check family.
const (
	irOrderCorrect            = "order_ok"
	irOrderMismatch           = "order_mismatch"
	irOrderAllOrNoneViolation = "all_or_none_violation"
	irOrderMalformedChunk     = "malformed_chunk"
)

var irUint256Max = func() *big.Int {
	v, _ := new(big.Int).SetString(irCustodyGroupWraparound, 10)
	return v
}()

// irValidateResponseOrder validates chunk ordering for a range response and
// returns a comparable verdict class.
func irValidateResponseOrder(protocol string, raw []byte, allOrNone bool) string {
	chunks := wire.ParseReqRespResponse(raw)
	for _, chunk := range chunks {
		if chunk.Malformed {
			return irOrderMalformedChunk
		}
	}
	if len(chunks) < 2 {
		return irOrderCorrect
	}
	switch protocol {
	case "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy",
		"/eth2/beacon_chain/req/beacon_blocks_by_range/1/ssz_snappy":
		return irValidateBlockOrdering(chunks)
	case "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy":
		return irValidateDataColumnOrdering(chunks, allOrNone)
	default:
		return irOrderCorrect
	}
}

func irValidateBlockOrdering(chunks []wire.ResponseChunk) string {
	var prevSlot uint64
	first := true
	for _, chunk := range chunks {
		if chunk.ResultCode != 0x00 || len(chunk.Payload) < 8 {
			if chunk.ResultCode == 0x00 {
				return irOrderMalformedChunk
			}
			continue
		}
		slot := binary.LittleEndian.Uint64(chunk.Payload[:8])
		if !first && slot <= prevSlot {
			return irOrderMismatch
		}
		prevSlot = slot
		first = false
	}
	return irOrderCorrect
}

func irValidateDataColumnOrdering(chunks []wire.ResponseChunk, checkAllOrNone bool) string {
	type slotCol struct {
		slot uint64
		col  uint64
	}
	var prev slotCol
	first := true
	slotColumns := make(map[uint64]int)

	for _, chunk := range chunks {
		if chunk.ResultCode != 0x00 {
			continue
		}
		slot, colIdx, ok := irParseDataColumnSidecarSlotCol(chunk.Payload)
		if !ok {
			return irOrderMalformedChunk
		}
		sc := slotCol{slot, colIdx}
		if !first {
			if sc.slot < prev.slot || (sc.slot == prev.slot && sc.col <= prev.col) {
				return irOrderMismatch
			}
		}
		prev = sc
		first = false
		slotColumns[slot]++
	}
	if checkAllOrNone && len(slotColumns) > 0 {
		var expected int
		for _, count := range slotColumns {
			if expected == 0 {
				expected = count
			} else if count != expected {
				return irOrderAllOrNoneViolation
			}
		}
	}
	return irOrderCorrect
}

// irParseDataColumnSidecarSlotCol extracts (slot, column_index) from a
// DataColumnSidecar SSZ payload, handling Fulu and Gloas layouts.
func irParseDataColumnSidecarSlotCol(payload []byte) (uint64, uint64, bool) {
	if len(payload) < 8 {
		return 0, 0, false
	}
	colIdx := binary.LittleEndian.Uint64(payload[0:8])
	if len(payload) >= 28 && irDataColumnFuluOffsetsValid(payload) {
		return binary.LittleEndian.Uint64(payload[20:28]), colIdx, true
	}
	if len(payload) >= 24 && irDataColumnGloasOffsetsValid(payload) {
		return binary.LittleEndian.Uint64(payload[16:24]), colIdx, true
	}
	return 0, 0, false
}

func irDataColumnFuluOffsetsValid(payload []byte) bool {
	const fixedSize = 356
	if len(payload) < fixedSize {
		return false
	}
	columnOffset := binary.LittleEndian.Uint32(payload[8:12])
	commitmentsOffset := binary.LittleEndian.Uint32(payload[12:16])
	proofsOffset := binary.LittleEndian.Uint32(payload[16:20])
	total := uint32(len(payload))
	return columnOffset >= fixedSize &&
		columnOffset <= commitmentsOffset &&
		commitmentsOffset <= proofsOffset &&
		proofsOffset <= total
}

func irDataColumnGloasOffsetsValid(payload []byte) bool {
	const fixedSize = 56
	if len(payload) < fixedSize {
		return false
	}
	columnOffset := binary.LittleEndian.Uint32(payload[8:12])
	proofsOffset := binary.LittleEndian.Uint32(payload[12:16])
	total := uint32(len(payload))
	return columnOffset >= fixedSize && columnOffset <= proofsOffset && proofsOffset <= total
}

// --- custody column selection ---

// irGetCustodyGroups computes the custody groups for a node ID (PeerDAS
// sampling rule with uint256 wraparound).
func irGetCustodyGroups(nodeID []byte, custodyGroupCount uint64) []uint64 {
	if custodyGroupCount >= irNumberOfCustodyGroups {
		groups := make([]uint64, irNumberOfCustodyGroups)
		for i := range groups {
			groups[i] = uint64(i)
		}
		return groups
	}
	currentID := new(big.Int).SetBytes(nodeID)
	seen := make(map[uint64]bool)
	var groups []uint64
	for uint64(len(groups)) < custodyGroupCount {
		var buf [32]byte
		b := currentID.Bytes()
		copy(buf[32-len(b):], b)
		h := sha256.Sum256(buf[:])
		custodyGroup := binary.LittleEndian.Uint64(h[0:8]) % irNumberOfCustodyGroups
		if !seen[custodyGroup] {
			seen[custodyGroup] = true
			groups = append(groups, custodyGroup)
		}
		if irUint256Max != nil && currentID.Cmp(irUint256Max) == 0 {
			currentID.SetUint64(0)
		} else {
			currentID.Add(currentID, big.NewInt(1))
		}
	}
	return groups
}

// irComputeColumnsForCustodyGroup maps a custody group to its column indices.
func irComputeColumnsForCustodyGroup(custodyGroup uint64) []uint64 {
	columnsPerGroup := irNumberOfColumns / irNumberOfCustodyGroups
	columns := make([]uint64, columnsPerGroup)
	for i := uint64(0); i < uint64(columnsPerGroup); i++ {
		columns[i] = uint64(irNumberOfCustodyGroups)*i + custodyGroup
	}
	return columns
}

// irCustodyColumns returns all column indices a node custodies.
func irCustodyColumns(nodeID []byte, custodyGroupCount uint64) []uint64 {
	var all []uint64
	for _, g := range irGetCustodyGroups(nodeID, custodyGroupCount) {
		all = append(all, irComputeColumnsForCustodyGroup(g)...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return all
}

// irNonCustodyColumns returns column indices outside the node's custody set.
func irNonCustodyColumns(nodeID []byte, custodyGroupCount uint64) []uint64 {
	custodySet := make(map[uint64]bool)
	for _, c := range irCustodyColumns(nodeID, custodyGroupCount) {
		custodySet[c] = true
	}
	var out []uint64
	for i := uint64(0); i < irNumberOfColumns; i++ {
		if !custodySet[i] {
			out = append(out, i)
		}
	}
	return out
}

// irPeerCustodyColumns resolves the peer's ENR (via the Beacon API identity
// endpoint), computes its node ID and custody group count, and returns the
// custody or non-custody column selection.
func irPeerCustodyColumns(beaconAPI string, nonCustody bool) ([]uint64, error) {
	if beaconAPI == "" {
		return nil, fmt.Errorf("no beacon API")
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(beaconAPI + "/eth/v1/node/identity")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("identity endpoint %d", resp.StatusCode)
	}
	var body struct {
		Data struct {
			ENR string `json:"enr"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	rec, err := enr.DecodeENR(body.Data.ENR)
	if err != nil {
		return nil, err
	}
	pubkey := rec.GetSecp256k1()
	if pubkey == nil {
		return nil, fmt.Errorf("ENR missing secp256k1 key")
	}
	nodeID, err := enr.NodeIDFromSecp256k1(pubkey)
	if err != nil {
		return nil, err
	}
	cgc := uint64(4) // CUSTODY_REQUIREMENT fallback
	if v, _, has := rec.GetCGC(); has && v > 0 {
		cgc = v
	}
	if nonCustody {
		return irNonCustodyColumns(nodeID, cgc), nil
	}
	return irCustodyColumns(nodeID, cgc), nil
}
