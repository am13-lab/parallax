package cases

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"

	"parallax/ethmsg"
	"parallax/wire"
)

// irbuilders.go — payload builders ported from p2p-testing's
// internal/statemachine for the smgen-generated cases (spec_generated.go).
// They operate on irContext, the minimal SeqContext equivalent, and emit
// byte-identical payloads. The cryptomsg signed-message builders (ethmsg
// backed) are not ported yet.

const maxRequestBlocksDeneb = 128

const slotsPerEpoch = 32

const epochsPerSyncCommitteePeriod = 256

// irContext is the minimal execution context shared by the generated cases:
// chain facts, gossip topic selection state, guard counters, and payload cache.
type irContext struct {
	Rng        *rand.Rand
	ForkDigest [4]byte
	Fork       string

	FinalizedRoot  [32]byte
	FinalizedEpoch uint64
	HeadRoot       [32]byte
	HeadSlot       uint64

	// Live-builder support (populated per client with a Beacon API).
	LiveBuilder             *LiveBuilderContext
	SetupInapplicableReason string
	GossipTopicOverride     string

	// Signing facts for the cryptomsg builders (populated from client state).
	Keys                  *ethmsg.Keystore
	ForkVersion           [4]byte
	GenesisForkVersion    [4]byte
	GenesisValidatorsRoot [32]byte
	CurrentEpoch          uint64

	OpenStreams             map[string]struct{}
	StepResults             int
	LastResultCode          byte
	MessagesSent            int
	RejectionCount          int
	ConnectionCount         int
	GossipViolationCount    int
	ReqRespFailureCount     int
	CustodyColumnsRequested int
	CustodyColumnsFailed    int
	NonCustodyRequested     int
	ReconnectAttempts       int
	DecayWaitCount          int
	DiscENRQueryCount       int
	DiscPeerListCount       int
	StatusDone              bool
	GeneringMode            bool
	DiscWeInPeerList        bool
	DiscNFDMismatchSent     bool

	CurrentTopic             string
	PayloadCache             map[string][]byte
	SubnetPhase              string
	DiscENRSnapshot          []byte // non-nil when an ENR snapshot was captured
	SubnetCustodySubnets     []uint64
	SubnetNonCustodySubnets  []uint64
	SubnetSubscribedAttn     []int
	SubnetSubscribedSync     []int
	SubnetUnsubscribedAttn   []int
	SubnetUnsubscribedSync   []int
	SubnetCustodyInjected    int
	SubnetNonCustodyInjected int
	SubnetBoundaryInjected   int
}

func (c *irContext) LoadPayload(key string) ([]byte, bool) {
	p, ok := c.PayloadCache[key]
	return p, ok
}

func (c *irContext) StorePayload(key string, payload []byte) {
	if c.PayloadCache == nil {
		c.PayloadCache = map[string][]byte{}
	}
	c.PayloadCache[key] = payload
}

func (c *irContext) HasVisitedTransition(label string) bool { return false }

// MarkSetupInapplicable records why a live payload could not be built; the
// step then yields an "inapplicable" verdict instead of a broken send.
func (c *irContext) MarkSetupInapplicable(reason string) {
	if c.SetupInapplicableReason == "" {
		c.SetupInapplicableReason = reason
	}
}

// SetGossipTopicOverride pins the gossip topic for subsequent steps.
func (c *irContext) SetGossipTopicOverride(topic string) { c.GossipTopicOverride = topic }

// syncCommitteePeriod computes the sync committee period for an epoch.
func syncCommitteePeriod(epoch uint64) uint64 {
	return epoch / epochsPerSyncCommitteePeriod
}

// deriveSyncPeriod computes the current sync committee period from chain state.
// Falls back to period 1 when no state is available.
func deriveSyncPeriod(ctx *irContext) uint64 {
	if ctx.FinalizedEpoch > 0 {
		return syncCommitteePeriod(ctx.FinalizedEpoch)
	}
	if ctx.HeadSlot > 0 {
		epoch := ctx.HeadSlot / slotsPerEpoch
		return syncCommitteePeriod(epoch)
	}
	return 1
}

// buildStatusV2SSZ constructs the 92-byte Status V2 (Fulu) SSZ payload.
func buildStatusV2SSZ(ctx *irContext) []byte {
	ssz := make([]byte, 92)
	copy(ssz[0:4], ctx.ForkDigest[:])
	copy(ssz[4:36], ctx.FinalizedRoot[:])
	binary.LittleEndian.PutUint64(ssz[36:44], ctx.FinalizedEpoch)
	copy(ssz[44:76], ctx.HeadRoot[:])
	binary.LittleEndian.PutUint64(ssz[76:84], ctx.HeadSlot)
	binary.LittleEndian.PutUint64(ssz[84:92], 0) // earliest_available_slot = 0
	return ssz
}

// buildPingStreamCountSSZ returns a Ping body whose value tracks the number of
// currently-open streams + 1.
func buildPingStreamCountSSZ(ctx *irContext) []byte {
	return uint64ToSSZ(uint64(len(ctx.OpenStreams) + 1))
}

// buildStatusV2ForkFlipped returns a Status V2 body with the fork digest
// overwritten by 0xDEADBEEF (a deliberately wrong fork digest).
func buildStatusV2ForkFlipped(ctx *irContext) []byte {
	ssz := buildStatusV2SSZ(ctx)
	ssz[0] = 0xDE
	ssz[1] = 0xAD
	ssz[2] = 0xBE
	ssz[3] = 0xEF
	return ssz
}

// buildStatusV2WrongNFD returns a Status V2 body with a correct fork digest but
// a finalized root set to all-0xFF and a bogus finalized epoch (999999).
func buildStatusV2WrongNFD(ctx *irContext) []byte {
	ssz := buildStatusV2SSZ(ctx)
	for i := 4; i < 36; i++ {
		ssz[i] = 0xFF
	}
	binary.LittleEndian.PutUint64(ssz[36:44], 999999)
	return ssz
}

func buildRandomGossip50(ctx *irContext) []byte {
	g := make([]byte, 50)
	ctx.Rng.Read(g)
	return g
}

func buildRandomGossip100(ctx *irContext) []byte {
	g := make([]byte, 100)
	ctx.Rng.Read(g)
	return g
}

func buildRandomGossip200(ctx *irContext) []byte {
	g := make([]byte, 200)
	ctx.Rng.Read(g)
	return g
}

func buildRandomGossip300(ctx *irContext) []byte {
	g := make([]byte, 300)
	ctx.Rng.Read(g)
	return g
}

// buildBlocksByRangeNearHead returns a BeaconBlocksByRange body requesting one
// block ~2 slots behind head.
func buildBlocksByRangeNearHead(ctx *irContext) []byte {
	buf := make([]byte, 16)
	slot := ctx.HeadSlot
	if slot > 2 {
		slot -= 2
	}
	binary.LittleEndian.PutUint64(buf[0:8], slot)
	buf[8] = 1 // count = 1
	return buf
}

// buildBeaconBlocksByRangeV2NearHead returns BeaconBlocksByRange v2
// {start_slot,count,step} with step=1.
func buildBeaconBlocksByRangeV2NearHead(ctx *irContext) []byte {
	buf := make([]byte, 24)
	slot := ctx.HeadSlot
	if slot > 2 {
		slot -= 2
	}
	binary.LittleEndian.PutUint64(buf[0:8], slot)
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	binary.LittleEndian.PutUint64(buf[16:24], 1)
	return buf
}

func buildBlock200Slot1(_ *irContext) []byte {
	ssz := make([]byte, 200)
	ssz[0] = 1
	return ssz
}

func buildBlockSlotPlusOne(ctx *irContext) []byte {
	ssz := make([]byte, 200)
	binary.LittleEndian.PutUint64(ssz[0:8], ctx.HeadSlot+1)
	return ssz
}

func buildBlockSlotPlusTwo(ctx *irContext) []byte {
	ssz := make([]byte, 200)
	binary.LittleEndian.PutUint64(ssz[0:8], ctx.HeadSlot+2)
	return ssz
}

// buildBlobIdentifierHeadRoot returns a single BlobIdentifier (block_root=head
// root, index=0), 40 bytes.
func buildBlobIdentifierHeadRoot(ctx *irContext) []byte {
	buf := make([]byte, 40)
	copy(buf[0:32], ctx.HeadRoot[:])
	return buf
}

// buildLCUpdatesByRange1SSZ returns a LightClientUpdatesByRange body with
// start_period = current sync period and count = 1.
func buildLCUpdatesByRange1SSZ(ctx *irContext) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], deriveSyncPeriod(ctx))
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	return buf
}

// buildLCAdditionalUpdatesSSZ returns a LightClientUpdatesByRange body with
// start_period = prior sync period and count = 2.
func buildLCAdditionalUpdatesSSZ(ctx *irContext) []byte {
	startPeriod := deriveSyncPeriod(ctx)
	if startPeriod > 0 {
		startPeriod--
	}
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], startPeriod)
	binary.LittleEndian.PutUint64(buf[8:16], 2)
	return buf
}

// buildPingHalfOpen returns the first half of a snappy-framed Ping body.
func buildPingHalfOpen(_ *irContext) []byte {
	body := wire.BuildSSZSnappy(uint64ToSSZ(1))
	return body[:len(body)/2]
}

// buildBlocksByRangeHalfOpen returns the first half of a snappy-framed
// BeaconBlocksByRange{0,1} body.
func buildBlocksByRangeHalfOpen(_ *irContext) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], 0)
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	body := wire.BuildSSZSnappy(buf)
	return body[:len(body)/2]
}

// buildBlocksByRangeOrdering returns a BeaconBlocksByRange body requesting 5
// blocks starting ~10 slots behind head (for response-ordering validation).
func buildBlocksByRangeOrdering(ctx *irContext) []byte {
	buf := make([]byte, 24)
	slot := ctx.HeadSlot
	if slot > 10 {
		slot -= 10
	}
	binary.LittleEndian.PutUint64(buf[0:8], slot)
	binary.LittleEndian.PutUint64(buf[8:16], 5)
	binary.LittleEndian.PutUint64(buf[16:24], 1) // step (deprecated, must be 1)
	return buf
}

// buildDataColumnsOrdering returns a DataColumnsByRange request for columns
// {0,1,2} over 3 slots starting ~5 slots behind head.
func buildDataColumnsOrdering(ctx *irContext) []byte {
	slot := ctx.HeadSlot
	if slot > 5 {
		slot -= 5
	}
	return buildDataColumnsByRangeRequest(slot, 3, []uint64{0, 1, 2})
}

// buildDataColumnsAllOrNone returns a DataColumnsByRange request for columns
// {0,1} over 2 slots starting ~3 slots behind head.
func buildDataColumnsAllOrNone(ctx *irContext) []byte {
	slot := ctx.HeadSlot
	if slot > 3 {
		slot -= 3
	}
	return buildDataColumnsByRangeRequest(slot, 2, []uint64{0, 1})
}

// buildDataColumns010 returns a DataColumnsByRange request for column 0 at
// slot 0, count 1.
func buildDataColumns010(_ *irContext) []byte {
	return buildDataColumnsByRangeRequest(0, 1, []uint64{0})
}

// buildBlocksByRangeV1Probe returns a deprecated V1 BeaconBlocksByRange body
// (start_slot=0, count=1, step=1; 24 bytes).
func buildBlocksByRangeV1Probe(_ *irContext) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint64(buf[0:8], 0)
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	binary.LittleEndian.PutUint64(buf[16:24], 1)
	return buf
}

// buildDataColumns16NoColumns returns a bare 16-byte {start_slot,count} body
// (missing the columns list — a malformed DataColumnsByRange request).
func buildDataColumns16NoColumns(_ *irContext) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], 0)
	binary.LittleEndian.PutUint64(buf[8:16], 1)
	return buf
}

// buildRootListHeadRoot returns a single-element SSZ List[Root] containing the
// head root (32 bytes).
func buildRootListHeadRoot(ctx *irContext) []byte {
	root := make([]byte, 32)
	copy(root, ctx.HeadRoot[:])
	return root
}

// buildBlocksByHeadHeadRoot returns BeaconBlocksByHead{beacon_root=head_root,
// count=1}, a Fulu fixed-container request whose root is context-derived.
func buildBlocksByHeadHeadRoot(ctx *irContext) []byte {
	buf := make([]byte, 40)
	copy(buf[0:32], ctx.HeadRoot[:])
	binary.LittleEndian.PutUint64(buf[32:40], 1)
	return buf
}

// buildBlocksByRangeCountOverMax returns a BeaconBlocksByRange body with
// count = MAX_REQUEST_BLOCKS_DENEB + 1 (over the limit).
func buildBlocksByRangeCountOverMax(_ *irContext) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint64(buf[0:8], 0)
	binary.LittleEndian.PutUint64(buf[8:16], maxRequestBlocksDeneb+1)
	binary.LittleEndian.PutUint64(buf[16:24], 1) // step (deprecated, must be 1)
	return buf
}

// buildDataColumnSidecarInvalid returns a structurally valid DataColumnSidecar
// whose column fails deferred KZG validation.
func buildDataColumnSidecarInvalid(ctx *irContext) []byte {
	return buildDataColumnSidecarSSZ(ctx, 0, true)
}

// buildDataColumnSidecarValid returns a structurally valid DataColumnSidecar
// describing a zero cell (passes deferred validation).
func buildDataColumnSidecarValid(ctx *irContext) []byte {
	return buildDataColumnSidecarSSZ(ctx, 0, false)
}

// buildAttestationPrevEpoch returns a 228-byte attestation whose target epoch is
// the previous epoch (EIP-7045 acceptance boundary).
func buildAttestationPrevEpoch(ctx *irContext) []byte {
	currentEpoch := ctx.HeadSlot / slotsPerEpoch
	var targetEpoch uint64
	if currentEpoch > 0 {
		targetEpoch = currentEpoch - 1
	}
	return attestationBody(targetEpoch)
}

// buildAttestationTwoEpochsAgo returns a 228-byte attestation whose target epoch
// is two epochs ago (MUST reject under EIP-7045).
func buildAttestationTwoEpochsAgo(ctx *irContext) []byte {
	currentEpoch := ctx.HeadSlot / slotsPerEpoch
	var targetEpoch uint64
	if currentEpoch > 1 {
		targetEpoch = currentEpoch - 2
	}
	return attestationBody(targetEpoch)
}

func attestationBody(targetEpoch uint64) []byte {
	targetSlot := targetEpoch * slotsPerEpoch
	ssz := make([]byte, 228)
	ssz[0] = 228
	ssz[4] = byte(targetSlot)
	ssz[5] = byte(targetSlot >> 8)
	ssz[6] = byte(targetSlot >> 16)
	ssz[7] = byte(targetSlot >> 24)
	ssz[92] = byte(targetEpoch)
	ssz[93] = byte(targetEpoch >> 8)
	ssz[94] = byte(targetEpoch >> 16)
	ssz[95] = byte(targetEpoch >> 24)
	return ssz
}

// buildOrphanEnvelopeRandomRoot returns a ~1 KiB SignedExecutionPayloadEnvelope-
// shaped payload whose leading 32 bytes are a random beacon_block_root.
func buildOrphanEnvelopeRandomRoot(ctx *irContext) []byte {
	buf := make([]byte, 1024)
	ctx.Rng.Read(buf[:32])
	return buf
}

// buildFutureSlotBlockRandom returns a 200-byte block-like payload at a
// far-future slot with a random leading root.
func buildFutureSlotBlockRandom(ctx *irContext) []byte {
	buf := make([]byte, 200)
	binary.LittleEndian.PutUint64(buf[0:8], ctx.HeadSlot+1024)
	ctx.Rng.Read(buf[8:40])
	return buf
}

// --- Subnet injection builders ---
//
// These reproduce the subnet machine's gossip-injection closures. Besides
// returning 100 bytes of RNG noise, each sets ctx.CurrentTopic (the topic the
// generated case publishes on), ctx.SubnetPhase, and a phase counter — side
// effects that drive subsequent guards, so they are replicated faithfully.

func subRandom100(ctx *irContext) []byte {
	data := make([]byte, 100)
	ctx.Rng.Read(data)
	return data
}

func buildSubInjectCustodyDataColumn(ctx *irContext) []byte {
	if len(ctx.SubnetCustodySubnets) == 0 {
		ctx.CurrentTopic = "data_column_sidecar_0"
	} else {
		idx := ctx.SubnetCustodySubnets[ctx.Rng.Intn(len(ctx.SubnetCustodySubnets))]
		ctx.CurrentTopic = fmt.Sprintf("data_column_sidecar_%d", idx)
	}
	ctx.SubnetPhase = "custody"
	ctx.SubnetCustodyInjected++
	return subRandom100(ctx)
}

func buildSubInjectSubscribedAttestation(ctx *irContext) []byte {
	if len(ctx.SubnetSubscribedAttn) == 0 {
		ctx.CurrentTopic = "beacon_attestation_0"
	} else {
		idx := ctx.SubnetSubscribedAttn[ctx.Rng.Intn(len(ctx.SubnetSubscribedAttn))]
		ctx.CurrentTopic = fmt.Sprintf("beacon_attestation_%d", idx)
	}
	ctx.SubnetPhase = "custody"
	ctx.SubnetCustodyInjected++
	return subRandom100(ctx)
}

func buildSubInjectSubscribedSync(ctx *irContext) []byte {
	if len(ctx.SubnetSubscribedSync) == 0 {
		ctx.CurrentTopic = "sync_committee_0"
	} else {
		idx := ctx.SubnetSubscribedSync[ctx.Rng.Intn(len(ctx.SubnetSubscribedSync))]
		ctx.CurrentTopic = fmt.Sprintf("sync_committee_%d", idx)
	}
	ctx.SubnetPhase = "custody"
	ctx.SubnetCustodyInjected++
	return subRandom100(ctx)
}

func buildSubInjectNonCustodyDataColumn(ctx *irContext) []byte {
	if len(ctx.SubnetNonCustodySubnets) == 0 {
		ctx.CurrentTopic = "data_column_sidecar_0"
	} else {
		idx := ctx.SubnetNonCustodySubnets[ctx.Rng.Intn(len(ctx.SubnetNonCustodySubnets))]
		ctx.CurrentTopic = fmt.Sprintf("data_column_sidecar_%d", idx)
	}
	ctx.SubnetPhase = "non_custody"
	ctx.SubnetNonCustodyInjected++
	return subRandom100(ctx)
}

func buildSubInjectUnsubscribedAttestation(ctx *irContext) []byte {
	if len(ctx.SubnetUnsubscribedAttn) == 0 {
		ctx.CurrentTopic = "beacon_attestation_63"
	} else {
		idx := ctx.SubnetUnsubscribedAttn[ctx.Rng.Intn(len(ctx.SubnetUnsubscribedAttn))]
		ctx.CurrentTopic = fmt.Sprintf("beacon_attestation_%d", idx)
	}
	ctx.SubnetPhase = "non_custody"
	ctx.SubnetNonCustodyInjected++
	return subRandom100(ctx)
}

func buildSubInjectUnsubscribedSync(ctx *irContext) []byte {
	if len(ctx.SubnetUnsubscribedSync) == 0 {
		ctx.CurrentTopic = "sync_committee_3"
	} else {
		idx := ctx.SubnetUnsubscribedSync[ctx.Rng.Intn(len(ctx.SubnetUnsubscribedSync))]
		ctx.CurrentTopic = fmt.Sprintf("sync_committee_%d", idx)
	}
	ctx.SubnetPhase = "non_custody"
	ctx.SubnetNonCustodyInjected++
	return subRandom100(ctx)
}

func buildSubBoundaryOutOfRange(ctx *irContext) []byte {
	ctx.SubnetPhase = "out_of_range"
	ctx.SubnetBoundaryInjected++
	return subRandom100(ctx)
}

func buildSubBoundaryDeprecated(ctx *irContext) []byte {
	ctx.SubnetPhase = "deprecated"
	ctx.SubnetBoundaryInjected++
	return subRandom100(ctx)
}

func buildSubBoundaryCrossType(ctx *irContext) []byte {
	if len(ctx.SubnetCustodySubnets) == 0 {
		ctx.CurrentTopic = "data_column_sidecar_0"
	} else {
		idx := ctx.SubnetCustodySubnets[ctx.Rng.Intn(len(ctx.SubnetCustodySubnets))]
		ctx.CurrentTopic = fmt.Sprintf("data_column_sidecar_%d", idx)
	}
	ctx.SubnetPhase = "cross_type"
	ctx.SubnetBoundaryInjected++
	return subRandom100(ctx)
}

// buildDataColumnSidecarSSZ builds a simplified DataColumnSidecar SSZ payload
// (356-byte fixed part + one 2048-byte cell + commitment + proof).
func buildDataColumnSidecarSSZ(ctx *irContext, colIndex uint64, invalidKZG bool) []byte {
	const (
		fixedSize        = 356
		cellSize         = 2048
		kzgCommitSize    = 48
		kzgProofSize     = 48
		offsetColumn     = fixedSize
		offsetCommitment = offsetColumn + cellSize
		offsetProof      = offsetCommitment + kzgCommitSize
		totalSize        = offsetProof + kzgProofSize
	)

	ssz := make([]byte, totalSize)

	// index (ColumnIndex).
	binary.LittleEndian.PutUint64(ssz[0:8], colIndex)

	// Offsets to variable-length lists.
	binary.LittleEndian.PutUint32(ssz[8:12], uint32(offsetColumn))      // column
	binary.LittleEndian.PutUint32(ssz[12:16], uint32(offsetCommitment)) // kzg_commitments
	binary.LittleEndian.PutUint32(ssz[16:20], uint32(offsetProof))      // kzg_proofs

	// signed_block_header.message.slot
	binary.LittleEndian.PutUint64(ssz[20:28], ctx.HeadSlot)

	// signed_block_header.message.proposer_index = 1
	binary.LittleEndian.PutUint64(ssz[28:36], 1)
	copy(ssz[36:68], ctx.FinalizedRoot[:])
	copy(ssz[68:100], ctx.HeadRoot[:])

	commitment := kzgPointAtInfinity()
	proof := kzgPointAtInfinity()
	copy(ssz[offsetCommitment:offsetProof], commitment[:])
	copy(ssz[offsetProof:totalSize], proof[:])

	commitmentsRoot := hashTreeRootKZGCommitmentsList(commitment[:])
	bodyRoot, inclusionProof := buildKZGCommitmentsInclusionProof(commitmentsRoot)
	copy(ssz[100:132], bodyRoot[:])
	for i, proofNode := range inclusionProof {
		copy(ssz[228+i*32:228+(i+1)*32], proofNode[:])
	}

	if invalidKZG {
		ssz[offsetColumn+31] = 1
	}

	return ssz
}

func kzgPointAtInfinity() [48]byte {
	var point [48]byte
	point[0] = 0xc0
	return point
}

func hashTreeRootKZGCommitmentsList(commitments []byte) [32]byte {
	const (
		commitmentSize         = 48
		maxBlobCommitmentsLog2 = 12
	)

	commitmentCount := len(commitments) / commitmentSize
	leaves := make([][32]byte, 0, commitmentCount)
	for i := 0; i < commitmentCount; i++ {
		leaves = append(leaves, hashTreeRootBytes48(commitments[i*commitmentSize:(i+1)*commitmentSize]))
	}

	root := merkleizeWithLimit(leaves, maxBlobCommitmentsLog2)
	return mixInLength(root, uint64(commitmentCount))
}

func hashTreeRootBytes48(data []byte) [32]byte {
	var left, right [32]byte
	copy(left[:], data[:32])
	copy(right[:], data[32:])
	return hashPair(left, right)
}

func buildKZGCommitmentsInclusionProof(leaf [32]byte) ([32]byte, [4][32]byte) {
	const blobKZGCommitmentsSubtreeIndex = 11
	zeroHashes := zeroHashTree(4)
	var branch [4][32]byte
	copy(branch[:], zeroHashes[:4])

	root := leaf
	index := uint64(blobKZGCommitmentsSubtreeIndex)
	for depth := 0; depth < len(branch); depth++ {
		if index&1 == 1 {
			root = hashPair(branch[depth], root)
		} else {
			root = hashPair(root, branch[depth])
		}
		index >>= 1
	}
	return root, branch
}

func merkleizeWithLimit(leaves [][32]byte, limitDepth int) [32]byte {
	zeroHashes := zeroHashTree(limitDepth)
	if len(leaves) == 0 {
		return zeroHashes[limitDepth]
	}

	nodes := append([][32]byte(nil), leaves...)
	for depth := 0; depth < limitDepth; depth++ {
		next := make([][32]byte, (len(nodes)+1)/2)
		for i := range next {
			left := nodes[i*2]
			right := zeroHashes[depth]
			if i*2+1 < len(nodes) {
				right = nodes[i*2+1]
			}
			next[i] = hashPair(left, right)
		}
		nodes = next
	}
	return nodes[0]
}

func zeroHashTree(depth int) [][32]byte {
	hashes := make([][32]byte, depth+1)
	for i := 1; i <= depth; i++ {
		hashes[i] = hashPair(hashes[i-1], hashes[i-1])
	}
	return hashes
}

func hashPair(left, right [32]byte) [32]byte {
	var data [64]byte
	copy(data[:32], left[:])
	copy(data[32:], right[:])
	return sha256.Sum256(data[:])
}

func mixInLength(root [32]byte, length uint64) [32]byte {
	var lengthRoot [32]byte
	binary.LittleEndian.PutUint64(lengthRoot[:8], length)
	return hashPair(root, lengthRoot)
}

func uint64ToSSZ(v uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, v)
	return buf
}

// buildDataColumnsByRangeRequest builds a DataColumnsByRange request:
// {start_slot, count, offset} fixed part + variable columns list, framed.
func buildDataColumnsByRangeRequest(startSlot, count uint64, columns []uint64) []byte {
	// Fixed part: start_slot(8) + count(8) + offset(4) = 20 bytes
	// Variable part: columns list = len(columns) * 8 bytes
	fixedSize := 20
	varSize := len(columns) * 8
	ssz := make([]byte, fixedSize+varSize)

	binary.LittleEndian.PutUint64(ssz[0:8], startSlot)
	binary.LittleEndian.PutUint64(ssz[8:16], count)
	// Offset to variable-length columns list.
	binary.LittleEndian.PutUint32(ssz[16:20], uint32(fixedSize))

	for i, col := range columns {
		binary.LittleEndian.PutUint64(ssz[fixedSize+i*8:fixedSize+i*8+8], col)
	}

	return wire.BuildSSZSnappy(ssz)
}
