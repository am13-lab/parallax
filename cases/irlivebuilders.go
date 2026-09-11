package cases

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	"parallax/ethmsg"
	"parallax/wire"
)

const (
	defaultSlotsPerEpoch                 = uint64(32)
	defaultSecondsPerSlot                = uint64(12)
	defaultShardCommitteePeriod          = uint64(256)
	defaultTargetAggregatorsPerCommittee = uint64(16)
	defaultTargetAggregatorsPerSync      = uint64(16)
	defaultSyncCommitteeSize             = uint64(512)
	defaultSyncCommitteeSubnetCount      = uint64(4)
	defaultAttestationSubnetCount        = uint64(64)
	maxDevnetValidatorKeyScan            = uint64(8192)
)

type LiveBuilderContext struct {
	BeaconAPI    string
	HTTPClient   *http.Client
	PoolContains func(topic string, index uint64) (contains, observable bool)
}

// liveBeaconSource is the capability a client must expose for live builders:
// a Beacon API endpoint plus gossip-pool containment checks.
type liveBeaconSource interface {
	LiveBeaconAPI() string
	LivePoolContains(topic string, index uint64) (contains, observable bool)
}

func newLiveBuilderContext(lc liveBeaconSource) *LiveBuilderContext {
	if lc == nil || lc.LiveBeaconAPI() == "" {
		return nil
	}
	return &LiveBuilderContext{
		BeaconAPI:  strings.TrimRight(lc.LiveBeaconAPI(), "/"),
		HTTPClient: &http.Client{Timeout: 8 * time.Second},
		PoolContains: func(topic string, index uint64) (bool, bool) {
			return lc.LivePoolContains(topic, index)
		},
	}
}

func buildLiveValidSyncCommitteeMessage(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for sync committee message: " + err.Error())
		return nil
	}
	slot, secondsIntoSlot, clockOK := live.currentSlotInfo(ctx)
	if clockOK && secondsIntoSlot > live.firstSeenWindowSeconds() {
		ctx.MarkSetupInapplicable(fmt.Sprintf("sync committee first-seen window elapsed: %ds into slot %d", secondsIntoSlot, slot))
		return nil
	}
	live.setCurrentEpoch(ctx, slot)
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for sync committee message: " + err.Error())
		return nil
	}
	epoch := slot / live.specUint("SLOTS_PER_EPOCH", defaultSlotsPerEpoch)
	duties, err := live.syncDuties(epoch, validatorIndices(validators))
	if err != nil {
		ctx.MarkSetupInapplicable("cannot query sync duties: " + err.Error())
		return nil
	}
	for _, duty := range duties {
		if len(duty.SyncCommitteeIndices) == 0 || !validatorMatched(validators, duty.ValidatorIndex) {
			continue
		}
		subnet := syncCommitteeSubnet(duty.SyncCommitteeIndices[0], live)
		payload, err := ethmsg.BuildSyncCommitteeMessage(irSignCtx(ctx), duty.ValidatorIndex, slot)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign sync committee message: " + err.Error())
			return nil
		}
		ctx.SetGossipTopicOverride(fmt.Sprintf("sync_committee_%d", subnet))
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched devnet validator has a current sync committee duty")
	return nil
}

func buildLiveValidSyncCommitteeContributionAndProof(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for sync contribution: " + err.Error())
		return nil
	}
	slot, secondsIntoSlot, clockOK := live.currentSlotInfo(ctx)
	if clockOK && secondsIntoSlot > live.firstSeenWindowSeconds() {
		ctx.MarkSetupInapplicable(fmt.Sprintf("sync contribution first-seen window elapsed: %ds into slot %d", secondsIntoSlot, slot))
		return nil
	}
	live.setCurrentEpoch(ctx, slot)
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for sync contribution: " + err.Error())
		return nil
	}
	epoch := slot / live.specUint("SLOTS_PER_EPOCH", defaultSlotsPerEpoch)
	duties, err := live.syncDuties(epoch, validatorIndices(validators))
	if err != nil {
		ctx.MarkSetupInapplicable("cannot query sync duties: " + err.Error())
		return nil
	}
	for _, duty := range duties {
		if len(duty.SyncCommitteeIndices) == 0 || !validatorMatched(validators, duty.ValidatorIndex) {
			continue
		}
		for _, committeeIndex := range duty.SyncCommitteeIndices {
			subnet := syncCommitteeSubnet(committeeIndex, live)
			proof, err := ethmsg.SyncCommitteeSelectionProof(irSignCtx(ctx), duty.ValidatorIndex, slot, subnet)
			if err != nil {
				ctx.MarkSetupInapplicable("cannot sign sync contribution selection proof: " + err.Error())
				return nil
			}
			if !syncContributionProofChoosesAggregator(proof, live) {
				continue
			}
			bitIndex := syncCommitteeSubcommitteePosition(committeeIndex, live)
			payload, err := ethmsg.BuildSignedContributionAndProofWithBit(
				irSignCtx(ctx),
				duty.ValidatorIndex,
				duty.ValidatorIndex,
				slot,
				subnet,
				bitIndex,
			)
			if err != nil {
				ctx.MarkSetupInapplicable("cannot sign sync contribution and proof: " + err.Error())
				return nil
			}
			ctx.SetGossipTopicOverride("sync_committee_contribution_and_proof")
			return wire.GossipSnappyEncode(payload)
		}
	}
	ctx.MarkSetupInapplicable("no matched sync committee validator is selected as a contribution aggregator for the current slot")
	return nil
}

func buildLiveValidBeaconAggregateAndProof(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for aggregate and proof: " + err.Error())
		return nil
	}
	slot, secondsIntoSlot, clockOK := live.currentSlotInfo(ctx)
	if clockOK && secondsIntoSlot > live.firstSeenWindowSeconds() {
		ctx.MarkSetupInapplicable(fmt.Sprintf("aggregate first-seen window elapsed: %ds into slot %d", secondsIntoSlot, slot))
		return nil
	}
	live.setCurrentEpoch(ctx, slot)
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for aggregate and proof: " + err.Error())
		return nil
	}
	epoch := slot / live.specUint("SLOTS_PER_EPOCH", defaultSlotsPerEpoch)
	duties, err := live.attesterDuties(epoch, validatorIndices(validators))
	if err != nil {
		ctx.MarkSetupInapplicable("cannot query attester duties: " + err.Error())
		return nil
	}
	targetAggregators := live.specUint("TARGET_AGGREGATORS_PER_COMMITTEE", defaultTargetAggregatorsPerCommittee)
	for _, duty := range duties {
		if duty.Slot != slot || !validatorMatched(validators, duty.ValidatorIndex) {
			continue
		}
		proof, err := ethmsg.SelectionProof(irSignCtx(ctx), duty.ValidatorIndex, duty.Slot)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign aggregate selection proof: " + err.Error())
			return nil
		}
		if !selectionProofChoosesAggregator(proof, duty.CommitteeLength, targetAggregators) {
			continue
		}
		data, err := live.attestationData(duty.Slot, duty.CommitteeIndex)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot query attestation data: " + err.Error())
			return nil
		}
		payload, err := ethmsg.BuildSignedAggregateAndProofFromData(
			irSignCtx(ctx),
			duty.ValidatorIndex,
			duty.ValidatorIndex,
			data,
			duty.CommitteeIndex,
			duty.CommitteeLength,
			duty.ValidatorCommitteeIndex,
		)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign aggregate and proof: " + err.Error())
			return nil
		}
		ctx.SetGossipTopicOverride("beacon_aggregate_and_proof")
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched current-slot attester duty is selected as an aggregator")
	return nil
}

func buildLiveValidBeaconAttestation(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for beacon attestation: " + err.Error())
		return nil
	}
	slot, secondsIntoSlot, clockOK := live.currentSlotInfo(ctx)
	if clockOK && secondsIntoSlot > live.firstSeenWindowSeconds() {
		ctx.MarkSetupInapplicable(fmt.Sprintf("attestation first-seen window elapsed: %ds into slot %d", secondsIntoSlot, slot))
		return nil
	}
	live.setCurrentEpoch(ctx, slot)
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for beacon attestation: " + err.Error())
		return nil
	}
	epoch := slot / live.specUint("SLOTS_PER_EPOCH", defaultSlotsPerEpoch)
	duties, err := live.attesterDuties(epoch, validatorIndices(validators))
	if err != nil {
		ctx.MarkSetupInapplicable("cannot query attester duties: " + err.Error())
		return nil
	}
	committeesPerSlot, err := live.committeesPerSlot(slot)
	if err != nil {
		committeesPerSlot = committeesPerSlotFromDuties(duties, slot)
	}
	if committeesPerSlot == 0 {
		ctx.MarkSetupInapplicable("cannot determine committees per slot for beacon attestation")
		return nil
	}
	for _, duty := range duties {
		if duty.Slot != slot || !validatorMatched(validators, duty.ValidatorIndex) {
			continue
		}
		data, err := live.attestationData(duty.Slot, duty.CommitteeIndex)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot query attestation data: " + err.Error())
			return nil
		}
		payload, err := ethmsg.BuildSingleAttestationFromData(irSignCtx(ctx), duty.ValidatorIndex, data, duty.CommitteeIndex)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign beacon attestation: " + err.Error())
			return nil
		}
		subnet := attestationSubnet(committeesPerSlot, duty.Slot, duty.CommitteeIndex, live)
		ctx.SetGossipTopicOverride(fmt.Sprintf("beacon_attestation_%d", subnet))
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched devnet validator has a current-slot attester duty")
	return nil
}

func buildLiveValidVoluntaryExit(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for voluntary exit: " + err.Error())
		return nil
	}
	live.setCurrentEpoch(ctx, live.currentSlot(ctx))
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for voluntary exit: " + err.Error())
		return nil
	}
	period := live.specUint("SHARD_COMMITTEE_PERIOD", defaultShardCommitteePeriod)
	for _, v := range validators {
		if !v.voluntaryExitEligible(ctx.CurrentEpoch, period) {
			continue
		}
		if contains, observable := live.poolContains("voluntary_exit", v.Index); observable && contains {
			continue
		}
		payload, err := ethmsg.BuildSignedVoluntaryExit(irSignCtx(ctx), v.Index)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign voluntary exit: " + err.Error())
			return nil
		}
		ctx.SetGossipTopicOverride("voluntary_exit")
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched validator is active, exit-eligible, non-exiting, and absent from the voluntary exit pool")
	return nil
}

func buildLiveValidProposerSlashing(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for proposer slashing: " + err.Error())
		return nil
	}
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for proposer slashing: " + err.Error())
		return nil
	}
	for _, v := range validators {
		if !v.activeAt(ctx.CurrentEpoch) {
			continue
		}
		if contains, observable := live.poolContains("proposer_slashing", v.Index); observable && contains {
			continue
		}
		payload, err := ethmsg.BuildProposerSlashing(irSignCtx(ctx), v.Index, ctx.HeadSlot)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign proposer slashing: " + err.Error())
			return nil
		}
		ctx.SetGossipTopicOverride("proposer_slashing")
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched validator is active, slashable, and absent from the proposer slashing pool")
	return nil
}

func buildLiveValidAttesterSlashing(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for attester slashing: " + err.Error())
		return nil
	}
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for attester slashing: " + err.Error())
		return nil
	}
	duties, err := live.attesterDuties(ctx.CurrentEpoch, validatorIndices(validators))
	if err != nil {
		ctx.MarkSetupInapplicable("cannot query attester duties for attester slashing: " + err.Error())
		return nil
	}
	for _, duty := range duties {
		if duty.Slot > ctx.HeadSlot || !validatorMatched(validators, duty.ValidatorIndex) {
			continue
		}
		if contains, observable := live.poolContains("attester_slashing", duty.ValidatorIndex); observable && contains {
			continue
		}
		payload, err := ethmsg.BuildAttesterSlashing(irSignCtx(ctx), duty.ValidatorIndex, duty.Slot, duty.CommitteeIndex)
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign attester slashing: " + err.Error())
			return nil
		}
		ctx.SetGossipTopicOverride("attester_slashing")
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched validator has a non-future attester duty absent from the attester slashing pool")
	return nil
}

func buildLiveValidBlsToExecutionChange(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for BLS-to-execution change: " + err.Error())
		return nil
	}
	live.setCurrentEpoch(ctx, live.currentSlot(ctx))
	validators, err := live.matchedActiveValidators(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("cannot match devnet validators for BLS-to-execution change: " + err.Error())
		return nil
	}
	for _, v := range validators {
		if !v.activeAt(ctx.CurrentEpoch) || !v.withdrawalCredentialMatches(ctx.Keys) {
			continue
		}
		if contains, observable := live.poolContains("bls_to_execution_change", v.Index); observable && contains {
			continue
		}
		payload, err := ethmsg.BuildSignedBLSToExecutionChange(irSignCtx(ctx), v.Index, liveExecutionAddress())
		if err != nil {
			ctx.MarkSetupInapplicable("cannot sign BLS-to-execution change: " + err.Error())
			return nil
		}
		ctx.SetGossipTopicOverride("bls_to_execution_change")
		return wire.GossipSnappyEncode(payload)
	}
	ctx.MarkSetupInapplicable("no matched validator has BLS withdrawal credentials absent from the BLS change pool")
	return nil
}

func buildLiveValidBlobSidecar(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for blob sidecar: " + err.Error())
		return nil
	}
	payload, index, slot, err := live.recentBlobSidecar(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("no live blob sidecar source: " + err.Error())
		return nil
	}
	if !freshSidecarSlot(ctx.HeadSlot, slot) {
		ctx.MarkSetupInapplicable(fmt.Sprintf("blob sidecar slot %d is not fresh enough for a first-seen setup at head slot %d", slot, ctx.HeadSlot))
		return nil
	}
	ctx.SetGossipTopicOverride(fmt.Sprintf("blob_sidecar_%d", index))
	return wire.GossipSnappyEncode(payload)
}

func buildLiveValidDataColumnSidecar(ctx *irContext) []byte {
	live, ok := liveBuilderReady(ctx)
	if !ok {
		return nil
	}
	if err := live.refreshHead(ctx); err != nil {
		ctx.MarkSetupInapplicable("cannot refresh head for data column sidecar: " + err.Error())
		return nil
	}
	payload, index, slot, err := live.recentDataColumnSidecar(ctx)
	if err != nil {
		ctx.MarkSetupInapplicable("no live data column sidecar source: " + err.Error())
		return nil
	}
	if !freshSidecarSlot(ctx.HeadSlot, slot) {
		ctx.MarkSetupInapplicable(fmt.Sprintf("data column sidecar slot %d is not fresh enough for a first-seen setup at head slot %d", slot, ctx.HeadSlot))
		return nil
	}
	ctx.SetGossipTopicOverride(fmt.Sprintf("data_column_sidecar_%d", index))
	return wire.GossipSnappyEncode(payload)
}

func liveBuilderReady(ctx *irContext) (*LiveBuilderContext, bool) {
	if ctx == nil {
		return nil, false
	}
	if ctx.LiveBuilder == nil || ctx.LiveBuilder.BeaconAPI == "" {
		ctx.MarkSetupInapplicable("no Beacon API configured for live sequence builder")
		return nil, false
	}
	if ctx.Keys == nil {
		ctx.MarkSetupInapplicable("no devnet validator keystore available for live sequence builder")
		return nil, false
	}
	if ctx.GenesisValidatorsRoot == [32]byte{} {
		ctx.MarkSetupInapplicable("node state lacks fork data required for live sequence signing")
		return nil, false
	}
	if ctx.LiveBuilder.HTTPClient == nil {
		ctx.LiveBuilder.HTTPClient = &http.Client{Timeout: 8 * time.Second}
	}
	return ctx.LiveBuilder, true
}

func liveExecutionAddress() [20]byte {
	return [20]byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}
}

func (live *LiveBuilderContext) refreshHead(ctx *irContext) error {
	var doc beaconHeaderResponse
	if err := live.getJSON("/eth/v1/beacon/headers/head", &doc); err != nil {
		return err
	}
	slot, err := parseUint(doc.Data.Header.Message.Slot)
	if err != nil {
		return fmt.Errorf("parse head slot: %w", err)
	}
	root, err := parseRoot(doc.Data.Root)
	if err != nil {
		return fmt.Errorf("parse head root: %w", err)
	}
	ctx.HeadSlot = slot
	ctx.HeadRoot = root
	live.setCurrentEpoch(ctx, slot)
	return nil
}

func (live *LiveBuilderContext) setCurrentEpoch(ctx *irContext, slot uint64) {
	slotsPerEpoch := live.specUint("SLOTS_PER_EPOCH", defaultSlotsPerEpoch)
	ctx.CurrentEpoch = slot / slotsPerEpoch
}

func (live *LiveBuilderContext) currentSlot(ctx *irContext) uint64 {
	slot, _, ok := live.currentSlotInfo(ctx)
	if !ok {
		return ctx.HeadSlot
	}
	return slot
}

// firstSeenWindowSeconds is the cutoff (seconds into the slot) after which a
// live single-slot gossip builder marks setup inapplicable. It is two thirds of
// the slot (the aggregation deadline), which leaves the target enough of the
// slot to validate the message as current-slot while giving the
// connect + observer-warmup + build pipeline room to complete within the window
// on a multi-client devnet. The oracle tolerates a duplicate/IGNORE outcome, so
// the window no longer needs to guarantee first-seen exclusivity.
func (live *LiveBuilderContext) firstSeenWindowSeconds() uint64 {
	sps := live.specUint("SECONDS_PER_SLOT", defaultSecondsPerSlot)
	if sps == 0 {
		sps = defaultSecondsPerSlot
	}
	w := sps * 2 / 3
	if w == 0 {
		w = sps
	}
	return w
}

func (live *LiveBuilderContext) currentSlotInfo(ctx *irContext) (slot uint64, secondsIntoSlot uint64, ok bool) {
	genesis, err := live.genesisTime()
	if err != nil {
		return ctx.HeadSlot, 0, false
	}
	secondsPerSlot := live.specUint("SECONDS_PER_SLOT", defaultSecondsPerSlot)
	if secondsPerSlot == 0 {
		secondsPerSlot = defaultSecondsPerSlot
	}
	now := uint64(time.Now().Unix())
	if now < genesis {
		return ctx.HeadSlot, 0, false
	}
	elapsed := now - genesis
	return elapsed / secondsPerSlot, elapsed % secondsPerSlot, true
}

func (live *LiveBuilderContext) genesisTime() (uint64, error) {
	var doc genesisResponse
	if err := live.getJSON("/eth/v1/beacon/genesis", &doc); err != nil {
		return 0, err
	}
	return parseUint(doc.Data.GenesisTime)
}

func (live *LiveBuilderContext) matchedActiveValidators(ctx *irContext) ([]matchedValidator, error) {
	var doc validatorsResponse
	if err := live.getJSON("/eth/v1/beacon/states/head/validators?status=active", &doc); err != nil {
		return nil, err
	}
	var validators []matchedValidator
	for _, entry := range doc.Data {
		index, err := parseUint(entry.Index)
		if err != nil {
			continue
		}
		if index >= maxDevnetValidatorKeyScan {
			continue
		}
		wantPub, err := parseHexBytes(entry.Validator.Pubkey)
		if err != nil || len(wantPub) != 48 {
			continue
		}
		gotPub, err := ctx.Keys.PublicKey(index)
		if err != nil || !bytes.Equal(gotPub, wantPub) {
			continue
		}
		v := matchedValidator{Index: index, Status: entry.Status}
		v.Pubkey = append([]byte(nil), wantPub...)
		v.WithdrawalCredentials, _ = parseHexBytes(entry.Validator.WithdrawalCredentials)
		v.ActivationEpoch, _ = parseUint(entry.Validator.ActivationEpoch)
		v.ExitEpoch, _ = parseUint(entry.Validator.ExitEpoch)
		v.Slashed = entry.Validator.Slashed
		validators = append(validators, v)
	}
	sort.Slice(validators, func(i, j int) bool { return validators[i].Index < validators[j].Index })
	if len(validators) == 0 {
		return nil, fmt.Errorf("no active validators matched the committed devnet mnemonic")
	}
	return validators, nil
}

func (live *LiveBuilderContext) syncDuties(epoch uint64, indices []uint64) ([]syncDuty, error) {
	var doc syncDutiesResponse
	if err := live.postJSON(fmt.Sprintf("/eth/v1/validator/duties/sync/%d", epoch), indicesAsStrings(indices), &doc); err != nil {
		return nil, err
	}
	var out []syncDuty
	for _, entry := range doc.Data {
		idx, err := parseUint(entry.ValidatorIndex)
		if err != nil {
			continue
		}
		committeeIndices := parseUintList(entry.ValidatorSyncCommitteeIndices)
		if len(committeeIndices) == 0 {
			committeeIndices = parseUintList(entry.SyncCommitteeIndices)
		}
		out = append(out, syncDuty{ValidatorIndex: idx, SyncCommitteeIndices: committeeIndices})
	}
	return out, nil
}

func (live *LiveBuilderContext) attesterDuties(epoch uint64, indices []uint64) ([]attesterDuty, error) {
	var doc attesterDutiesResponse
	if err := live.postJSON(fmt.Sprintf("/eth/v1/validator/duties/attester/%d", epoch), indicesAsStrings(indices), &doc); err != nil {
		return nil, err
	}
	var out []attesterDuty
	for _, entry := range doc.Data {
		duty := attesterDuty{}
		var err error
		if duty.ValidatorIndex, err = parseUint(entry.ValidatorIndex); err != nil {
			continue
		}
		if duty.CommitteeIndex, err = parseUint(entry.CommitteeIndex); err != nil {
			continue
		}
		if duty.CommitteeLength, err = parseUint(entry.CommitteeLength); err != nil {
			continue
		}
		if duty.ValidatorCommitteeIndex, err = parseUint(entry.ValidatorCommitteeIndex); err != nil {
			continue
		}
		if duty.Slot, err = parseUint(entry.Slot); err != nil {
			continue
		}
		out = append(out, duty)
	}
	return out, nil
}

func (live *LiveBuilderContext) attestationData(slot, committeeIndex uint64) (*phase0.AttestationData, error) {
	var doc attestationDataResponse
	path := fmt.Sprintf("/eth/v1/validator/attestation_data?slot=%d&committee_index=%d", slot, committeeIndex)
	if err := live.getJSON(path, &doc); err != nil {
		return nil, err
	}
	data := doc.Data
	blockRoot, err := parseRoot(data.BeaconBlockRoot)
	if err != nil {
		return nil, fmt.Errorf("parse beacon block root: %w", err)
	}
	sourceEpoch, err := parseUint(data.Source.Epoch)
	if err != nil {
		return nil, fmt.Errorf("parse source epoch: %w", err)
	}
	sourceRoot, err := parseRoot(data.Source.Root)
	if err != nil {
		return nil, fmt.Errorf("parse source root: %w", err)
	}
	targetEpoch, err := parseUint(data.Target.Epoch)
	if err != nil {
		return nil, fmt.Errorf("parse target epoch: %w", err)
	}
	targetRoot, err := parseRoot(data.Target.Root)
	if err != nil {
		return nil, fmt.Errorf("parse target root: %w", err)
	}
	return &phase0.AttestationData{
		Slot:            phase0.Slot(slot),
		Index:           0,
		BeaconBlockRoot: phase0.Root(blockRoot),
		Source:          &phase0.Checkpoint{Epoch: phase0.Epoch(sourceEpoch), Root: phase0.Root(sourceRoot)},
		Target:          &phase0.Checkpoint{Epoch: phase0.Epoch(targetEpoch), Root: phase0.Root(targetRoot)},
	}, nil
}

func (live *LiveBuilderContext) committeesPerSlot(slot uint64) (uint64, error) {
	var doc committeesResponse
	if err := live.getJSON(fmt.Sprintf("/eth/v1/beacon/states/head/committees?slot=%d", slot), &doc); err != nil {
		return 0, err
	}
	var maxIndex uint64
	found := false
	for _, entry := range doc.Data {
		idx, err := parseUint(entry.Index)
		if err != nil {
			continue
		}
		if !found || idx > maxIndex {
			maxIndex = idx
			found = true
		}
	}
	if !found {
		return 0, fmt.Errorf("no committees returned for slot %d", slot)
	}
	return maxIndex + 1, nil
}

func (live *LiveBuilderContext) recentBlobSidecar(ctx *irContext) ([]byte, uint64, uint64, error) {
	for _, blockID := range recentBlockIDs(ctx.HeadSlot) {
		raw, contentType, err := live.getBytes("/eth/v1/beacon/blob_sidecars/" + blockID + "?indices=0")
		if err != nil {
			continue
		}
		payload, index, slot, err := decodeBlobSidecarPayload(raw, contentType)
		if err == nil {
			return payload, index, slot, nil
		}
	}
	return nil, 0, 0, fmt.Errorf("no decodable blob sidecar at head or previous slot")
}

func (live *LiveBuilderContext) recentDataColumnSidecar(ctx *irContext) ([]byte, uint64, uint64, error) {
	paths := []string{
		"/eth/v1/debug/beacon/data_column_sidecars/",
		"/eth/v1/beacon/data_column_sidecars/",
	}
	for _, blockID := range recentBlockIDs(ctx.HeadSlot) {
		for _, prefix := range paths {
			raw, contentType, err := live.getBytes(prefix + blockID + "?indices=0")
			if err != nil {
				continue
			}
			payload, index, slot, err := decodeDataColumnSidecarPayload(raw, contentType)
			if err == nil {
				return payload, index, slot, nil
			}
		}
	}
	return nil, 0, 0, fmt.Errorf("no decodable data column sidecar at head or previous slot")
}

func (live *LiveBuilderContext) poolContains(topic string, index uint64) (bool, bool) {
	if live.PoolContains == nil {
		return false, false
	}
	return live.PoolContains(topic, index)
}

func (live *LiveBuilderContext) specUint(name string, fallback uint64) uint64 {
	var doc specResponse
	if err := live.getJSON("/eth/v1/config/spec", &doc); err != nil {
		return fallback
	}
	raw, ok := doc.Data[name]
	if !ok {
		return fallback
	}
	v, err := parseUint(fmt.Sprint(raw))
	if err != nil {
		return fallback
	}
	return v
}

func (live *LiveBuilderContext) getJSON(path string, out any) error {
	body, _, err := live.getBytesWithAccept(path, "application/json")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func (live *LiveBuilderContext) postJSON(path string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, live.BeaconAPI+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := live.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func (live *LiveBuilderContext) getBytes(path string) ([]byte, string, error) {
	return live.getBytesWithAccept(path, "application/octet-stream")
}

func (live *LiveBuilderContext) getBytesWithAccept(path, accept string) ([]byte, string, error) {
	req, err := http.NewRequest(http.MethodGet, live.BeaconAPI+path, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", accept)
	resp, err := live.HTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("%s returned HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, resp.Header.Get("Content-Type"), nil
}

type matchedValidator struct {
	Index                 uint64
	Status                string
	Pubkey                []byte
	WithdrawalCredentials []byte
	ActivationEpoch       uint64
	ExitEpoch             uint64
	Slashed               bool
}

func (v matchedValidator) activeAt(epoch uint64) bool {
	return !v.Slashed && v.ActivationEpoch <= epoch && epoch < v.ExitEpoch
}

func (v matchedValidator) voluntaryExitEligible(epoch, shardCommitteePeriod uint64) bool {
	return v.activeAt(epoch) && v.ExitEpoch == ^uint64(0) && epoch >= v.ActivationEpoch+shardCommitteePeriod
}

func (v matchedValidator) withdrawalCredentialMatches(keys *ethmsg.Keystore) bool {
	if len(v.WithdrawalCredentials) != 32 || v.WithdrawalCredentials[0] != 0 || keys == nil {
		return false
	}
	pub, err := keys.WithdrawalPublicKey(v.Index)
	if err != nil {
		return false
	}
	h := sha256.Sum256(pub)
	return bytes.Equal(v.WithdrawalCredentials[1:], h[1:])
}

type syncDuty struct {
	ValidatorIndex       uint64
	SyncCommitteeIndices []uint64
}

type attesterDuty struct {
	ValidatorIndex          uint64
	CommitteeIndex          uint64
	CommitteeLength         uint64
	ValidatorCommitteeIndex uint64
	Slot                    uint64
}

func validatorMatched(validators []matchedValidator, index uint64) bool {
	i := sort.Search(len(validators), func(i int) bool { return validators[i].Index >= index })
	return i < len(validators) && validators[i].Index == index
}

func validatorIndices(validators []matchedValidator) []uint64 {
	out := make([]uint64, len(validators))
	for i, v := range validators {
		out[i] = v.Index
	}
	return out
}

func indicesAsStrings(indices []uint64) []string {
	out := make([]string, len(indices))
	for i, v := range indices {
		out[i] = strconv.FormatUint(v, 10)
	}
	return out
}

func syncCommitteeSubnet(syncCommitteeIndex uint64, live *LiveBuilderContext) uint64 {
	committeeSize := live.specUint("SYNC_COMMITTEE_SIZE", defaultSyncCommitteeSize)
	subnetCount := live.specUint("SYNC_COMMITTEE_SUBNET_COUNT", defaultSyncCommitteeSubnetCount)
	if subnetCount == 0 {
		subnetCount = defaultSyncCommitteeSubnetCount
	}
	perSubnet := committeeSize / subnetCount
	if perSubnet == 0 {
		perSubnet = defaultSyncCommitteeSize / defaultSyncCommitteeSubnetCount
	}
	return syncCommitteeIndex / perSubnet
}

func syncCommitteeSubcommitteePosition(syncCommitteeIndex uint64, live *LiveBuilderContext) uint64 {
	committeeSize := live.specUint("SYNC_COMMITTEE_SIZE", defaultSyncCommitteeSize)
	subnetCount := live.specUint("SYNC_COMMITTEE_SUBNET_COUNT", defaultSyncCommitteeSubnetCount)
	if subnetCount == 0 {
		subnetCount = defaultSyncCommitteeSubnetCount
	}
	perSubnet := committeeSize / subnetCount
	if perSubnet == 0 {
		perSubnet = defaultSyncCommitteeSize / defaultSyncCommitteeSubnetCount
	}
	return syncCommitteeIndex % perSubnet
}

func attestationSubnet(committeesPerSlot, slot, committeeIndex uint64, live *LiveBuilderContext) uint64 {
	slotsPerEpoch := live.specUint("SLOTS_PER_EPOCH", defaultSlotsPerEpoch)
	if slotsPerEpoch == 0 {
		slotsPerEpoch = defaultSlotsPerEpoch
	}
	subnetCount := live.specUint("ATTESTATION_SUBNET_COUNT", defaultAttestationSubnetCount)
	if subnetCount == 0 {
		subnetCount = defaultAttestationSubnetCount
	}
	slotsSinceEpochStart := slot % slotsPerEpoch
	committeesSinceEpochStart := committeesPerSlot * slotsSinceEpochStart
	return (committeesSinceEpochStart + committeeIndex) % subnetCount
}

func committeesPerSlotFromDuties(duties []attesterDuty, slot uint64) uint64 {
	var maxIndex uint64
	found := false
	for _, duty := range duties {
		if duty.Slot != slot {
			continue
		}
		if !found || duty.CommitteeIndex > maxIndex {
			maxIndex = duty.CommitteeIndex
			found = true
		}
	}
	if !found {
		return 0
	}
	return maxIndex + 1
}

func selectionProofChoosesAggregator(sig []byte, committeeLength, targetAggregators uint64) bool {
	if targetAggregators == 0 {
		targetAggregators = defaultTargetAggregatorsPerCommittee
	}
	modulo := committeeLength / targetAggregators
	if modulo == 0 {
		modulo = 1
	}
	h := sha256.Sum256(sig)
	return binary.LittleEndian.Uint64(h[:8])%modulo == 0
}

func syncContributionProofChoosesAggregator(sig []byte, live *LiveBuilderContext) bool {
	committeeSize := live.specUint("SYNC_COMMITTEE_SIZE", defaultSyncCommitteeSize)
	subnetCount := live.specUint("SYNC_COMMITTEE_SUBNET_COUNT", defaultSyncCommitteeSubnetCount)
	if subnetCount == 0 {
		subnetCount = defaultSyncCommitteeSubnetCount
	}
	targetAggregators := live.specUint("TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE", defaultTargetAggregatorsPerSync)
	if targetAggregators == 0 {
		targetAggregators = defaultTargetAggregatorsPerSync
	}
	modulo := committeeSize / subnetCount / targetAggregators
	if modulo == 0 {
		modulo = 1
	}
	h := sha256.Sum256(sig)
	return binary.LittleEndian.Uint64(h[:8])%modulo == 0
}

func recentBlockIDs(headSlot uint64) []string {
	ids := []string{"head"}
	if headSlot > 0 {
		ids = append(ids, strconv.FormatUint(headSlot, 10), strconv.FormatUint(headSlot-1, 10))
	} else {
		ids = append(ids, "0")
	}
	return ids
}

func freshSidecarSlot(headSlot, sidecarSlot uint64) bool {
	return sidecarSlot >= headSlot || headSlot-sidecarSlot <= 1
}

func decodeBlobSidecarPayload(raw []byte, contentType string) ([]byte, uint64, uint64, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, 0, 0, fmt.Errorf("empty blob sidecar response")
	}
	if strings.Contains(contentType, "json") || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		var doc struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, 0, 0, err
		}
		for _, entry := range doc.Data {
			var sidecar deneb.BlobSidecar
			if err := json.Unmarshal(entry, &sidecar); err != nil {
				continue
			}
			payload, err := sidecar.MarshalSSZ()
			if err != nil {
				continue
			}
			return payload, uint64(sidecar.Index), uint64(sidecar.SignedBlockHeader.Message.Slot), nil
		}
		return nil, 0, 0, fmt.Errorf("blob sidecar JSON response has no decodable data")
	}
	var sidecar deneb.BlobSidecar
	if err := sidecar.UnmarshalSSZ(raw); err != nil {
		return nil, 0, 0, err
	}
	return append([]byte(nil), raw...), uint64(sidecar.Index), uint64(sidecar.SignedBlockHeader.Message.Slot), nil
}

func decodeDataColumnSidecarPayload(raw []byte, contentType string) ([]byte, uint64, uint64, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, 0, 0, fmt.Errorf("empty data column sidecar response")
	}
	if strings.Contains(contentType, "json") || bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, 0, 0, fmt.Errorf("data column sidecar JSON decoding is not implemented; endpoint must return SSZ")
	}
	var sidecar ethmsg.DataColumnSidecar
	if err := sidecar.UnmarshalSSZ(raw); err != nil {
		return nil, 0, 0, err
	}
	if sidecar.SignedBlockHeader == nil || sidecar.SignedBlockHeader.Message == nil {
		return nil, 0, 0, fmt.Errorf("data column sidecar is missing signed header")
	}
	return append([]byte(nil), raw...), sidecar.Index, sidecar.SignedBlockHeader.Message.Slot, nil
}

func parseHexBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

func parseRoot(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := parseHexBytes(s)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("root has %d bytes", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func parseUint(s string) (uint64, error) {
	s = strings.TrimSpace(strings.Trim(s, `"`))
	return strconv.ParseUint(s, 10, 64)
}

func parseUintList(values []string) []uint64 {
	out := make([]uint64, 0, len(values))
	for _, value := range values {
		v, err := parseUint(value)
		if err == nil {
			out = append(out, v)
		}
	}
	return out
}

type beaconHeaderResponse struct {
	Data struct {
		Root   string `json:"root"`
		Header struct {
			Message struct {
				Slot string `json:"slot"`
			} `json:"message"`
		} `json:"header"`
	} `json:"data"`
}

type validatorsResponse struct {
	Data []struct {
		Index     string `json:"index"`
		Status    string `json:"status"`
		Validator struct {
			Pubkey                string `json:"pubkey"`
			WithdrawalCredentials string `json:"withdrawal_credentials"`
			ActivationEpoch       string `json:"activation_epoch"`
			ExitEpoch             string `json:"exit_epoch"`
			Slashed               bool   `json:"slashed"`
		} `json:"validator"`
	} `json:"data"`
}

type syncDutiesResponse struct {
	Data []struct {
		ValidatorIndex                string   `json:"validator_index"`
		ValidatorSyncCommitteeIndices []string `json:"validator_sync_committee_indices"`
		SyncCommitteeIndices          []string `json:"sync_committee_indices"`
	} `json:"data"`
}

type attesterDutiesResponse struct {
	Data []struct {
		ValidatorIndex          string `json:"validator_index"`
		CommitteeIndex          string `json:"committee_index"`
		CommitteeLength         string `json:"committee_length"`
		ValidatorCommitteeIndex string `json:"validator_committee_index"`
		Slot                    string `json:"slot"`
	} `json:"data"`
}

type committeesResponse struct {
	Data []struct {
		Index string `json:"index"`
		Slot  string `json:"slot"`
	} `json:"data"`
}

type attestationDataResponse struct {
	Data struct {
		Slot            string `json:"slot"`
		Index           string `json:"index"`
		BeaconBlockRoot string `json:"beacon_block_root"`
		Source          struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"source"`
		Target struct {
			Epoch string `json:"epoch"`
			Root  string `json:"root"`
		} `json:"target"`
	} `json:"data"`
}

type specResponse struct {
	Data map[string]interface{} `json:"data"`
}

type genesisResponse struct {
	Data struct {
		GenesisTime string `json:"genesis_time"`
	} `json:"data"`
}
