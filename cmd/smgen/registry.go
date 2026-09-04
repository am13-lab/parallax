package main

// The validator's vocabularies. Inlined from p2p-testing's internal/constants
// and internal/statemachine so this tool has no internal package deps. The
// allowlists that have no single Go source of truth (guard field names, oracle
// verdict tokens) are spelled out here.

// actionTypeNames is the set of valid IR action "type" strings.
var actionTypeNames = map[string]bool{
	"ActSendReqResp":           true,
	"ActOpenStream":            true,
	"ActWritePartial":          true,
	"ActWriteAndClose":         true,
	"ActReadResponse":          true,
	"ActSleep":                 true,
	"ActReconnect":             true,
	"ActInjectGossip":          true,
	"ActCheckConnected":        true,
	"ActSwitchTopic":           true,
	"ActConnectRaw":            true,
	"ActSendStatus":            true,
	"ActDisconnectPeer":        true,
	"ActRequestCustodyColumns": true,
	"ActQueryENR":              true,
	"ActQueryPeerList":         true,
	"ActVerifyENRBehavior":     true,
	"ActResolveSubnets":        true,
	"ActValidateResponseOrder": true,
}

// reqRespProtocolActions: actions whose "protocol" is a real Req/Resp protocol
// ID (validated against protocolIDSet). Note ActRequestCustodyColumns and
// ActVerifyENRBehavior use "protocol" as a selector keyword (custody/cgc/...),
// not a protocol ID, so they are intentionally excluded.
var reqRespProtocolActions = map[string]bool{
	"ActSendReqResp":           true,
	"ActSendStatus":            true,
	"ActValidateResponseOrder": true,
	"ActOpenStream":            true,
}

// noProtocolActions must not set "protocol".
var noProtocolActions = map[string]bool{
	"ActSleep":          true,
	"ActReconnect":      true,
	"ActConnectRaw":     true,
	"ActDisconnectPeer": true,
	"ActCheckConnected": true,
	"ActQueryENR":       true,
	"ActQueryPeerList":  true,
	"ActResolveSubnets": true,
}

// protocolIDSet is the set of valid Req/Resp protocol ID strings (inlined
// from internal/constants).
var protocolIDSet = map[string]bool{
	"/eth2/beacon_chain/req/status/1/ssz_snappy":                               true,
	"/eth2/beacon_chain/req/status/2/ssz_snappy":                               true,
	"/eth2/beacon_chain/req/goodbye/1/ssz_snappy":                              true,
	"/eth2/beacon_chain/req/beacon_blocks_by_range/1/ssz_snappy":               true,
	"/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy":               true,
	"/eth2/beacon_chain/req/beacon_blocks_by_root/1/ssz_snappy":                true,
	"/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy":                true,
	"/eth2/beacon_chain/req/beacon_blocks_by_head/1/ssz_snappy":                true,
	"/eth2/beacon_chain/req/ping/1/ssz_snappy":                                 true,
	"/eth2/beacon_chain/req/metadata/1/ssz_snappy":                             true,
	"/eth2/beacon_chain/req/metadata/2/ssz_snappy":                             true,
	"/eth2/beacon_chain/req/metadata/3/ssz_snappy":                             true,
	"/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy":               true,
	"/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy":                true,
	"/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy":        true,
	"/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy":         true,
	"/eth2/beacon_chain/req/execution_payload_envelopes_by_range/1/ssz_snappy": true,
	"/eth2/beacon_chain/req/execution_payload_envelopes_by_root/1/ssz_snappy":  true,
	"/eth2/beacon_chain/req/light_client_bootstrap/1/ssz_snappy":               true,
	"/eth2/beacon_chain/req/light_client_updates_by_range/1/ssz_snappy":        true,
	"/eth2/beacon_chain/req/light_client_finality_update/1/ssz_snappy":         true,
	"/eth2/beacon_chain/req/light_client_optimistic_update/1/ssz_snappy":       true,
}

// mutatorNames is the set of valid mutator .Name values (inlined from the
// internal/statemachine mutator registries).
var mutatorNames = map[string]bool{
	"append_garbage": true, "blob_index_over_max": true, "break_snappy": true,
	"count_over_max": true, "count_zero": true, "data_column_count_max": true,
	"empty_root_list": true, "fork_digest_flip": true, "gossip_append_garbage": true,
	"gossip_at_max_payload_size": true, "gossip_attestation_previous_epoch": true,
	"gossip_attestation_stale_slot": true, "gossip_attestation_subnet_oob": true,
	"gossip_attestation_two_epochs_ago": true, "gossip_break_snappy": true,
	"gossip_cross_type": true, "gossip_data_column_index_oob": true,
	"gossip_far_future_slot": true, "gossip_future_slot": true, "gossip_old_slot": true,
	"gossip_one_over_max_payload": true, "gossip_oversized": true,
	"gossip_random_bytes": true, "gossip_snappy_only": true, "gossip_stale_slot": true,
	"gossip_sync_committee_subnet_oob": true, "gossip_truncate": true,
	"gossip_zero_signature": true, "oversized_root_list": true, "random_bytes": true,
	"truncate_half": true, "truncate_one": true, "varint_non_minimal": true,
	"varint_oversize": true, "varint_zero": true, "wrong_ssz_size": true,
}

// resultCodeNames maps every named result code to its byte value (inlined
// from internal/statemachine types.go).
var resultCodeNames = map[string]byte{
	"GossipAccepted": 0x10, "GossipRejected": 0x11,
	"GossipDisconnected": 0x12, "GossipConnected": 0x13,
	"ConnStatusSuccess": 0x20, "ConnStatusRejected": 0x21,
	"ConnDisconnectedOK": 0x22, "ConnReconnectedOK": 0x23,
	"PeerScoreStillConnected": 0x30, "PeerScoreDisconnected": 0x31,
	"PeerScoreCustodyOK": 0x32, "PeerScoreCustodyFailed": 0x33,
	"PeerScoreReconnectOK": 0x34, "PeerScoreReconnectBanned": 0x35,
	"DiscENRQueryOK": 0x40, "DiscENRQueryFailed": 0x41,
	"DiscMetaDataOK": 0x42, "DiscMetaDataMismatch": 0x43,
	"DiscCustodyMatch": 0x44, "DiscCustodyMismatch": 0x45,
	"DiscPeerListFound": 0x46, "DiscPeerListNotFound": 0x47,
	"DiscNFDAccepted": 0x48, "DiscNFDRejected": 0x49,
	"SubnetCustodyAccepted": 0x50, "SubnetCustodyRejected": 0x51,
	"SubnetNonCustodyAccepted": 0x52, "SubnetNonCustodyRejected": 0x53,
	"SubnetOutOfRangeAccepted": 0x54, "SubnetOutOfRangeRejected": 0x55,
	"SubnetDeprecatedAccepted": 0x56, "SubnetDeprecatedRejected": 0x57,
	"SubnetCrossTypeAccepted": 0x58, "SubnetCrossTypeRejected": 0x59,
	"SubnetENRResolved": 0x5A, "SubnetENRResolveFailed": 0x5B,
	"ConcStreamOpened": 0x70, "ConcStreamWritten": 0x71,
	"ConcStreamRead": 0x72, "ConcStreamRefused": 0x73,
	"ConcStreamTimeout": 0x74,
	"LCBootstrapOK":     0x60, "LCBootstrapFailed": 0x61,
	"LCUpdateOK": 0x62, "LCUpdateFailed": 0x63,
	"LCFinalityOK": 0x64, "LCFinalityFailed": 0x65,
	"LCOptimisticOK": 0x66, "LCOptimisticFailed": 0x67,
	"FTForkAccepted": 0x80, "FTForkRejected": 0x81,
	"FTGracePeriodOK": 0x82, "FTGracePeriodFail": 0x83,
	"FTDeprecatedAccepted": 0x84, "FTDeprecatedRejected": 0x85,
	"RespOrderCorrect": 0x90, "RespOrderMismatch": 0x91,
	"RespAllOrNoneViolation": 0x92, "RespMalformedChunk": 0x93,
}

// Guard field allowlists. These name SeqContext fields; the compiler maps each
// to a field access. Spelled out here because there is no single Go source.
var (
	guardFlagFields = map[string]bool{
		"status_done": true, "generating_mode": true,
		"disc_we_in_peer_list": true, "disc_nfd_mismatch_sent": true,
	}
	guardPresentNames = map[string]bool{
		"enr_snapshot": true,
	}
	guardCounterFields = map[string]bool{
		"messages_sent": true, "rejection_count": true, "connection_count": true,
		"gossip_violation_count": true, "reqresp_failure_count": true,
		"custody_columns_requested": true, "custody_columns_failed": true,
		"non_custody_requested": true, "reconnect_attempts": true,
		"decay_wait_count": true, "disc_enr_query_count": true,
		"disc_peer_list_count": true, "subnet_custody_injected": true,
		"subnet_non_custody_injected": true, "subnet_boundary_injected": true,
	}
	guardLenFields = map[string]bool{
		"open_streams": true, "step_results": true,
		"subnet_custody_subnets": true, "subnet_non_custody_subnets": true,
		"subnet_subscribed_attn": true, "subnet_unsubscribed_attn": true,
		"subnet_subscribed_sync": true, "subnet_unsubscribed_sync": true,
	}
)

// oracleVerdicts is the vocabulary for oracle expected/must_not tokens.
var oracleVerdicts = map[string]bool{
	"ACCEPT": true, "REJECT": true, "SUCCESS": true, "EMPTY": true,
	"CRASH": true, "UNREACHABLE": true, "TIMEOUT": true, "ERROR": true,
	"STREAM_RESET": true, "INVALID_REQUEST": true, "SERVER_ERROR": true,
	"RESOURCE_UNAVAILABLE": true, "RATE_LIMITED": true,
	"RESP_ORDER_CORRECT": true, "RESP_ORDER_MISMATCH": true,
	"RESP_ALL_OR_NONE_VIOLATION": true, "RESP_MALFORMED_CHUNK": true,
	// Composite verdicts for rules where the spec permits more than one conforming
	// answer. See matchesVerdict for the exact tokens each accepts.
	"SUCCESS_OR_UNAVAILABLE": true, "ACCEPT_OR_IGNORE": true,
}

// builderNames is the set of named payload builders the IR may reference.
var builderNames = map[string]bool{
	"buildStatusSSZ":                        true,
	"buildStatusV2SSZ":                      true,
	"buildDataColumnSidecarSSZ":             true,
	"BuildDataColumnsByRangeRequest":        true,
	"deriveSyncPeriod":                      true,
	"buildPingStreamCountSSZ":               true,
	"buildStatusV2ForkFlipped":              true,
	"buildRandomGossip100":                  true,
	"buildRandomGossip200":                  true,
	"buildBlocksByRangeNearHead":            true,
	"buildBeaconBlocksByRangeV2NearHead":    true,
	"buildBlock200Slot1":                    true,
	"buildBlobIdentifierHeadRoot":           true,
	"buildLCUpdatesByRange1SSZ":             true,
	"buildLCAdditionalUpdatesSSZ":           true,
	"buildStatusV2WrongNFD":                 true,
	"buildSubInjectCustodyDataColumn":       true,
	"buildSubInjectSubscribedAttestation":   true,
	"buildSubInjectSubscribedSync":          true,
	"buildSubInjectNonCustodyDataColumn":    true,
	"buildSubInjectUnsubscribedAttestation": true,
	"buildSubInjectUnsubscribedSync":        true,
	"buildSubBoundaryOutOfRange":            true,
	"buildSubBoundaryDeprecated":            true,
	"buildSubBoundaryCrossType":             true,
	"buildPingHalfOpen":                     true,
	"buildBlocksByRangeHalfOpen":            true,
	"buildBlocksByRangeOrdering":            true,
	"buildDataColumnsOrdering":              true,
	"buildDataColumnsAllOrNone":             true,
	"buildDataColumns010":                   true,
	"buildBlocksByRangeV1Probe":             true,
	"buildDataColumns16NoColumns":           true,
	"buildRootListHeadRoot":                 true,
	"buildBlocksByHeadHeadRoot":             true,
	"buildRandomGossip50":                   true,
	"buildBlocksByRangeCountOverMax":        true,
	"buildDataColumnSidecarInvalid":         true,
	"buildDataColumnSidecarValid":           true,
	"buildRandomGossip300":                  true,
	"buildBlockSlotPlusOne":                 true,
	"buildBlockSlotPlusTwo":                 true,
	"buildAttestationPrevEpoch":             true,
	"buildAttestationTwoEpochsAgo":          true,
	"buildOrphanEnvelopeRandomRoot":         true,
	"buildFutureSlotBlockRandom":            true,

	// cryptomsg: ethmsg-backed signed/encoded consensus messages (valid + variants).
	"buildValidBeaconBlock":                                       true,
	"buildInvalidBeaconBlockParentKnownValid":                     true,
	"buildInvalidBeaconBlockSigInvalid":                           true,
	"buildInvalidBeaconBlockSlotFuture":                           true,
	"buildInvalidBeaconBlockProposerIndexWrong":                   true,
	"buildInvalidBeaconBlockTimestampCorrect":                     true,
	"buildInvalidBeaconBlockKzgProof":                             true,
	"buildValidBeaconAttestation":                                 true,
	"buildInvalidBeaconAttestationSlotFuture":                     true,
	"buildInvalidBeaconAttestationSlotEpochRange":                 true,
	"buildInvalidBeaconAttestationIndexOob":                       true,
	"buildInvalidBeaconAttestationSigInvalid":                     true,
	"buildInvalidBeaconAttestationTargetRootConsistent":           true,
	"buildInvalidBeaconAttestationFinalizedAncestor":              true,
	"buildValidBeaconAggregateAndProof":                           true,
	"buildLiveValidBeaconAggregateAndProof":                       true,
	"buildInvalidBeaconAggregateAndProofAggregateSigInvalid":      true,
	"buildInvalidBeaconAggregateAndProofSelectionProofSigInvalid": true,
	"buildInvalidBeaconAggregateAndProofOuterSigInvalid":          true,
	"buildInvalidBeaconAggregateAndProofSlotFuture":               true,
	"buildInvalidBeaconAggregateAndProofSlotEpochRange":           true,
	"buildInvalidBeaconAggregateAndProofDataIndexNonZero":         true,
	"buildInvalidBeaconAggregateAndProofMultipleCommitteeBits":    true,
	"buildInvalidBeaconAggregateAndProofNoParticipants":           true,
	"buildValidSyncCommitteeMessage":                              true,
	"buildLiveValidSyncCommitteeMessage":                          true,
	"buildInvalidSyncCommitteeMessageSigInvalid":                  true,
	"buildInvalidSyncCommitteeMessageIndexOob":                    true,
	"buildInvalidSyncCommitteeMessageSlotEpochRange":              true,
	"buildValidSyncCommitteeContributionAndProof":                 true,
	"buildInvalidSyncCommitteeContributionAndProofSigInvalid":     true,
	"buildInvalidSyncCommitteeContributionAndProofIndexOob":       true,
	"buildInvalidSyncCommitteeContributionAndProofSlotEpochRange": true,
	"buildInvalidSyncCommitteeContributionAndProofLengthLimit":    true,
	"buildValidVoluntaryExit":                                     true,
	"buildLiveValidVoluntaryExit":                                 true,
	"buildInvalidVoluntaryExitSigInvalid":                         true,
	"buildInvalidVoluntaryExitIndexOob":                           true,
	"buildInvalidVoluntaryExitSlotFuture":                         true,
	"buildValidProposerSlashing":                                  true,
	"buildInvalidProposerSlashingSigInvalid":                      true,
	"buildInvalidProposerSlashingFieldEquality":                   true,
	"buildInvalidProposerSlashingIndexOob":                        true,
	"buildValidAttesterSlashing":                                  true,
	"buildInvalidAttesterSlashingSigInvalid":                      true,
	"buildInvalidAttesterSlashingFieldEquality":                   true,
	"buildInvalidAttesterSlashingIndexOob":                        true,
	"buildInvalidAttesterSlashingLengthLimit":                     true,
	"buildValidBlobSidecar":                                       true,
	"buildLiveValidBlobSidecar":                                   true,
	"buildInvalidBlobSidecarKzgProof":                             true,
	"buildInvalidBlobSidecarSigInvalid":                           true,
	"buildInvalidBlobSidecarSlotFuture":                           true,
	"buildInvalidBlobSidecarIndexOob":                             true,
	"buildInvalidBlobSidecarProposerIndexWrong":                   true,
	"buildValidDataColumnSidecar":                                 true,
	"buildLiveValidDataColumnSidecar":                             true,
	"buildInvalidDataColumnSidecarKzgProof":                       true,
	"buildInvalidDataColumnSidecarSigInvalid":                     true,
	"buildInvalidDataColumnSidecarSlotFuture":                     true,
	"buildInvalidDataColumnSidecarIndexOob":                       true,
	"buildInvalidDataColumnSidecarProposerIndexWrong":             true,
	"buildValidBlsToExecutionChange":                              true,
	"buildLiveValidBlsToExecutionChange":                          true,
	"buildInvalidBlsToExecutionChangeSigInvalid":                  true,
	"buildInvalidBlsToExecutionChangeFieldEquality":               true,
	"buildInvalidBlsToExecutionChangeIndexOob":                    true,
	"buildValidPartialDataColumnSidecar":                          true,
	"buildInvalidPartialDataColumnEmpty":                          true,
	"buildInvalidPartialDataColumnHeaderNoCommitments":            true,
	"buildInvalidPartialDataColumnProofCountMismatch":             true,
	"buildInvalidPartialDataColumnCellCountMismatch":              true,
	"buildInvalidPartialDataColumnBitmapLenMismatch":              true,
	"buildInvalidPartialDataColumnKzgProof":                       true,
	"buildInvalidPartialDataColumnSigInvalid":                     true,
	"buildInvalidPartialDataColumnSlotFuture":                     true,
}

// compareOps are the valid comparison operators for count/len guards.
var compareOps = map[string]bool{
	"==": true, "!=": true, "<": true, "<=": true, ">": true, ">=": true,
}

// payloadKinds and wrapModes are the valid enums for the payload IR.
var (
	payloadKinds = map[string]bool{"literal": true, "fields": true, "builder": true}
	wrapModes    = map[string]bool{"ssz_snappy": true, "raw": true, "none": true, "": true}
)
