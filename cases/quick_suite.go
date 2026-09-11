package cases

// QuickSuite lists representative case IDs for the fast tier: the main
// families each covered across their input classes (convergent baseline,
// malformed truncation, boundary values, varint encoding, appended
// garbage, negotiation, gossip observation), plus a sequence. Sized for a
// pre-run sanity check in single-digit minutes.
func QuickSuite() []string {
	return []string{
		// --- reqresp: convergent baselines ---
		"reqresp.ping.empty_body",
		"reqresp.status.valid",
		"reqresp.metadata.valid",
		"reqresp.goodbye.valid",
		// --- reqresp: negotiation and status semantics ---
		"reqresp.unknown_protocol",
		"reqresp.status.fork_mismatch",
		"reqresp.status.finalized_mismatch",
		"reqresp.status.boundary.head_slot_max_uint64",
		// --- reqresp: malformed / bombs / trailing / exhaustion ---
		"reqresp.malformed.ping.truncate_one",
		"reqresp.malformed.ping.random_bytes",
		"reqresp.length_bomb.ping.varint_max_uint64",
		"reqresp.trailing_bytes.ping.extra_snappy_chunk",
		"reqresp.exhaustion.slow_request",
		"reqresp.data_columns_by_range.zero_columns",
		// --- cryptomsg: truncation classes across protocols ---
		"cryptomsg.ping.truncate_one.tiny",
		"cryptomsg.status.truncate_half.tiny",
		"cryptomsg.blocks_by_range.append_garbage.tiny",
		"cryptomsg.varint.ping.128",
		"cryptomsg.varint.blocksbyrange.18446744073709551615",
		// --- gossip / gossipsub ---
		"gossip.block.malformed",
		"gossipsub.malformed.garbage_appended",
		"gossipsub.replay.duplicate_message",
		"gossipsub.invalid_flood",
		"gossipsub.attestation_stale.offset_max",
		// --- discovery / enr / metadata ---
		"discovery.fork_digest",
		"discovery.enr.seq_number_value",
		"discovery.enr.ip_field_valid",
		"discovery.metadata.custody_group_count",
		// --- transport ---
		"transport.handshake.connect",
		"transport.handshake.identity_rotation",
		"transporttest.corrupted.random_bytes",
		"transporttest.handshake.stalled_single",
		// --- semantic + sequence ---
		"semantic_valid.ping_valid_accepts",
		"semantic_valid.blocks_by_range_valid",
		"statemachine.seq.01.status_garbage.ping_valid.ping_truncated",
	}
}
