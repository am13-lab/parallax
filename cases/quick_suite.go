package cases

// QuickSuite lists representative case IDs for the fast tier: one or two
// cases per major family, covering a convergent baseline, malicious
// inputs, gossip, discovery, transport and a sequence. Small enough for a
// pre-run sanity check, broad enough to exercise every protocol surface.
func QuickSuite() []string {
	return []string{
		// reqresp semantics: convergent baseline, mismatch, negotiation
		"reqresp.ping.empty_body",
		"reqresp.status.valid",
		"reqresp.status.fork_mismatch",
		"reqresp.unknown_protocol",
		"reqresp.goodbye.valid",
		// malicious input families
		"reqresp.malformed.ping.truncate_one",
		"reqresp.length_bomb.ping.varint_max_uint64",
		"cryptomsg.ping.truncate_one.tiny",
		"cryptomsg.varint.status.0",
		// gossip
		"gossip.block.malformed",
		"gossipsub.malformed.garbage_appended",
		"gossipsub.replay.duplicate_message",
		// discovery / enr
		"discovery.fork_digest",
		"discovery.enr.seq_number_value",
		// transport
		"transport.handshake.connect",
		"transporttest.handshake.stalled_single",
		// semantic + sequence
		"semantic_valid.ping_valid_accepts",
		"statemachine.seq.01.status_garbage.ping_valid.ping_truncated",
	}
}
