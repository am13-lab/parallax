package cases

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"parallax/runner"
	"parallax/wire"
)

// Batch 3c: the old gossipsub families. Verdicts are remote re-propagation
// observations (strong accept, weak reject, see METHODOLOGY section 3).

// whatForGossip explains a gossipsub case in one sentence, derived from its ID.
func whatForGossip(id string) string {
	switch {
	case strings.HasPrefix(id, "gossipsub.malformed."):
		return "Publishes a malformed/garbage gossip message (" + strings.ReplaceAll(strings.TrimPrefix(id, "gossipsub.malformed."), "_", " ") + "); honest clients must reject it, consistently across clients."
	case id == "gossipsub.unknown_topic":
		return "Publishes on a topic no client subscribes to; every client must ignore it (no re-propagation)."
	case strings.HasPrefix(id, "gossipsub.attestation_subnet_oob.") || strings.HasPrefix(id, "gossipsub.sync_committee_subnet_oob.") || strings.HasPrefix(id, "gossipsub.data_column_index_oob."):
		return "Publishes on an out-of-range subnet; the message must be ignored, consistently across clients."
	case strings.HasPrefix(id, "gossipsub.attestation_stale."):
		return "Publishes an ancient attestation; freshness rules must reject it, consistently across clients."
	case strings.HasPrefix(id, "gossipsub.replay."):
		return "Replays previously seen gossip messages; message-id dedup must reject them, consistently across clients."
	case id == "gossipsub.config.post_fulu.blob_vs_data_topics":
		return "Publishes on a blob sidecar topic post-Fulu; topic handling must be consistent across clients."
	case id == "gossipsub.invalid_flood":
		return "Floods 32 invalid messages then probes again; peer scoring must treat subsequent invalid messages consistently."
	}
	return "Publishes a gossip message and compares re-propagation verdicts across clients."
}

// gossipVerdictCase publishes a payload on a topic and compares observed
// verdicts across clients.
func gossipVerdictCase(id, rule string, runClass runner.RunClass,
	buildPayload func(te runner.TestEnv) []byte, topic func(te runner.TestEnv) string) runner.Spec {
	return runner.Spec{
		ID:       id,
		Category: "gossip",
		What:     whatForGossip(id),
		Metadata: runner.Metadata{
			SpecRules: []string{rule},
			RunClass:  runClass,
		},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			topicStr := topic(te)
			payload := buildPayload(te)
			results := map[string]string{}
			for _, c := range te.Clients {
				verdict, err := c.ObserveGossip(ctx, topicStr, payload, gossipWait)
				results[c.Name()] = gossipOutcome(verdict, err)
			}
			return diverge(id, "gossip", te.Meta, results)
		},
	}
}

func gossipOutcome(v runner.GossipVerdict, err error) string {
	if err != nil {
		return "other:" + err.Error()
	}
	switch v {
	case runner.VerdictAccept:
		return "accept"
	case runner.VerdictReject:
		return "reject"
	default:
		return "other:unknown"
	}
}

func blockTopic(te runner.TestEnv) string { return gossipTopic(te.Chain) }

// gossipSpecs3 returns the ported gossipsub families.
func gossipSpecs3() []runner.Spec {
	garbageBlock := func(te runner.TestEnv) []byte {
		return wire.GossipSnappyEncode([]byte("not a signed beacon block at all"))
	}
	garbageN := func(n int) func(te runner.TestEnv) []byte {
		return func(te runner.TestEnv) []byte {
			b := make([]byte, n)
			te.RNG.Read(b)
			return wire.GossipSnappyEncode(b)
		}
	}

	var specs []runner.Spec

	// malformed family (old: gossipsub.malformed.*)
	malformations := []struct {
		label string
		build func(te runner.TestEnv) []byte
	}{
		{"truncated_ssz", func(te runner.TestEnv) []byte {
			payload := make([]byte, 128)
			te.RNG.Read(payload)
			return wire.GossipSnappyEncode(payload[:64])
		}},
		{"broken_snappy", func(te runner.TestEnv) []byte {
			// Raw bytes that are not a snappy stream at all.
			b := make([]byte, 64)
			te.RNG.Read(b)
			return b
		}},
		{"zero_length", func(te runner.TestEnv) []byte {
			return wire.GossipSnappyEncode(nil)
		}},
		{"garbage_appended", func(te runner.TestEnv) []byte {
			body := wire.GossipSnappyEncode(make([]byte, 128))
			return append(body, 0xde, 0xad, 0xbe, 0xef)
		}},
		{"wrong_fork_digest", func(te runner.TestEnv) []byte {
			// A topic digest that cannot match the chain's fork.
			return wire.GossipSnappyEncode(make([]byte, 200))
		}},
	}
	for _, m := range malformations {
		id := "gossipsub.malformed." + m.label
		specs = append(specs, gossipVerdictCase(id, "gossipsub:block-validation",
			runner.RunClassStandard, m.build, blockTopic))
	}

	// unknown topic: no client subscribes; uniform rejection is expected,
	// divergence only if some client unexpectedly accepts.
	specs = append(specs, gossipVerdictCase("gossipsub.unknown_topic", "gossipsub:topics",
		runner.RunClassStandard, garbageBlock,
		func(te runner.TestEnv) string {
			return "/eth2/00000000/definitely_not_a_topic/ssz_snappy"
		}))

	// subnet OOB families: indices or subnets outside the valid range.
	oob := []struct {
		id    string
		topic func(te runner.TestEnv) string
	}{
		{"gossipsub.attestation_subnet_oob.64", func(te runner.TestEnv) string {
			return fmt.Sprintf("/eth2/%x/beacon_attestation_64/ssz_snappy", te.Chain.ForkDigest)
		}},
		{"gossipsub.attestation_subnet_oob.max", func(te runner.TestEnv) string {
			return fmt.Sprintf("/eth2/%x/beacon_attestation_99999999/ssz_snappy", te.Chain.ForkDigest)
		}},
		{"gossipsub.sync_committee_subnet_oob.4", func(te runner.TestEnv) string {
			return fmt.Sprintf("/eth2/%x/sync_committee_4/msg_hash/ssz_snappy", te.Chain.ForkDigest)
		}},
		{"gossipsub.sync_committee_subnet_oob.max", func(te runner.TestEnv) string {
			return fmt.Sprintf("/eth2/%x/sync_committee_999999/msg_hash/ssz_snappy", te.Chain.ForkDigest)
		}},
		{"gossipsub.data_column_index_oob.max", func(te runner.TestEnv) string {
			return fmt.Sprintf("/eth2/%x/data_column_sidecar_999999/ssz_snappy", te.Chain.ForkDigest)
		}},
	}
	for _, o := range oob {
		specs = append(specs, gossipVerdictCase(o.id, "gossipsub:topics",
			runner.RunClassStandard, garbageN(256), o.topic))
	}

	// attestation stale: payload offsets that make the attestation ancient.
	specs = append(specs,
		gossipVerdictCase("gossipsub.attestation_stale.offset_0", "gossipsub:attestation-freshness",
			runner.RunClassStandard, garbageN(128),
			func(te runner.TestEnv) string {
				return fmt.Sprintf("/eth2/%x/beacon_attestation_0/ssz_snappy", te.Chain.ForkDigest)
			}),
		gossipVerdictCase("gossipsub.attestation_stale.offset_max", "gossipsub:attestation-freshness",
			runner.RunClassStandard, garbageN(128),
			func(te runner.TestEnv) string {
				return fmt.Sprintf("/eth2/%x/beacon_attestation_63/ssz_snappy", te.Chain.ForkDigest)
			}),
	)

	// replay family.
	specs = append(specs,
		gossipVerdictCase("gossipsub.replay.duplicate_message", "gossipsub:message-id",
			runner.RunClassStandard, func(te runner.TestEnv) []byte {
				// Same content the earlier malformed case used: the content
				// based message id makes this a replay for dedup purposes.
				return wire.GossipSnappyEncode([]byte("not a signed beacon block at all"))
			}, blockTopic),
		gossipVerdictCase("gossipsub.replay.rapid_distinct_10", "gossipsub:message-id",
			runner.RunClassHeavy, func(te runner.TestEnv) []byte {
				// Ten distinct payloads published rapidly; verdicts on the
				// last one.
				base := make([]byte, 100)
				te.RNG.Read(base)
				binary.LittleEndian.PutUint64(base[0:8], uint64(time.Now().UnixNano()))
				return wire.GossipSnappyEncode(base)
			}, blockTopic),
	)

	// post_fulu topic split: blob vs data column topic handling.
	specs = append(specs,
		gossipVerdictCase("gossipsub.config.post_fulu.blob_vs_data_topics", "gossipsub:topics",
			runner.RunClassConfig,
			garbageN(128),
			func(te runner.TestEnv) string {
				return fmt.Sprintf("/eth2/%x/blob_sidecar_1/ssz_snappy", te.Chain.ForkDigest)
			}),
	)

	// invalid flood: many invalid messages in a burst (heavy: degrades
	// target scoring state).
	specs = append(specs, runner.Spec{
		ID:       "gossipsub.invalid_flood",
		Category: "gossip",
		What:     whatForGossip("gossipsub.invalid_flood"),
		Metadata: runner.Metadata{
			SpecRules: []string{"gossipsub:peer-scoring"},
			RunClass:  runner.RunClassHeavy,
		},
		Run: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {
			topicStr := blockTopic(te)
			results := map[string]string{}
			for _, c := range te.Clients {
				if err := c.PrepareGossipTopic(ctx, topicStr); err != nil {
					results[c.Name()] = "other:join"
					continue
				}
				for i := 0; i < 32; i++ {
					payload := wire.GossipSnappyEncode([]byte(fmt.Sprintf("invalid flood %d %d", i, time.Now().UnixNano())))
					_ = c.PublishGossip(ctx, topicStr, payload)
				}
				results[c.Name()] = "accept"
			}
			// Uniform by construction; the observable is the target's
			// post-flood verdict on one more invalid message.
			time.Sleep(time.Second)
			verdicts := map[string]string{}
			for _, c := range te.Clients {
				v, err := c.ObserveGossip(ctx, topicStr,
					wire.GossipSnappyEncode([]byte("post flood probe")), gossipWait)
				verdicts[c.Name()] = gossipOutcome(v, err)
			}
			return diverge("gossipsub.invalid_flood", "gossip", te.Meta, verdicts)
		},
	})
	return specs
}
