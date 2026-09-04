package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// skeleton.go — the -emit-dict-skeleton generator. It walks the gossip-validation
// rules, groups them by (topic, violation_class), and emits one dictionary entry
// per pair pre-filled with the prescribed builder variant. Under the builder-variant
// model each (topic, class) maps to a dedicated ethmsg builder,
// buildInvalid<Topic><Class>, that constructs an already-corrupted, re-signed
// message; behavioral classes need a 2-step sequence template instead. Every row is
// marked TODO with the artifact to implement, so authoring the catalog and the
// ethmsg builders is fill-in-the-blanks.

type skelKey struct{ topic, class string }

// dictSkeleton returns catalog entries for every distinct (topic, class) pair among
// gossip-validation rules, deterministically ordered.
func dictSkeleton(doc *astDoc) []dictEntry {
	count := map[skelKey]int{}
	var order []skelKey
	for i := range doc.Rules {
		r := &doc.Rules[i]
		res, ok := classifyBound(r)
		if !ok || res.domain != domGossip || res.class == "" || !isGossipTopic(res.topic) {
			continue
		}
		k := skelKey{res.topic, res.class}
		if _, ex := count[k]; !ex {
			order = append(order, k)
		}
		count[k]++
	}
	sort.Slice(order, func(i, j int) bool {
		if order[i].topic != order[j].topic {
			return order[i].topic < order[j].topic
		}
		return order[i].class < order[j].class
	})

	entries := make([]dictEntry, 0, len(order))
	for _, k := range order {
		note := fmt.Sprintf("%s / %s (%d rule(s))", k.topic, k.class, count[k])
		emit := dictEmit{Action: "ActInjectGossip", Expected: "REJECT"}
		if isSequenceClass(k.class) {
			note += "  TODO[SEQUENCE: 2-step template, no single builder]"
		} else {
			emit.Builder = variantBuilderName(k.topic, k.class)
			note += "  TODO[builder:" + emit.Builder + "]"
		}
		entries = append(entries, dictEntry{
			Match: dictMatch{Domain: domGossip, Topic: k.topic, ViolationClass: k.class},
			Emit:  emit,
			Note:  note,
		})
	}
	return entries
}

// emitDictSkeleton writes the skeleton catalog as JSON to stdout (read-only) and a
// summary to stderr.
func emitDictSkeleton(doc *astDoc) error {
	entries := dictSkeleton(doc)
	printSkeletonSummary(entries)
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// printSkeletonSummary reports the coverage tiers: total pairs/topics and how many
// need a builder variant vs a sequence template. All builder variants are pending
// (the ethmsg crypto/message work).
func printSkeletonSummary(entries []dictEntry) {
	topics := map[string]bool{}
	builderPairs, seqPairs := 0, 0
	for _, e := range entries {
		topics[e.Match.Topic] = true
		if e.Emit.Builder == "" {
			seqPairs++
		} else {
			builderPairs++
		}
	}
	fmt.Fprintf(os.Stderr,
		"skeleton: %d (topic,class) pairs across %d topics | builder-variant %d, sequence %d | all builders pending (ethmsg)\n",
		len(entries), len(topics), builderPairs, seqPairs)
}

// camel joins underscore-separated segments into TitleCase (beacon_block ->
// BeaconBlock), dropping any "{subnet_id}" template.
func camel(s string) string {
	if i := strings.IndexByte(s, '{'); i >= 0 {
		s = strings.TrimRight(s[:i], "_")
	}
	var b strings.Builder
	for _, p := range strings.Split(s, "_") {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return b.String()
}

// builderNameForTopic derives the valid-baseline builder name for a topic
// (buildValid<Topic>).
func builderNameForTopic(topic string) string { return "buildValid" + camel(topic) }

// variantBuilderName derives the invalid-variant builder name for a (topic, class):
// buildInvalid<Topic><Class>, e.g. (beacon_attestation, slot_future) ->
// buildInvalidBeaconAttestationSlotFuture.
func variantBuilderName(topic, class string) string {
	return "buildInvalid" + camel(topic) + camel(class)
}
