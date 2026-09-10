package main

import (
	"fmt"
	"go/format"
	"strings"
)

// render_cases.go — compiles validated SM-IR into self-contained parallax
// runner.Spec cases. One Spec per eligible transition: the transition's action
// runs against every client, the per-client verdict vector is compared, and
// fork guards become Preflight gates. Transitions needing fine-grained stream
// control (open/partial-write/read), pure computation, or unported payload
// builders are skipped with a printed note.

// caseActionFamilies lists the IR action types the renderer can emit, with
// the runtime family used in the generated Run closure.
var caseActionFamilies = map[string]string{
	"ActSendReqResp":           "reqresp",
	"ActSendStatus":            "reqresp",
	"ActInjectGossip":          "gossip",
	"ActCheckConnected":        "health",
	"ActReconnect":             "reconnect",
	"ActQueryENR":              "statequery",
	"ActVerifyENRBehavior":     "statequery",
	"ActSleep":                 "sleep",
	"ActOpenStream":            "openstream",
	"ActReadResponse":          "reqresp",
	"ActWritePartial":          "writepartial",
	"ActSwitchTopic":           "switchtopic",
	"ActResolveSubnets":        "resolvesubnets",
	"ActWriteAndClose":         "sendonly",
	"ActValidateResponseOrder": "ordercheck",
	"ActDisconnectPeer":        "disconnect",
	"ActRequestCustodyColumns": "custody",
}

// portedCaseBuilders is the set of payload builder names available in the
// parallax cases package (cases/irbuilders.go, byte-equivalence verified
// against p2p-testing). Builder references outside this set skip the
// transition (the cryptomsg ethmsg-backed builders are not ported yet).
var portedCaseBuilders = map[string]bool{
	"buildStatusV2SSZ": true, "buildPingStreamCountSSZ": true,
	"buildStatusV2ForkFlipped": true, "buildStatusV2WrongNFD": true,
	"buildRandomGossip50": true, "buildRandomGossip100": true,
	"buildRandomGossip200": true, "buildRandomGossip300": true,
	"buildBlocksByRangeNearHead": true, "buildBeaconBlocksByRangeV2NearHead": true,
	"buildBlock200Slot1": true, "buildBlockSlotPlusOne": true, "buildBlockSlotPlusTwo": true,
	"buildBlobIdentifierHeadRoot": true, "buildLCUpdatesByRange1SSZ": true,
	"buildLCAdditionalUpdatesSSZ": true, "buildPingHalfOpen": true,
	"buildBlocksByRangeHalfOpen": true, "buildBlocksByRangeOrdering": true,
	"buildDataColumnsOrdering": true, "buildDataColumnsAllOrNone": true,
	"buildDataColumns010": true, "buildBlocksByRangeV1Probe": true,
	"buildDataColumns16NoColumns": true, "buildRootListHeadRoot": true,
	"buildBlocksByHeadHeadRoot": true, "buildBlocksByRangeCountOverMax": true,
	"buildDataColumnSidecarValid": true, "buildDataColumnSidecarInvalid": true,
	"buildAttestationPrevEpoch": true, "buildAttestationTwoEpochsAgo": true,
	"buildOrphanEnvelopeRandomRoot": true, "buildFutureSlotBlockRandom": true,
	"buildSubInjectCustodyDataColumn": true, "buildSubInjectSubscribedAttestation": true,
	"buildSubInjectSubscribedSync": true, "buildSubInjectNonCustodyDataColumn": true,
	"buildSubInjectUnsubscribedAttestation": true, "buildSubInjectUnsubscribedSync": true,
	"buildSubBoundaryOutOfRange": true, "buildSubBoundaryDeprecated": true,
	"buildSubBoundaryCrossType": true,

	// live 系列需要 Beacon API（运行时职责/时钟窗口）；无法构建时返回 nil。
	"buildLiveValidBeaconAggregateAndProof": true,
	"buildLiveValidSyncCommitteeMessage":    true,
	"buildLiveValidBlobSidecar":             true,
	"buildLiveValidDataColumnSidecar":       true,
	"buildLiveValidVoluntaryExit":           true,
	"buildLiveValidBlsToExecutionChange":    true,

	// cryptomsg: ethmsg-backed signed/encoded consensus messages (ported).
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
	"buildInvalidBeaconAggregateAndProofAggregateSigInvalid":      true,
	"buildInvalidBeaconAggregateAndProofSelectionProofSigInvalid": true,
	"buildInvalidBeaconAggregateAndProofOuterSigInvalid":          true,
	"buildInvalidBeaconAggregateAndProofSlotFuture":               true,
	"buildInvalidBeaconAggregateAndProofSlotEpochRange":           true,
	"buildInvalidBeaconAggregateAndProofDataIndexNonZero":         true,
	"buildInvalidBeaconAggregateAndProofMultipleCommitteeBits":    true,
	"buildInvalidBeaconAggregateAndProofNoParticipants":           true,
	"buildValidSyncCommitteeMessage":                              true,
	"buildInvalidSyncCommitteeMessageSigInvalid":                  true,
	"buildInvalidSyncCommitteeMessageIndexOob":                    true,
	"buildInvalidSyncCommitteeMessageSlotEpochRange":              true,
	"buildValidSyncCommitteeContributionAndProof":                 true,
	"buildInvalidSyncCommitteeContributionAndProofSigInvalid":     true,
	"buildInvalidSyncCommitteeContributionAndProofIndexOob":       true,
	"buildInvalidSyncCommitteeContributionAndProofSlotEpochRange": true,
	"buildInvalidSyncCommitteeContributionAndProofLengthLimit":    true,
	"buildValidVoluntaryExit":                                     true,
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
	"buildInvalidBlobSidecarKzgProof":                             true,
	"buildInvalidBlobSidecarSigInvalid":                           true,
	"buildInvalidBlobSidecarSlotFuture":                           true,
	"buildInvalidBlobSidecarIndexOob":                             true,
	"buildInvalidBlobSidecarProposerIndexWrong":                   true,
	"buildValidDataColumnSidecar":                                 true,
	"buildInvalidDataColumnSidecarKzgProof":                       true,
	"buildInvalidDataColumnSidecarSigInvalid":                     true,
	"buildInvalidDataColumnSidecarSlotFuture":                     true,
	"buildInvalidDataColumnSidecarIndexOob":                       true,
	"buildInvalidDataColumnSidecarProposerIndexWrong":             true,
	"buildValidBlsToExecutionChange":                              true,
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

// caseSkip reports why a transition cannot be rendered as a standalone case;
// empty means renderable.
func caseSkip(t *Transition) string {
	if _, ok := caseActionFamilies[t.Action.Type]; !ok {
		return "action " + t.Action.Type + " not mapped"
	}
	if t.Guard != nil {
		_, _, residual, err := splitForkGuard(t.Guard)
		if err != nil {
			return "guard: " + err.Error()
		}
		if residual != nil {
			return "non-fork guard"
		}
	}
	if caseActionFamilies[t.Action.Type] == "sendonly" && t.Action.Protocol == "" {
		return "sendonly action has no protocol"
	}
	if p := t.Action.Payload; p != nil {
		switch p.Kind {
		case "builder":
			if !portedCaseBuilders[p.Name] {
				return "builder " + p.Name + " not ported"
			}
		case "fields":
			if fam := caseActionFamilies[t.Action.Type]; fam != "reqresp" && fam != "openstream" && fam != "writepartial" {
				return "fields payload on non-reqresp action"
			}
		case "literal":
			// hex/size/null
		default:
			return "payload kind " + p.Kind
		}
	}
	return ""
}

// caseNeedsIctx reports whether the generated Run closure references ictx.
func caseNeedsIctx(t *Transition) bool {
	fam := caseActionFamilies[t.Action.Type]
	if fam == "gossip" || fam == "custody" || fam == "ordercheck" || fam == "switchtopic" {
		return true
	}
	if t.Action.Mutator != "" {
		return true
	}
	if p := t.Action.Payload; p != nil {
		switch p.Kind {
		case "builder":
			return true
		case "fields":
			for _, fv := range p.Fields {
				if fv.Ctx != "" {
					return true
				}
			}
			return false
		}
		return false
	}
	return false
}

// renderMachineCasesFile renders every machine into one Go source file
// defining irMachineSpecs() []runner.Spec.
func renderMachineCasesFile(machines []*Machine, pkg, source string, pm *ProtocolModel) (string, error) {
	var fnNames []string
	var bodies []string
	for _, m := range machines {
		fn, body, err := renderMachineSpecFunc(m, pm)
		if err != nil {
			return "", err
		}
		fnNames = append(fnNames, fn)
		bodies = append(bodies, body)
	}
	all := strings.Join(bodies, "\n")
	needTime := strings.Contains(all, "time.Millisecond")
	needWire := strings.Contains(all, "wire.")
	needBinary := strings.Contains(all, "binary.")

	var file strings.Builder
	file.WriteString("// Code generated by smgen; DO NOT EDIT.\n")
	fmt.Fprintf(&file, "// Source: %s.\n\n", source)
	fmt.Fprintf(&file, "package %s\n\n", pkg)
	file.WriteString("import (\n\t\"context\"\n")
	if needBinary {
		file.WriteString("\t\"encoding/binary\"\n")
	}
	if needTime {
		file.WriteString("\t\"time\"\n")
	}
	if needWire {
		file.WriteString("\t\"parallax/wire\"\n")
	}
	file.WriteString("\t\"parallax/runner\"\n)\n\n")

	file.WriteString("// irMachineSpecs returns every SM-IR machine case.\n")
	file.WriteString("func irMachineSpecs() []runner.Spec {\n\tvar specs []runner.Spec\n")
	for _, fn := range fnNames {
		fmt.Fprintf(&file, "\tspecs = append(specs, %s()...)\n", fn)
	}
	file.WriteString("\treturn specs\n}\n\n")
	for _, b := range bodies {
		file.WriteString(b)
		file.WriteString("\n")
	}
	return formatCaseSource(&file)
}

// renderMachineSpecFunc renders one machine as
// func ir<Name>Specs() []runner.Spec with one Spec per eligible transition.
func renderMachineSpecFunc(m *Machine, pm *ProtocolModel) (string, string, error) {
	var b strings.Builder
	fn := "ir" + sanitizeIdent(m.Name) + "Specs"
	fmt.Fprintf(&b, "// %s renders machine %q transitions as differential cases.\n", fn, m.Name)
	fmt.Fprintf(&b, "func %s() []runner.Spec {\n\tvar specs []runner.Spec\n", fn)
	for i := range m.Transitions {
		t := &m.Transitions[i]
		if reason := caseSkip(t); reason != "" {
			fmt.Printf("  skip %s/%s: %s\n", m.Name, t.Label, reason)
			continue
		}
		if err := renderCaseSpec(&b, m.Name, t, pm); err != nil {
			return "", "", fmt.Errorf("transition %q: %w", t.Label, err)
		}
	}
	fmt.Fprintf(&b, "\treturn specs\n}\n")
	return fn, b.String(), nil
}

// renderCaseSpec emits one runner.Spec literal for a transition.
func renderCaseSpec(b *strings.Builder, machine string, t *Transition, pm *ProtocolModel) error {
	id := "ir." + machine + "." + t.Label
	category := "ir_" + strings.ToLower(machine)

	what := describeTransition(t)
	if want := oracleWant(t.Oracle); want != "" {
		what += fmt.Sprintf(" (expected %s)", want)
	}

	fmt.Fprintf(b, "\t{\n")
	fmt.Fprintf(b, "\t\tid := %q\n", id)
	fmt.Fprintf(b, "\t\tspecs = append(specs, runner.Spec{\n")
	fmt.Fprintf(b, "\t\t\tID: id, Category: %q,\n", category)
	fmt.Fprintf(b, "\t\t\tWhat: %q,\n", what)
	fmt.Fprintf(b, "\t\t\tMetadata: runner.Metadata{SpecRules: %s, MinClients: 2},\n", goStringSlice(t.SpecRefs))
	if pre := renderPreflight(t.Guard); pre != "" {
		fmt.Fprintf(b, "\t\t\tPreflight: %s,\n", pre)
	}
	fmt.Fprintf(b, "\t\t\tRun: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {\n")
	if err := renderCaseRun(b, t, category, pm); err != nil {
		return err
	}
	fmt.Fprintf(b, "\t\t\t},\n")
	fmt.Fprintf(b, "\t\t})\n")
	fmt.Fprintf(b, "\t}\n")
	return nil
}

// oracleWant maps an oracle's Expected token to the case verdict class;
// empty for differential-only oracles.
func oracleWant(o *Oracle) string {
	if o == nil {
		return ""
	}
	switch o.Expected {
	case "SUCCESS", "ACCEPT":
		return "accept"
	case "REJECT", "INVALID_REQUEST", "SERVER_ERROR":
		return "reject"
	case "":
		return ""
	default:
		return strings.ToLower(o.Expected)
	}
}

// renderPreflight emits a Preflight closure literal for a fork constraint;
// empty when the guard has no fork atoms.
func renderPreflight(g *Guard) string {
	if g == nil {
		return ""
	}
	gte, in, residual, err := splitForkGuard(g)
	if err != nil || residual != nil {
		return ""
	}
	if gte == "" && len(in) == 0 {
		return ""
	}
	return fmt.Sprintf("func(ctx context.Context, chain runner.ChainConfig, cs []runner.Client) runner.PreflightResult { return irPreflightFork(ctx, cs, %q, %s) }",
		gte, goStringSlice(in))
}

// renderCaseRun emits the Run closure body for a transition.
func renderCaseRun(b *strings.Builder, t *Transition, category string, pm *ProtocolModel) error {
	family := caseActionFamilies[t.Action.Type]
	if caseNeedsIctx(t) {
		fmt.Fprintf(b, "\t\t\t\tictx := irNewContext(te)\n")
	}
	switch family {
	case "reqresp":
		proto := t.Action.Protocol
		if proto == "" {
			return fmt.Errorf("reqresp action has no protocol")
		}
		if err := renderTimeout(b, t.Action.TimeoutMs); err != nil {
			return err
		}
		if err := renderPayloadBody(b, &t.Action, "body", pm); err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tres, err := c.ReqResp(ctx, %q, body, timeout)\n", proto)
		fmt.Fprintf(b, "\t\t\t\t\tresults[c.Name()] = outcome(res, err)\n")
		fmt.Fprintf(b, "\t\t\t\t}\n")
	case "gossip":
		fmt.Fprintf(b, "\t\t\t\ttopic := irFullGossipTopic(ictx, %q)\n", t.Action.Protocol)
		if err := renderPayloadBody(b, &t.Action, "payload", pm); err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t\t\tif ictx.GossipTopicOverride != \"\" {\n\t\t\t\t\ttopic = ictx.GossipTopicOverride\n\t\t\t\t}\n")
		fmt.Fprintf(b, "\t\t\t\tif ictx.CurrentTopic != \"\" {\n\t\t\t\t\ttopic = ictx.CurrentTopic\n\t\t\t\t}\n")
		fmt.Fprintf(b, "\t\t\t\ttopic = irFullGossipTopic(ictx, topic)\n")
		fmt.Fprintf(b, "\t\t\t\tif ictx.SetupInapplicableReason != \"\" {\n")
		fmt.Fprintf(b, "\t\t\t\t\treturn nil\n")
		fmt.Fprintf(b, "\t\t\t\t}\n")
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tv, err := c.ObserveGossip(ctx, topic, payload, gossipWait)\n")
		fmt.Fprintf(b, "\t\t\t\t\tresults[c.Name()] = gossipOutcome(v, err)\n")
		fmt.Fprintf(b, "\t\t\t\t}\n")
	case "ordercheck":
		if err := renderPayloadBody(b, &t.Action, "body", pm); err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tresults[c.Name()] = irOrderCheck(ctx, c, %q, id, body, %d)\n", t.Action.Protocol, t.Action.TimeoutMs)
		fmt.Fprintf(b, "\t\t\t\t}\n")
	case "disconnect":
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tresults[c.Name()] = irDisconnectAndRestore(ctx, c)\n")
		fmt.Fprintf(b, "\t\t\t\t}\n")
	case "custody":
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tresults[c.Name()] = irCustodyRequest(ctx, c, ictx, %q)\n", t.Action.Protocol)
		fmt.Fprintf(b, "\t\t\t\t}\n")
	case "health":
		emitHealthBody(b)
	case "sendonly":
		proto := t.Action.Protocol
		if proto == "" {
			return fmt.Errorf("sendonly action has no protocol")
		}
		if err := renderPayloadBody(b, &t.Action, "body", pm); err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tif err := c.SendOnly(ctx, %q, body); err != nil {\n", proto)
		fmt.Fprintf(b, "\t\t\t\t\t\tresults[c.Name()] = \"other:\" + err.Error()\n")
		fmt.Fprintf(b, "\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"sent\"\n\t\t\t\t\t}\n")
		fmt.Fprintf(b, "\t\t\t\t}\n")
	case "reconnect":
		emitReconnectBody(b)
	case "statequery":
		emitStateQueryBody(b)
	case "sleep":
		renderTimeout(b, t.Action.TimeoutMs)
		fmt.Fprintf(b, "\t\t\t\ttime.Sleep(timeout)\n")
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tif c.Health(ctx) != nil {\n\t\t\t\t\t\tresults[c.Name()] = \"dropped\"\n\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"connected\"\n\t\t\t\t\t}\n\t\t\t\t}\n")
	case "openstream":
		proto := t.Action.Protocol
		if proto == "" {
			return fmt.Errorf("openstream action has no protocol")
		}
		timeoutMs := t.Action.TimeoutMs
		if timeoutMs <= 0 {
			timeoutMs = 5000
		}
		fmt.Fprintf(b, "\t\t\t\tctx, cancel := context.WithTimeout(ctx, %d*time.Millisecond)\n", timeoutMs)
		fmt.Fprintf(b, "\t\t\t\tdefer cancel()\n")
		if err := renderPayloadBody(b, &t.Action, "body", pm); err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tir, err := c.OpenStream(ctx, %q)\n", proto)
		fmt.Fprintf(b, "\t\t\t\t\tif err != nil {\n\t\t\t\t\t\tresults[c.Name()] = \"other:\" + err.Error()\n\t\t\t\t\t\tcontinue\n\t\t\t\t\t}\n")
		fmt.Fprintf(b, "\t\t\t\t\tif len(body) > 0 {\n\t\t\t\t\t\tif werr := ir.WriteChunk(body, false); werr != nil {\n\t\t\t\t\t\t\tresults[c.Name()] = \"other:\" + werr.Error()\n\t\t\t\t\t\t\tcontinue\n\t\t\t\t\t\t}\n\t\t\t\t\t\tresults[c.Name()] = \"written\"\n\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"opened\"\n\t\t\t\t\t}\n\t\t\t\t\tir.Close()\n\t\t\t\t}\n")
	case "writepartial":
		proto := t.Action.Protocol
		if proto == "" {
			return fmt.Errorf("writepartial action has no protocol")
		}
		if err := renderPayloadBody(b, &t.Action, "body", pm); err != nil {
			return err
		}
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\thalf := body\n\t\t\t\t\tif len(body) > 1 {\n\t\t\t\t\t\thalf = body[:len(body)/2]\n\t\t\t\t\t}\n")
		fmt.Fprintf(b, "\t\t\t\t\tif err := c.SendOnly(ctx, %q, half); err != nil {\n", proto)
		fmt.Fprintf(b, "\t\t\t\t\t\tresults[c.Name()] = \"other:\" + err.Error()\n\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"sent_partial\"\n\t\t\t\t\t}\n\t\t\t\t}\n")
	case "switchtopic":
		fmt.Fprintf(b, "\t\t\t\ttopic := irFullGossipTopic(ictx, %q)\n", t.Action.Protocol)
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tif err := c.PrepareGossipTopic(ctx, topic); err != nil {\n\t\t\t\t\t\tresults[c.Name()] = \"other:\" + err.Error()\n\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"subscribed\"\n\t\t\t\t\t}\n\t\t\t\t}\n")
	case "resolvesubnets":
		fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
		fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
		fmt.Fprintf(b, "\t\t\t\t\tif _, err := c.State(ctx); err != nil {\n\t\t\t\t\t\tresults[c.Name()] = \"other:\" + err.Error()\n\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"resolved\"\n\t\t\t\t\t}\n\t\t\t\t}\n")
	}
	emitDivergeTail(b, category)
	return nil
}

func renderTimeout(b *strings.Builder, timeoutMs int) error {
	if timeoutMs > 0 {
		fmt.Fprintf(b, "\t\t\t\ttimeout := %d * time.Millisecond\n", timeoutMs)
	} else {
		fmt.Fprintf(b, "\t\t\t\ttimeout := 5 * time.Second\n")
	}
	return nil
}

func emitHealthBody(b *strings.Builder) {
	fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
	fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
	fmt.Fprintf(b, "\t\t\t\t\tif err := c.Health(ctx); err != nil {\n")
	fmt.Fprintf(b, "\t\t\t\t\t\tresults[c.Name()] = \"not_connected\"\n")
	fmt.Fprintf(b, "\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"connected\"\n\t\t\t\t\t}\n")
	fmt.Fprintf(b, "\t\t\t\t}\n")
}

func emitReconnectBody(b *strings.Builder) {
	fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
	fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
	fmt.Fprintf(b, "\t\t\t\t\tif err := c.Connect(ctx, runner.ConnectNoStatus); err != nil {\n")
	fmt.Fprintf(b, "\t\t\t\t\t\tresults[c.Name()] = \"reconnect_failed\"\n")
	fmt.Fprintf(b, "\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"reconnected\"\n\t\t\t\t\t}\n")
	fmt.Fprintf(b, "\t\t\t\t}\n")
}

func emitStateQueryBody(b *strings.Builder) {
	fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
	fmt.Fprintf(b, "\t\t\t\tfor _, c := range te.Clients {\n")
	fmt.Fprintf(b, "\t\t\t\t\tif _, err := c.State(ctx); err != nil {\n")
	fmt.Fprintf(b, "\t\t\t\t\t\tresults[c.Name()] = \"state_unavailable\"\n")
	fmt.Fprintf(b, "\t\t\t\t\t} else {\n\t\t\t\t\t\tresults[c.Name()] = \"state_available\"\n\t\t\t\t\t}\n")
	fmt.Fprintf(b, "\t\t\t\t}\n")
}

func emitDivergeTail(b *strings.Builder, category string) {
	fmt.Fprintf(b, "\t\t\t\tdivs := diverge(id, %q, te.Meta, results)\n", category)
	fmt.Fprintf(b, "\t\t\t\tif len(divs) > 0 {\n")
	fmt.Fprintf(b, "\t\t\t\t\tdivs[0].Severity = runner.SeverityHigh\n")
	fmt.Fprintf(b, "\t\t\t\t}\n")
	fmt.Fprintf(b, "\t\t\t\treturn divs\n")
}

// renderPayloadBody emits `name := <expr over ictx>` for the transition's
// payload; a nil payload emits name := []byte(nil). Fields payloads inline a
// fixed-container SSZ encoder derived from the protocol model.
func renderPayloadBody(b *strings.Builder, a *Action, name string, pm *ProtocolModel) error {
	p := a.Payload
	if p == nil {
		fmt.Fprintf(b, "\t\t\t\t%s := []byte(nil)\n", name)
		return nil
	}
	switch p.Kind {
	case "builder":
		fmt.Fprintf(b, "\t\t\t\t%s := %s(ictx)\n", name, p.Name)
		return irEmitMutator(b, a, name)
	case "literal":
		var inner string
		switch {
		case p.Null:
			inner = "[]byte(nil)"
		case p.Size != nil:
			inner = fmt.Sprintf("make([]byte, %d)", *p.Size)
		case p.Bytes != "":
			lit, err := hexToGoBytes(p.Bytes)
			if err != nil {
				return err
			}
			inner = lit
		default:
			return fmt.Errorf("literal payload has no bytes/size/null")
		}
		fmt.Fprintf(b, "\t\t\t\t%s := %s\n", name, wrapExprCases(p.Wrap, inner))
		return irEmitMutator(b, a, name)
	case "fields":
		if err := renderFieldsPayload(b, p, a.Protocol, pm, name); err != nil {
			return err
		}
		return irEmitMutator(b, a, name)
	default:
		return fmt.Errorf("unknown payload kind %q", p.Kind)
	}
}

// renderFieldsPayload emits a fixed-container SSZ encoder assigning to name,
// with fields placed at protocol-model offsets and ictx ctx sources.
func renderFieldsPayload(b *strings.Builder, p *Payload, protocol string, pm *ProtocolModel, name string) error {
	if pm == nil {
		return fmt.Errorf("fields payload requires a protocol model")
	}
	method, ok := pm.method(protocol)
	if !ok {
		return fmt.Errorf("no protocol model entry for %q", protocol)
	}
	if method.Request.Container != "fixed" {
		return fmt.Errorf("fields codegen requires a fixed container; method %s is %q", method.Name, method.Request.Container)
	}
	total := 0
	for _, f := range method.Request.Fields {
		total += f.Size
	}
	fmt.Fprintf(b, "\t\t\t\tbuf := make([]byte, %d)\n", total)
	off := 0
	for _, f := range method.Request.Fields {
		fv, present := p.Fields[f.Name]
		if !present {
			return fmt.Errorf("missing field %q for method %s", f.Name, method.Name)
		}
		end := off + f.Size
		switch f.Type {
		case "uint64":
			switch {
			case fv.Lit != nil:
				fmt.Fprintf(b, "\t\t\t\tbinary.LittleEndian.PutUint64(buf[%d:%d], %d)\n", off, end, *fv.Lit)
			case fv.Ctx != "":
				acc, ok := caseCtxUint64[fv.Ctx]
				if !ok {
					return fmt.Errorf("unknown ctx uint64 source %q", fv.Ctx)
				}
				fmt.Fprintf(b, "\t\t\t\tbinary.LittleEndian.PutUint64(buf[%d:%d], %s)\n", off, end, acc)
			default:
				return fmt.Errorf("field %q (uint64) needs lit or ctx", f.Name)
			}
		case "bytes":
			if fv.Ctx != "" {
				acc, ok := caseCtxBytes[fv.Ctx]
				if !ok {
					return fmt.Errorf("unknown ctx bytes source %q", fv.Ctx)
				}
				fmt.Fprintf(b, "\t\t\t\tcopy(buf[%d:%d], %s)\n", off, end, acc)
			} else {
				return fmt.Errorf("field %q (bytes) needs a ctx source", f.Name)
			}
		default:
			return fmt.Errorf("field %q has unsupported type %q", f.Name, f.Type)
		}
		off = end
	}
	fmt.Fprintf(b, "\t\t\t\t%s := wire.BuildSSZSnappy(buf)\n", name)
	return nil
}

// irEmitMutator emits the post-build mutator application when the action
// declares one.
func irEmitMutator(b *strings.Builder, a *Action, name string) error {
	if a.Mutator == "" {
		return nil
	}
	fmt.Fprintf(b, "\t\t\t\t%s = irApplyMutator(%q, %s, ictx.Rng)\n", name, a.Mutator, name)
	return nil
}

// wrapExprCases wraps an inner expression per the payload wrap mode.
func wrapExprCases(wrap, inner string) string {
	switch wrap {
	case "ssz_snappy":
		return fmt.Sprintf("wire.BuildSSZSnappy(%s)", inner)
	default:
		return inner
	}
}

// --- stateless / sequence artifact rendering ---

// renderStatelessCasesFile renders the stateless testcase artifact as
// func irStatelessSpecs() []runner.Spec.
func renderStatelessCasesFile(doc *statelessArtifact, pm *ProtocolModel, pkg, source string) (string, error) {
	var b strings.Builder
	b.WriteString("// Code generated by smgen; DO NOT EDIT.\n")
	fmt.Fprintf(&b, "// Source: %s.\n\n", source)
	fmt.Fprintf(&b, "package %s\n\n", pkg)
	b.WriteString("import (\n\t\"context\"\n\t\"time\"\n\n\t\"parallax/runner\"\n)\n\n")
	b.WriteString("// irStatelessSpecs returns every SM-IR stateless case.\n")
	b.WriteString("func irStatelessSpecs() []runner.Spec {\n\tvar specs []runner.Spec\n")
	for i := range doc.Cases {
		c := &doc.Cases[i]
		if reason := caseSkip(&c.Transition); reason != "" {
			fmt.Printf("  skip stateless %s: %s\n", c.ID, reason)
			continue
		}
		if err := renderStatelessCase(&b, c, pm); err != nil {
			return "", err
		}
	}
	b.WriteString("\treturn specs\n}\n")
	return formatCaseSource(&b)
}

func renderStatelessCase(b *strings.Builder, c *statelessCase, pm *ProtocolModel) error {
	t := &c.Transition
	id := "ir_stateless." + c.ID
	what := describeTransition(t)
	if want := oracleWant(t.Oracle); want != "" {
		what += fmt.Sprintf(" (expected %s)", want)
	}
	fmt.Fprintf(b, "\t{\n")
	fmt.Fprintf(b, "\t\tid := %q\n", id)
	fmt.Fprintf(b, "\t\tspecs = append(specs, runner.Spec{\n")
	fmt.Fprintf(b, "\t\t\tID: id, Category: %q,\n", c.Category)
	fmt.Fprintf(b, "\t\t\tWhat: %q,\n", what)
	fmt.Fprintf(b, "\t\t\tMetadata: runner.Metadata{SpecRules: %s, MinClients: 2},\n", goStringSlice(c.RuleIDs))
	fmt.Fprintf(b, "\t\t\tRun: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {\n")
	if err := renderCaseRun(b, t, c.Category, pm); err != nil {
		return err
	}
	fmt.Fprintf(b, "\t\t\t},\n")
	fmt.Fprintf(b, "\t\t})\n")
	fmt.Fprintf(b, "\t}\n")
	return nil
}

// renderSequenceCasesFile renders the sequence artifact as
// func irSequenceSpecs() []runner.Spec; each case drives its steps in order
// on every client and compares the joint per-step verdict vectors.
func renderSequenceCasesFile(doc *sequenceArtifact, pm *ProtocolModel, pkg, source string) (string, error) {
	var b strings.Builder
	b.WriteString("// Code generated by smgen; DO NOT EDIT.\n")
	fmt.Fprintf(&b, "// Source: %s.\n\n", source)
	fmt.Fprintf(&b, "package %s\n\n", pkg)
	b.WriteString("import (\n\t\"context\"\n\t\"strings\"\n")
	if seqNeedsTime(doc) {
		b.WriteString("\t\"time\"\n")
	}
	b.WriteString("\n\t\"parallax/runner\"\n)\n\n")
	b.WriteString("// irSequenceSpecs returns every SM-IR sequence case.\n")
	b.WriteString("func irSequenceSpecs() []runner.Spec {\n\tvar specs []runner.Spec\n")
	for i := range doc.Cases {
		renderSequenceCase(&b, &doc.Cases[i])
	}
	b.WriteString("\treturn specs\n}\n")
	return formatCaseSource(&b)
}

// seqNeedsTime reports whether any renderable step emits a timeout duration
// (only the req/resp family does; gossip uses the shared gossipWait).
func seqNeedsTime(doc *sequenceArtifact) bool {
	for i := range doc.Cases {
		for j := range doc.Cases[i].Steps {
			t := &doc.Cases[i].Steps[j].Transition
			if caseSkip(t) == "" && caseActionFamilies[t.Action.Type] == "reqresp" {
				return true
			}
		}
	}
	return false
}

// hasSeqCache reports whether the payload uses the step-to-step cache.
func hasSeqCache(p *Payload) bool {
	return p != nil && (p.CacheLoad != "" || p.CacheStore != "")
}

func renderSequenceCase(b *strings.Builder, c *sequenceCase) {
	id := "ir_seq." + c.ID
	var stepsDesc []string
	for i := range c.Steps {
		stepsDesc = append(stepsDesc, fmt.Sprintf("%d:%s", i+1, c.Steps[i].Transition.Label))
	}
	what := fmt.Sprintf("%s: %d-step sequence (%s)", c.ID, len(c.Steps), strings.Join(stepsDesc, " -> "))
	fmt.Fprintf(b, "\t{\n")
	fmt.Fprintf(b, "\t\tid := %q\n", id)
	fmt.Fprintf(b, "\t\tspecs = append(specs, runner.Spec{\n")
	fmt.Fprintf(b, "\t\t\tID: id, Category: %q,\n", c.Category)
	fmt.Fprintf(b, "\t\t\tWhat: %q,\n", what)
	fmt.Fprintf(b, "\t\t\tMetadata: runner.Metadata{SpecRules: %s, MinClients: 2},\n", goStringSlice(c.RuleIDs))
	fmt.Fprintf(b, "\t\t\tRun: func(ctx context.Context, te runner.TestEnv) []runner.Divergence {\n")
	needsIctx := false
	for i := range c.Steps {
		st := &c.Steps[i].Transition
		if caseSkip(st) != "" {
			continue
		}
		if caseNeedsIctx(st) || st.Action.Mutator != "" || hasSeqCache(st.Action.Payload) {
			needsIctx = true
		}
	}
	if needsIctx {
		fmt.Fprintf(b, "\t\t\t\tictx := irNewContext(te)\n")
	}
	fmt.Fprintf(b, "\t\t\t\tresults := map[string]string{}\n")
	fmt.Fprintf(b, "\t\t\t\tfor _, cl := range te.Clients {\n")
	fmt.Fprintf(b, "\t\t\t\t\tvar verdicts []string\n")
	for i := range c.Steps {
		t := &c.Steps[i].Transition
		fmt.Fprintf(b, "\t\t\t\t\t// step %d: %s\n", i+1, t.Label)
		if reason := caseSkip(t); reason != "" {
			fmt.Fprintf(b, "\t\t\t\t\tverdicts = append(verdicts, \"skipped\")\n")
			continue
		}
		if err := renderSeqPayload(b, &t.Action, i+1); err != nil {
			fmt.Fprintf(b, "\t\t\t\t\tverdicts = append(verdicts, \"skipped\")\n")
			continue
		}
		emitSeqStep(b, t, i+1)
	}
	fmt.Fprintf(b, "\t\t\t\t\tresults[cl.Name()] = strings.Join(verdicts, \"/\")\n")
	fmt.Fprintf(b, "\t\t\t\t}\n")
	fmt.Fprintf(b, "\t\t\t\treturn divergeValues(id, %q, te, runner.DivAcceptReject, runner.SeverityHigh, results)\n", c.Category)
	fmt.Fprintf(b, "\t\t\t},\n")
	fmt.Fprintf(b, "\t\t})\n")
	fmt.Fprintf(b, "\t}\n")
}

// renderSeqPayload emits payload<N> for sequence step N.
func renderSeqPayload(b *strings.Builder, a *Action, n int) error {
	p := a.Payload
	if p == nil {
		fmt.Fprintf(b, "\t\t\t\t\tpayload%d := []byte(nil)\n", n)
		return irEmitSeqMutator(b, a, n)
	}
	if p.CacheLoad != "" {
		// Reuse the bytes stored by an earlier step verbatim.
		fmt.Fprintf(b, "\t\t\t\t\tpayload%d, _ := ictx.LoadPayload(%q)\n", n, p.CacheLoad)
		return irEmitSeqMutator(b, a, n)
	}
	switch p.Kind {
	case "builder":
		if !portedCaseBuilders[p.Name] {
			return fmt.Errorf("builder not ported")
		}
		fmt.Fprintf(b, "\t\t\t\t\tpayload%d := %s(ictx)\n", n, p.Name)
	case "literal":
		var inner string
		switch {
		case p.Null:
			inner = "[]byte(nil)"
		case p.Size != nil:
			inner = fmt.Sprintf("make([]byte, %d)", *p.Size)
		case p.Bytes != "":
			lit, err := hexToGoBytes(p.Bytes)
			if err != nil {
				return err
			}
			inner = lit
		}
		fmt.Fprintf(b, "\t\t\t\t\tpayload%d := %s\n", n, wrapExprCases(p.Wrap, inner))
	default:
		return fmt.Errorf("payload kind %q not supported in sequences", p.Kind)
	}
	return irEmitSeqMutatorAndStore(b, a, p, n)
}

// irEmitSeqMutator applies the step mutator in generated sequence code.
func irEmitSeqMutator(b *strings.Builder, a *Action, n int) error {
	if a.Mutator == "" {
		return nil
	}
	fmt.Fprintf(b, "\t\t\t\t\tpayload%d = irApplyMutator(%q, payload%d, ictx.Rng)\n", n, a.Mutator, n)
	return nil
}

// irEmitSeqMutatorAndStore applies the mutator then stores the payload for
// later cache_load steps.
func irEmitSeqMutatorAndStore(b *strings.Builder, a *Action, p *Payload, n int) error {
	if err := irEmitSeqMutator(b, a, n); err != nil {
		return err
	}
	if p.CacheStore != "" {
		fmt.Fprintf(b, "\t\t\t\t\tictx.StorePayload(%q, payload%d)\n", p.CacheStore, n)
	}
	return nil
}

// emitSeqStep emits the per-step action for sequence step N.
func emitSeqStep(b *strings.Builder, t *Transition, n int) {
	timeout := t.Action.TimeoutMs
	if timeout == 0 {
		timeout = 5000
	}
	switch caseActionFamilies[t.Action.Type] {
	case "reqresp":
		fmt.Fprintf(b, "\t\t\t\t\ttimeout%d := %d * time.Millisecond\n", n, timeout)
		fmt.Fprintf(b, "\t\t\t\t\tres%d, err%d := cl.ReqResp(ctx, %q, payload%d, timeout%d)\n", n, n, t.Action.Protocol, n, n)
		fmt.Fprintf(b, "\t\t\t\t\tverdicts = append(verdicts, classOf(outcome(res%d, err%d)))\n", n, n)
	case "gossip":
		fmt.Fprintf(b, "\t\t\t\t\tgtopic%d := irFullGossipTopic(ictx, %q)\n", n, t.Action.Protocol)
		fmt.Fprintf(b, "\t\t\t\t\tif ictx.GossipTopicOverride != \"\" {\n\t\t\t\t\t\tgtopic%d = ictx.GossipTopicOverride\n\t\t\t\t\t}\n", n)
		fmt.Fprintf(b, "\t\t\t\t\tif ictx.CurrentTopic != \"\" {\n\t\t\t\t\t\tgtopic%d = ictx.CurrentTopic\n\t\t\t\t\t}\n", n)
		fmt.Fprintf(b, "\t\t\t\t\tgv%d, gerr%d := cl.ObserveGossip(ctx, gtopic%d, payload%d, gossipWait)\n", n, n, n, n)
		fmt.Fprintf(b, "\t\t\t\t\tverdicts = append(verdicts, classOf(gossipOutcome(gv%d, gerr%d)))\n", n, n)
	case "health":
		fmt.Fprintf(b, "\t\t\t\t\tif cl.Health(ctx) != nil {\n\t\t\t\t\t\tverdicts = append(verdicts, \"not_connected\")\n\t\t\t\t\t} else {\n\t\t\t\t\t\tverdicts = append(verdicts, \"connected\")\n\t\t\t\t\t}\n")
	case "sendonly":
		fmt.Fprintf(b, "\t\t\t\t\tif serr := cl.SendOnly(ctx, %q, payload%d); serr != nil {\n\t\t\t\t\t\tverdicts = append(verdicts, \"other:\"+serr.Error())\n\t\t\t\t\t} else {\n\t\t\t\t\t\tverdicts = append(verdicts, \"sent\")\n\t\t\t\t\t}\n", t.Action.Protocol, n)
	case "reconnect":
		fmt.Fprintf(b, "\t\t\t\t\tif cl.Connect(ctx, runner.ConnectNoStatus) != nil {\n\t\t\t\t\t\tverdicts = append(verdicts, \"reconnect_failed\")\n\t\t\t\t\t} else {\n\t\t\t\t\t\tverdicts = append(verdicts, \"reconnected\")\n\t\t\t\t\t}\n")
	case "statequery":
		fmt.Fprintf(b, "\t\t\t\t\tif _, serr := cl.State(ctx); serr != nil {\n\t\t\t\t\t\tverdicts = append(verdicts, \"state_unavailable\")\n\t\t\t\t\t} else {\n\t\t\t\t\t\tverdicts = append(verdicts, \"state_available\")\n\t\t\t\t\t}\n")
	}
}

// caseCtxUint64/caseCtxBytes map IR ctx source names to irContext accessors.
var (
	caseCtxUint64 = map[string]string{
		"head_slot":       "ictx.HeadSlot",
		"finalized_epoch": "ictx.FinalizedEpoch",
	}
	caseCtxBytes = map[string]string{
		"fork_digest":    "ictx.ForkDigest[:]",
		"finalized_root": "ictx.FinalizedRoot[:]",
		"head_root":      "ictx.HeadRoot[:]",
	}
)

func describeTransition(t *Transition) string {
	if t.Description != "" {
		return t.Description
	}
	return fmt.Sprintf("%s (%s -> %s)", t.Label, t.From, t.To)
}

func formatCaseSource(b *strings.Builder) (string, error) {
	formatted, err := format.Source([]byte(b.String()))
	if err != nil {
		return "", fmt.Errorf("gofmt generated source: %w\n--- source ---\n%s", err, b.String())
	}
	return string(formatted), nil
}
