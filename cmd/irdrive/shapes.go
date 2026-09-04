package main

import (
	"regexp"
	"strings"
)

// gossipTopicRe recognizes a real gossip topic name: lowercase snake_case with at
// least one underscore. Real CL gossip topics (beacon_block, beacon_attestation,
// data_column_sidecar, ...) all match; spec-extraction noise bound as a topic —
// constants (MAXIMUM_GOSSIP_CLOCK_DISPARITY), type names (PartialDataColumnPartsMetadata),
// or the ENR key (eth2) — does not.
var gossipTopicRe = regexp.MustCompile(`^[a-z0-9]+(_[a-z0-9]+)+$`)

// isGossipTopic reports whether name is a plausible gossip topic, ignoring a
// trailing subnet template like "_{subnet_id}".
func isGossipTopic(name string) bool {
	if i := strings.IndexByte(name, '{'); i >= 0 {
		name = strings.TrimRight(name[:i], "_")
	}
	return gossipTopicRe.MatchString(name)
}

// shapes.go — Layer D0. Domain/shape vocabulary and the surface index. A rule is
// routed to exactly one domain; link.go (D0.5) resolves the domain+surface for
// rules whose binds_to is empty.

const (
	domGossip    = "gossip"
	domCrypto    = "cryptomsg"
	domReqResp   = "reqresp"
	domConn      = "conn"
	domDiscovery = "discovery"
	domNone      = "" // unresolved -> coverage gap
)

// connMethods are Req/Resp methods that belong to the connection-lifecycle
// machine (handshake + liveness) rather than the generic ReqResp machine.
var connMethods = map[string]bool{
	"status": true, "goodbye": true, "ping": true, "metadata": true,
}

// resolved is a rule bound to a concrete (domain, surface). protocolID is the
// normalized id for reqresp/conn (may be "" for a machine-level/backbone rule);
// topic is set for gossip.
type resolved struct {
	rule       *astRule
	domain     string
	topic      string
	protocolID string
	methodName string
	class      string // violation class (gossip rules); "" if unclassified/non-gossip
}

// surfaceIndex provides name/method lookup over AST surfaces.
type surfaceIndex struct {
	protocols []astSurface          // kind == protocol
	topics    map[string]bool       // topic name set
	byName    map[string]astSurface // lower(name) -> latest protocol surface
}

func newSurfaceIndex(surfaces []astSurface) *surfaceIndex {
	si := &surfaceIndex{topics: map[string]bool{}, byName: map[string]astSurface{}}
	for _, s := range surfaces {
		switch s.Kind {
		case "topic":
			si.topics[s.Name] = true
		case "protocol":
			si.protocols = append(si.protocols, s)
			key := strings.ToLower(s.Name)
			// Keep the highest version for a bare-name lookup.
			if prev, ok := si.byName[key]; !ok || s.Version > prev.Version {
				si.byName[key] = s
			}
		}
	}
	return si
}

// domainOfMethod routes a resolved protocol method to conn or reqresp.
func domainOfMethod(methodName string) string {
	if connMethods[strings.ToLower(methodName)] {
		return domConn
	}
	return domReqResp
}

// classifyBound routes a rule that already has binds_to set.
func classifyBound(r *astRule) (resolved, bool) {
	switch {
	case strings.HasPrefix(r.BindsTo, "topic:"):
		return resolved{rule: r, domain: domGossip, topic: strings.TrimPrefix(r.BindsTo, "topic:"), class: classify(r)}, true
	case strings.HasPrefix(r.BindsTo, "protocol:"):
		pid := strings.TrimPrefix(r.BindsTo, "protocol:")
		name, ver := methodFromProtocolID(pid)
		_ = ver
		return resolved{rule: r, domain: domainOfMethod(name), protocolID: pid, methodName: name}, true
	}
	return resolved{}, false
}

// methodFromProtocolID extracts (name-ish, version) from /eth2/.../<name>/<ver>/<enc>.
func methodFromProtocolID(pid string) (string, string) {
	parts := strings.Split(strings.Trim(pid, "/"), "/")
	// .../req/<name>/<ver>/<enc>
	for i := 0; i < len(parts); i++ {
		if parts[i] == "req" && i+1 < len(parts) {
			name := parts[i+1]
			ver := ""
			if i+2 < len(parts) {
				ver = parts[i+2]
			}
			return name, ver
		}
	}
	return "", ""
}
