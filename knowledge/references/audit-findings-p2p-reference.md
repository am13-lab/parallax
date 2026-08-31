# P2P Audit Findings Reference for Differential Testing

**Generated**: 2026-04-01

**Source**: [Sigma Prime public-audits](../public-audits/) repository

**Target**: Ethereum CL P2P differential testing (Prysm, Lighthouse, Teku, Nimbus, Lodestar)

---

## Executive Summary

This document catalogs P2P networking vulnerabilities found across Sigma Prime audit reports and maps them to actionable test cases for Ethereum consensus layer P2P differential testing. The findings come from audits of:

| Report | Target | Protocol Layer | P2P Findings | Relevance |
|--------|--------|---------------|-------------|-----------|
| **Reth** | Ethereum EL client (Rust) | devp2p, discv4, ECIES, RLPx | ~25 | **HIGH** |
| **Chainsafe Forest** | Filecoin client (Rust) | GossipSub, libp2p | 3 | **HIGH** |
| **Chainsafe Gossamer** | Polkadot Host (Go) | SCALE decoding, consensus msgs | 2 | **MEDIUM** |
| **Obol Charon** | DVT middleware (Go) | libp2p, ENR, RLP, QBFT | 5 | **MEDIUM** |
| **Filecoin Drand** | Randomness beacon (Go) | gRPC/libp2p broadcast | 3 | **MEDIUM** |

While EL clients use devp2p and CL clients use libp2p, the underlying **bug patterns** transfer directly: missing timeouts, unbounded allocations, encoding edge cases, discovery manipulation, message replay, and peer scoring bypass.

---

## 1. Discovery Layer

### 1.1 DHT / Neighbor Response Leaks

**Source**: RETH-06 (High) — `respond_closest()` Shares All Neighbours

- **Bug**: Discovery response returns entire local DHT instead of the 16 closest nodes. Missing `take()` on iterator causes all routing table entries to be sent.
- **Impact**: Information leakage of full peer table; receiving nodes reject oversized responses, breaking discovery.
- **CL Analog**: CL clients use discv5 (not discv4), but the same pattern applies — verify that `FIND_NODE` responses in discv5 are bounded to the correct number of entries (16 per NODES response).

**Suggested Test Cases**:
- Send `FIND_NODE` to each CL client and verify response contains at most 16 ENR records per NODES packet
- Inject oversized NODES responses (17+ records) and verify clients reject them
- Compare how each client handles NODES responses at exactly the boundary (15, 16, 17 records)

### 1.2 PING Flood / Unbounded Queue DoS

**Source**: RETH-11 (Medium) — Denial-of-Service Through PING Spamming

- **Bug**: Unbounded `queued_pings` vector grows indefinitely when max pending PINGs is reached. Each incoming PING from a new node triggers a PONG + outgoing PING. With bucket insert failures (TooManyIncoming), the outgoing PING queue grows without limit.
- **Impact**: OOM crash; valid PINGs starved until queue is drained.
- **CL Analog**: discv5 PING/PONG in CL clients. Test whether CL clients have rate limits on discovery PING processing.

**Suggested Test Cases**:
- Flood each CL client's discv5 port with PING messages from many spoofed node IDs
- Measure memory growth over time during sustained PING flood
- Verify that legitimate PING/PONG exchanges still work under flood conditions
- Test with varying rates: 100/s, 1000/s, 10000/s from a single source

### 1.3 Endpoint Proof Bypass in FIND_NODE

**Source**: RETH-12 (Medium) — `find_node` Called Without Valid Endpoint

- **Bug**: `find_node()` called for nodes without validated endpoint proof. A node that sent PING but not PONG gets added to DHT, then `on_neighbours()` iterates all entries including unproven ones.
- **Impact**: Discovery messages sent to unvalidated endpoints; potential for directing traffic to arbitrary IPs.
- **CL Analog**: discv5 uses a different handshake model (WHOAREYOU), but similar patterns may exist — verify that CL clients only query nodes with completed handshakes.

**Suggested Test Cases**:
- Initiate partial discv5 handshake (send but don't complete WHOAREYOU) and check if node is used in routing
- Test whether incompletely-handshaked nodes appear in FIND_NODE responses

### 1.4 Incorrect Expiration Handling

**Source**: RETH-22 (Low) — Incorrect Expiration for ENR/Lookup Requests

- **Bug**: All pending request types (ENR, lookup, ping) use PING expiration timeout instead of type-specific expirations.
- **CL Analog**: Verify CL discv5 implementations use correct per-request-type timeouts.

**Suggested Test Cases**:
- Send discv5 requests and delay responses by varying amounts to probe timeout boundaries
- Compare timeout behavior across clients for FIND_NODE, PING, and TALK_REQ

### 1.5 Missing Field Skipping in Message Decoding

**Source**: RETH-23 (Low, Open) — Missing Fields Should Be Skipped

- **Bug**: Discv4 message types (FindNode, Neighbours, EnrRequest) don't skip additional list elements during decoding, violating the EIP-8 forward-compatibility requirement. Same issue in RLPx handshake and Hello messages.
- **CL Analog**: SSZ is generally fixed-schema, but test how CL clients handle SSZ containers with unexpected extra fields or messages with trailing bytes.

**Suggested Test Cases**:
- Append extra bytes after valid SSZ-encoded req/resp messages and verify client behavior
- Send Status messages with extra fields appended after the SSZ payload
- Compare ACCEPT/REJECT behavior across clients for messages with trailing data

### 1.6 ENR Response Validation

**Source**: RETH-42 (Informational) — ENR Responses Are Not Validated

- **Bug**: ENR response `msg.enr` is not validated (signature not checked against response signer). Spec requires verifying the node record is signed by the same public key that signed the response.
- **CL Analog**: Verify CL discv5 implementations validate ENR signatures in responses.

**Suggested Test Cases**:
- Send ENR responses with mismatched signatures (ENR signed by key A, response packet signed by key B)
- Send ENR responses with invalid signatures
- Send ENR responses with ENR `seq` = 0 or very high sequence numbers
- Cross-client comparison of ENR validation strictness

### 1.7 Eclipse Attack Resistance

**Source**: RETH-43 (Informational, Open) — Eclipse Mitigations

- **Bug**: Missing IP-per-bucket limits and subnet diversity requirements in routing table. Attacker pre-generates node IDs to fill first ~10 routing table buckets with malicious entries, controlling all new peer discoveries.
- **CL Analog**: CL clients should have similar protections. Lighthouse uses IP limits per bucket and subnet limits.

**Suggested Test Cases**:
- Generate many node IDs targeting specific bucket positions and attempt to fill a client's routing table
- Verify per-bucket IP limits and subnet diversity across all CL clients
- Measure how many attacker-controlled nodes are needed to eclipse each client
- Compare routing table eviction policies across clients

### 1.8 PING/PONG Man-in-the-Middle

**Source**: RETH-39 (Informational) — PING/PONG MitM

- **Bug**: Lack of validation on `Ping.to`, `Ping.from`, `Pong.to` fields. PING/PONG messages are replayable until expiry. Mallory can forward Alice's PING to Bob, making Bob register Mallory's IP with Alice's node ID.
- **CL Analog**: discv5 uses different handshake (WHOAREYOU nonces), but verify that CL clients validate source addresses and don't allow MitM on the handshake.

**Suggested Test Cases**:
- Attempt to relay discv5 handshake messages between two clients through an intermediary
- Verify that identity claims match the transport-level source address
- Test whether replaying captured WHOAREYOU responses is possible

### 1.9 Duplicate ENR Keys

**Source**: OBOL-14 (Low) — Duplicate Keys Allowed in ENR

- **Bug**: ENR records with duplicate keys are accepted. The spec states keys must be unique.
- **CL Analog**: All CL clients parse ENR records. Duplicate keys could cause inconsistent behavior.

**Suggested Test Cases**:
- Craft ENR records with duplicate keys (e.g., two `ip` entries with different values)
- Verify each CL client's behavior: reject, use first, use last
- Differential test: compare which key value each client uses

---

## 2. GossipSub / Message Propagation

### 2.1 Disabled Peer Scoring Parameters

**Source**: FOR-08 (High) — Disabled Gossipsub Scoring Parameters (Forest)

- **Bug**: All GossipSub v1.1 scoring parameters disabled, leaving the node vulnerable to all known GossipSub v1.0 attacks (Sybil flooding, eclipse via mesh manipulation, amplification attacks).
- **CL Analog**: Verify all CL clients have scoring enabled and properly configured per the Ethereum spec.

**Suggested Test Cases**:
- Query each client's GossipSub scoring configuration via debug APIs
- Send invalid messages and verify peer score decreases
- Attempt to stay in the mesh while sending invalid messages — compare scoring thresholds across clients
- Test whether a peer that sends N invalid messages gets disconnected (and at what N)

### 2.2 Incorrect message_id Function

**Source**: FOR-11 (Medium) — Incorrect `message_id` in Gossipsub (Forest)

- **Bug**: Non-standard `message_id` function causes constant IHAVE/IWANT re-requests (massive bandwidth amplification) and peer scoring penalties.
- **CL Analog**: Ethereum CL spec defines message_id as `SHA256(MESSAGE_DOMAIN_VALID_SNAPPY + snappy_decompress(message.data))[:20]` for Altair+. Verify all clients implement the same function.

**Suggested Test Cases**:
- Publish the same message from two peers and verify all clients compute the same message_id
- Compare message_id computation for: Phase0 messages (first 8 bytes of SHA256), Altair+ messages (first 20 bytes with domain prefix)
- Inject messages with valid content but manipulated in ways that might cause message_id divergence
- Monitor IHAVE/IWANT traffic between mixed-client pairs for duplicate message requests

### 2.3 Valid Signature Replay / Flood DoS

**Source**: RND-01 (High) — Partial Signature Rebroadcast DoS (Drand)

- **Bug**: Valid signed messages can be replayed/flooded to consume memory and CPU. The system doesn't deduplicate by (round, sender) and doesn't drop messages for already-completed rounds.
- **CL Analog**: CL GossipSub messages (attestations, blocks) have deduplication via message_id and seen caches. But test edge cases:

**Suggested Test Cases**:
- Replay valid attestations that have already been seen — verify all clients deduplicate correctly
- Flood attestations for old/already-finalized slots — verify clients drop them before expensive validation
- Send many distinct but valid attestations from the same validator in the same slot (equivocation) — compare how each client handles the flood
- Measure memory growth under sustained message replay

### 2.4 Broadcast Ordering Inconsistency

**Source**: RND-09 (Low) — Broadcast Assumption Does Not Guarantee Packet Order (Drand)

- **Bug**: Messages arriving out of order across nodes cause inconsistent state (some nodes process a message, others don't because they received it in a different phase).
- **CL Analog**: CL clients may handle attestations/blocks that arrive out of order differently. E.g., an attestation for a block that hasn't been received yet.

**Suggested Test Cases**:
- Send an attestation for a block before the block itself — compare handling across clients
- Send a data_column_sidecar before its parent block — compare IGNORE vs REJECT behavior
- Reorder gossip messages within a slot and measure propagation differences

### 2.5 QBFT Consensus Message Replay

**Source**: OBOL-07 (High) — QBFT Consensus Allows Replay of Justification Messages

- **Bug**: Justification messages in QBFT consensus can be replayed across rounds, allowing manipulation of the consensus process.
- **CL Analog**: While CL clients don't use QBFT, the pattern of message replay across epochs/slots is testable.

**Suggested Test Cases**:
- Replay attestations from epoch N in epoch N+1 — verify all clients reject based on slot/epoch checks
- Replay beacon blocks with stale slot numbers
- Send sync committee messages from previous sync periods

---

## 3. Req/Resp Protocol

### 3.1 RLP/Encoding Header Validation

**Source**: RETH-33 (Low) — RLP Header Not Validated in RequestPair Decoding
**Source**: RETH-34 (Low) — RLP Header Not Validated in DisconnectReason

- **Bug**: Decoded RLP headers are discarded without checking `payload_length`, allowing reads past the end of the encoding. In DisconnectReason, empty payload (`payload_length = 0`) is followed by reading the next byte outside the payload.
- **CL Analog**: CL uses SSZ+snappy encoding. Test for similar issues: what happens when the SSZ length prefix doesn't match actual payload length?

**Suggested Test Cases**:
- Send req/resp messages where the SSZ length varint claims more bytes than provided
- Send req/resp messages where the SSZ length varint claims fewer bytes than provided (trailing data)
- Send messages with length varint = 0 followed by non-empty data
- Send messages where snappy-decompressed size doesn't match the SSZ container size
- Compare error responses (INVALID_REQUEST vs connection drop vs timeout) across clients

### 3.2 Empty Message Handling

**Source**: RETH-35 (Low) — Index Out Of Bounds When Sending Empty Bytes
**Source**: RETH-36 (Low) — Index Out Of Bounds When Multiplex Message Is Empty

- **Bug**: Sending zero-length P2P messages causes arithmetic overflow (`item.len() - 1`) and index out of bounds panics (`msg[0]`).
- **CL Analog**: CL req/resp messages start with a response code byte. Test zero-length messages.

**Suggested Test Cases**:
- Send completely empty request bodies (0 bytes) for each req/resp method (Ping, Status, MetaData, etc.)
- Send a response frame with 0 bytes (no response code, no payload)
- Send a stream with only the response code byte (1 byte, no payload)
- Compare: crash, error response, timeout, or graceful close

### 3.3 Arithmetic Overflow in Message Size Calculations

**Source**: RETH-29 (Low) — Arithmetic Overflow in `decrypt_message()`
**Source**: RETH-30 (Low) — Arithmetic Overflow in `read_body()`
**Source**: RETH-37 (Low) — Arithmetic Overflows in ProtocolStream

- **Bug**: Subtraction underflow when message is shorter than expected header/MAC size. `encrypted.len() - 32` overflows when `encrypted.len() < 32`.
- **CL Analog**: CL snappy framing has similar length calculations. Test messages at exact boundary sizes.

**Suggested Test Cases**:
- Send snappy-compressed frames with decompressed size at exact SSZ container boundaries
- Send req/resp messages with payload sizes: 0, 1, minimum_valid-1, minimum_valid, maximum_valid, maximum_valid+1
- Test `BeaconBlocksByRange` with `count = 0`, `step = 0`, `start_slot = MAX_UINT64`
- Test `DataColumnSidecarsByRange` with boundary values for `start_slot`, `count`

---

## 4. Transport Layer

### 4.1 Handshake Timeout Abuse

**Source**: RETH-07 (High) — Lack of Timeout in EthStream Handshake

- **Bug**: No timeout waiting for Status reply during EthStream handshake. Attacker opens many connections, performs handshake up to the Status message, then never sends it. Each thread blocks indefinitely. Same bug in ECIES handshake (`transport.try_next().await` with no timeout).
- **CL Analog**: CL uses Noise protocol handshake + Status req/resp. Test whether clients have timeouts at each stage.

**Suggested Test Cases**:
- Connect via TCP, complete Noise handshake, but never send Status request — measure when client drops connection
- Complete Noise handshake, send Status request, but never read the response — measure timeout
- Open many (100, 500, 1000) connections that stall at different handshake stages — measure resource exhaustion
- Compare timeout values across clients (should be RESP_TIMEOUT = 10s per spec)

### 4.2 Connection DoS via Invalid Packets

**Source**: RETH-25 (Low, Open) — Connection DoS via Invalid TCP Packets

- **Bug**: Injecting TCP packets with predicted sequence numbers and garbage body causes the stream to decode the garbage as a header, fail MAC check, and close the connection. RLPx connections cannot be re-established once closed this way.
- **CL Analog**: CL uses Noise-encrypted TCP/QUIC streams. The encryption provides better protection, but test how clients handle corrupted encrypted frames.

**Suggested Test Cases**:
- Send random bytes on an established libp2p connection after the Noise handshake
- Send truncated Noise frames (valid header, truncated payload)
- Send oversized Noise frames exceeding MAX_CHUNK_SIZE
- Compare: does the client close just the stream, the connection, or ban the peer?

### 4.3 UDP Flood on Discovery Port

**Source**: RETH-27 (Low) — DoS Through UDP Spamming

- **Bug**: UDP spam fills the ingress channel buffer, blocking `receive_loop()`. While blocked, the OS socket fills and drops legitimate packets. Forged source IP makes rate limiting ineffective.
- **CL Analog**: CL discv5 uses UDP. Same attack vector applies.

**Suggested Test Cases**:
- Flood each client's discv5 UDP port with random packets at increasing rates
- Measure at what packet rate legitimate discv5 operations (FIND_NODE, PING) start failing
- Test with forged source IPs to evaluate rate-limiting effectiveness
- Compare discovery recovery time after flood stops

### 4.4 ECIES / Noise Protocol Edge Cases

**Source**: RETH-44 (Informational, Open) — ECIES Protocol Bugs

- **Bug**: Three ECIES issues: (1) forgeable signatures via attacker-chosen message hash, (2) auth handshake completion without knowledge of private key (~50% success with random sig), (3) Auth/Ack packets replayable (no expiry).
- **CL Analog**: CL uses Noise XX protocol which has better security properties, but test edge cases.

**Suggested Test Cases**:
- Attempt Noise handshake with random/invalid static keys — verify all clients reject
- Replay captured Noise handshake messages to different peers
- Attempt to complete Noise handshake with incorrect ephemeral keys
- Send valid Noise handshake but with mismatched peer ID in the payload

### 4.5 Multiplexer Error Handling

**Source**: RETH-13 (Medium) — Multiplexer Ignores Errors from P2PStream

- **Bug**: When `poll_ready()` returns an error, it's treated the same as `Ok(())` — messages continue to be sent on a broken stream.
- **CL Analog**: CL uses libp2p multiplexing (yamux/mplex). Test behavior when one stream errors.

**Suggested Test Cases**:
- Open multiple simultaneous streams (Status + BlocksByRange) and abruptly close one — verify the other continues
- Send invalid data on one stream and verify other streams on the same connection aren't affected
- Reset a stream mid-transfer and verify the peer handles it gracefully

### 4.6 Sub-Protocol Message Ordering

**Source**: RETH-14 (Medium) — Sub Protocol Messages Dropped During Handshake

- **Bug**: Messages for non-primary protocols received during the primary protocol handshake are silently dropped because handlers aren't installed yet.
- **CL Analog**: CL multiplexes multiple protocols (req/resp, gossip, identify). Test message ordering during connection setup.

**Suggested Test Cases**:
- Immediately send a Ping request before Status handshake completes — compare handling
- Send GossipSub SUBSCRIBE messages before the libp2p identify exchange completes
- Compare whether clients buffer, drop, or error on pre-handshake protocol messages

---

## 5. Message Decoding / Serialization

### 5.1 Length-Prefixed Decoding OOM

**Source**: GSR-06 (Critical) — DoS via Decoding of Malicious Messages (Gossamer)

- **Bug**: SCALE messages with enormous length prefixes cause `make([]byte, length)` to allocate excessive memory, triggering OOM crash. Affects BlockAnnounce, VersionData, and other broadcast message types. Random data is likely to trigger this.
- **CL Analog**: CL uses SSZ with explicit length limits, but the snappy decompression layer and SSZ varint parsing could have similar issues.

**Suggested Test Cases**:
- Send req/resp messages with SSZ length varint encoding `MAX_UINT64` or very large values
- Send snappy-compressed data that claims to decompress to enormous sizes
- Craft SSZ containers with List/Vector length fields set to `2^32 - 1`
- Compare: OOM, error response, or graceful rejection across clients

### 5.2 ECIES KDF / Crypto Edge Cases

**Source**: RETH-28 (Low) — Index Out Of Bounds in `kdf()`
**Source**: RETH-32 (Low) — `read_header()` OOB if Input < 32 Bytes

- **Bug**: Cryptographic utility functions panic on inputs shorter than expected. `kdf()` panics if dest length is not a multiple of 32. `read_header()` panics if input < 32 bytes.
- **CL Analog**: CL Noise protocol implementation has similar crypto utility functions. Test with truncated messages.

**Suggested Test Cases**:
- Send Noise handshake messages truncated at every byte position (1 byte through N bytes)
- Send encrypted frames with headers shorter than the minimum expected size
- Fuzz the Noise frame parser with random byte sequences

### 5.3 RLP Length in Bits vs Bytes

**Source**: OBOL-13 (Low) — RLP Length in Bits Rather Than Bytes

- **Bug**: RLP length field interpreted as bits instead of bytes, causing 8x size discrepancy.
- **CL Analog**: While CL uses SSZ not RLP, analogous confusion between units (bytes/bits, slots/epochs) in length calculations is a general bug pattern.

**Suggested Test Cases**:
- Send SSZ containers where variable-length fields are exactly at `MAX_CHUNK_SIZE / 8` and `MAX_CHUNK_SIZE` boundaries
- Test data column requests with counts at exactly `NUMBER_OF_COLUMNS` and `NUMBER_OF_COLUMNS * 8`

---

## 6. Resource Exhaustion

### 6.1 Unbounded Channels / Queues

**Source**: RETH-24 (Low) — Unbounded Channels

- **Bug**: Unbounded mpsc channels for consensus events and event listeners. During congestion, events accumulate faster than processed, leading to OOM.
- **CL Analog**: CL clients have similar internal channel architectures. Test by overwhelming the client with valid but high-volume traffic.

**Suggested Test Cases**:
- Send maximum-rate valid attestations to each client for extended periods (minutes)
- Monitor memory growth of each client under sustained gossip load
- Compare client behavior when gossip backpressure builds: drop messages, slow down, or crash

### 6.2 Consensus Message Tracker Flood

**Source**: GSR-05 (Critical) — Insufficient Garbage Collection for GRANDPA Message Tracker (Gossamer)

- **Bug**: Vote messages with rounds much higher than current round are stored indefinitely in a tracker. Attacker sends votes with different high round numbers (uint64 gives ~2^64 different rounds) referencing non-existent block hashes, growing memory indefinitely.
- **CL Analog**: CL clients cache various message types (attestations for future slots, blocks for unknown parents). Test cache limits.

**Suggested Test Cases**:
- Send attestations referencing far-future slots (current_slot + 1000, +10000, +100000)
- Send beacon blocks for slots far in the future
- Monitor whether clients bound their future-message caches
- Differential comparison of cache eviction policies across clients

---

## 7. Cross-Reference: Existing p2p-testing Coverage

| Audit Finding Pattern | p2p-testing Category | Existing Coverage | Gap |
|-----------------------|---------------------|-------------------|-----|
| Discovery neighbor bounds | `discovery/` | `enr_structure.go` — ENR validation | Missing: response count bounds |
| PING flood DoS | `discovery/` | `peer_discovery.go` — basic probes | Missing: flood/rate-limit tests |
| ENR validation | `discovery/` | `enr_structure.go`, `enr_consistency.go` | Partial: signature validation present |
| Eclipse resistance | `discovery/` | Not covered | **Gap**: bucket diversity tests |
| GossipSub scoring | `gossipsub/` | `scoring.go` — peer scoring tests | Partial: could add more invalid msg patterns |
| Message_id consistency | `gossipsub/` | `topics.go` — topic tests | Missing: message_id divergence tests |
| Message replay/dedup | `gossipsub/` | `malformed.go` — malformed messages | Missing: replay of valid messages |
| Req/resp encoding edge cases | `reqresp/` | `malformed.go`, `valid.go` | Partial: add zero-length, trailing bytes |
| Req/resp boundary values | `reqresp/` | `exhaustion.go` — resource exhaustion | Partial: add exact boundary sizes |
| Handshake timeout abuse | `transport/` | `libp2p_peer.go` — peer connections | Missing: stalled handshake tests |
| Empty/truncated frames | `transport/` | `encoding.go` — encoding tests | Partial: add zero-length frames |
| Noise protocol edge cases | `transport/` | `libp2p_peer.go` | Missing: handshake fuzzing |
| Length-bomb OOM | `transport/` | `encoding.go` | Missing: oversized length prefix |
| Unbounded resource growth | `statemachine/` | `peerscoring.go` — decay/scoring | Missing: sustained load tests |

---

## 8. Priority Test Ideas (Ranked by Impact)

### P0 — High impact, likely to find bugs

1. **Stalled handshake resource exhaustion**: Open 100+ connections that complete Noise but never send Status. Measure fd/memory/goroutine exhaustion per client.
2. **SSZ length bomb via req/resp**: Send `BeaconBlocksByRange` responses with snappy frames claiming enormous decompressed size. Test for OOM/panic.
3. **Future-slot message cache exhaustion**: Flood attestations for `current_slot + 100000`. Monitor memory growth.
4. **GossipSub message_id differential**: Publish identical content to two clients and compare computed message_ids. Any divergence = bandwidth amplification.
5. **Discovery UDP flood**: Flood discv5 port and measure legitimate request success rate degradation.

### P1 — Medium impact, good for coverage

6. **Zero-length req/resp bodies**: Empty request for every method. Compare crash/error/timeout behavior.
7. **Trailing bytes after valid SSZ**: Append random bytes after valid payloads. Compare ACCEPT/REJECT.
8. **ENR duplicate keys**: Craft ENRs with duplicate `ip`, `tcp`, `udp` keys. Compare parsed values.
9. **Eclipse resistance**: Attempt to fill routing table buckets with attacker-controlled nodes.
10. **Req/resp at exact boundary sizes**: `MAX_CHUNK_SIZE`, `MAX_REQUEST_BLOCKS`, etc.

### P2 — Lower impact, good for completeness

11. **discv5 PING/PONG replay**: Replay captured handshake messages to test anti-replay.
12. **Invalid Noise handshake**: Random keys, mismatched peer IDs, truncated handshake messages.
13. **Stream multiplexing interference**: Error one stream, verify others unaffected.
14. **Scoring threshold differential**: Send N invalid messages and find exact disconnect threshold per client.
15. **Out-of-order gossip**: Send attestations before their referenced block.

---

## 9. Source Reports

| Report | Path | Pages |
|--------|------|-------|
| Reth — Ethereum EL Client | `reports/reth/review.pdf` | 86 |
| Chainsafe Forest — Filecoin Client | `reports/chainsafe/forest/review.pdf` | 36 |
| Chainsafe Gossamer — Polkadot Host | `reports/chainsafe/gossamer/review.pdf` | 43 |
| Obol Charon — DVT Client | `reports/obol/Sigma_Prime_Obol_Network_Charon_Security_Assessment_Report_v2_1.pdf` | 43 |
| Filecoin Drand — Randomness Beacon | `reports/filecoin/filecoin-drand/review.pdf` | 56 |
| EF Pectra — System Contracts | `reports/ethereum-foundation/pectra/review.pdf` | 17 (no P2P) |

All paths are relative to the `public-audits/` repository root.
