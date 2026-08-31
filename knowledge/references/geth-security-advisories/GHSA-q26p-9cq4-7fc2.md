# GHSA-q26p-9cq4-7fc2: DoS via malicious p2p message

| Field | Value |
|---|---|
| GHSA | [GHSA-q26p-9cq4-7fc2](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-q26p-9cq4-7fc2) |
| CVE | CVE-2025-24883 |
| Severity | high |
| Published | 2025-01-30 |
| Updated | 2025-03-16 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: RLPx handshake
- Confidence: high
- Rationale: Invalid EC public key in the connection handshake crashes the node.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `>= 1.14.0, < 1.14.13`, patched `>= 1.14.13`

## Description (verbatim from advisory)

### Impact

A vulnerable node can be forced to shutdown/crash using a specially crafted message.

During the peer-to-peer connection handshake, a shared secret key is computed. The implementation
did not verify whether the EC public key provided by the remote party is a valid point on the secp256k1 curve.
By simply sending an all-zero public key, a crash could be induced due to unexpected results from the handshake.

The issue was fixed by adding a curve point validity check in https://github.com/ethereum/go-ethereum/commit/159fb1a1db551c544978dc16a5568a4730b4abf3

### Patches

A fix has been included in geth version 1.14.13 and onwards.

### Workarounds

Unfortunately, no workaround is available.

### Credits

This issue was originally reported to Polygon Security by David Matosse (@iam-ned).

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-q26p-9cq4-7fc2
