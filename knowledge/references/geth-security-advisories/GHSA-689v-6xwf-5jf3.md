# GHSA-689v-6xwf-5jf3: DoS via malicious p2p message

| Field | Value |
|---|---|
| GHSA | [GHSA-689v-6xwf-5jf3](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-689v-6xwf-5jf3) |
| CVE | CVE-2026-26313 |
| Severity | medium |
| Published | 2026-02-17 |
| Updated | 2026-02-17 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: devp2p message
- Confidence: high
- Rationale: High memory usage via a specially crafted p2p message.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `< 1.17.0`, patched `>= 1.17.0`

## Description (verbatim from advisory)

### Impact

An attacker can cause high memory usage by sending a specially-crafted p2p message.
More details to be released later.

### Patches

The issue is resolved in the v1.17.0 release. 

### Credit

This issue was reported to the Ethereum Foundation Bug Bounty Program by @revofusion

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-689v-6xwf-5jf3
