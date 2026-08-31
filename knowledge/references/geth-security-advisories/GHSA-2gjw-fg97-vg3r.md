# GHSA-2gjw-fg97-vg3r: DoS via malicious p2p message

| Field | Value |
|---|---|
| GHSA | [GHSA-2gjw-fg97-vg3r](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-2gjw-fg97-vg3r) |
| CVE | CVE-2026-26314 |
| Severity | high |
| Published | 2026-02-17 |
| Updated | 2026-02-17 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: devp2p message
- Confidence: high
- Rationale: Node crash via a specially crafted p2p message.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `<= 1.16.8`, patched `>= 1.16.9`

## Description (verbatim from advisory)

### Impact

A vulnerable node can be forced to shutdown/crash using a specially crafted message.
More details to be released later.

### Patches

The problem is resolved in the v1.16.9 and v1.17.0 releases of Geth.

### Credit

This issue was reported to the Ethereum Foundation Bug Bounty Program by Waleed Ahmed from vulsight.com

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-2gjw-fg97-vg3r
