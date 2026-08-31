# GHSA-mq3p-rrmp-79jg: DoS via malicious p2p message

| Field | Value |
|---|---|
| GHSA | [GHSA-mq3p-rrmp-79jg](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-mq3p-rrmp-79jg) |
| CVE | CVE-2026-22868 |
| Severity | medium |
| Published | 2026-01-13 |
| Updated | 2026-01-13 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: devp2p message
- Confidence: high
- Rationale: High CPU usage via a specially crafted p2p message.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `<= 1.16.7`, patched `>= 1.16.8`

## Description (verbatim from advisory)

**Impact**

An attacker can cause high CPU usage by sending a specially crafted p2p message.
More details to be released later.

**Credit**

This issue was reported to the Ethereum Foundation Bug Bounty Program by @Yenya030

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-mq3p-rrmp-79jg
