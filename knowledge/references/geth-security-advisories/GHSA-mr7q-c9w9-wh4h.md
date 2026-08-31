# GHSA-mr7q-c9w9-wh4h: DoS via malicious p2p message 

| Field | Value |
|---|---|
| GHSA | [GHSA-mr7q-c9w9-wh4h](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-mr7q-c9w9-wh4h) |
| CVE | CVE-2026-22862 |
| Severity | high |
| Published | 2026-01-13 |
| Updated | 2026-01-13 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: devp2p message
- Confidence: high
- Rationale: Node crash via a specially crafted p2p message.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `<= 1.16.7`, patched `>= 1.16.8`

## Description (verbatim from advisory)

**Impact**

A vulnerable node can be forced to shutdown/crash using a specially crafted message. 
More details to be released later.

**Credit**

This issue was reported to the Ethereum Foundation Bug Bounty Program by DELENE TCHIO ROMUALD.

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-mr7q-c9w9-wh4h
