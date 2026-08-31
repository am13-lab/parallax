# GHSA-m6j8-rg6r-7mv8: Improper ECIES Public Key Validation in RLPx Handshake

| Field | Value |
|---|---|
| GHSA | [GHSA-m6j8-rg6r-7mv8](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-m6j8-rg6r-7mv8) |
| CVE | CVE-2026-26315 |
| Severity | medium |
| Published | 2026-02-17 |
| Updated | 2026-02-17 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: RLPx handshake
- Confidence: high
- Rationale: ECIES flaw in the RLPx handshake leaks bits of the p2p node key.

## Affected versions

- ``: vulnerable `<= 1.16.8`, patched `>= 1.16.9`

## Description (verbatim from advisory)

### Impact

Through a flaw in the ECIES cryptography implementation, an attacker may be able to extract bits of the p2p node key.

### Patches

The issue is resolved in the v1.16.9 and v1.17.0 releases of Geth. We recommend rotating the node key after applying the upgrade, which can be done by removing the file `<datadir>/geth/nodekey` before starting Geth.

### Credit

The issue was reported as a public pull request to go-ethereum by @fengjian.

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-m6j8-rg6r-7mv8
