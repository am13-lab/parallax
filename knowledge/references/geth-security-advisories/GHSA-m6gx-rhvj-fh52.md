# GHSA-m6gx-rhvj-fh52: Denial of service due to Go CVE-2020-28362

| Field | Value |
|---|---|
| GHSA | [GHSA-m6gx-rhvj-fh52](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-m6gx-rhvj-fh52) |
| CVE | CVE-2020-28362 |
| Severity | critical |
| Published | 2020-11-24 |
| Updated | 2020-11-24 |
| CWE | none listed |

## Classification (ours)

- P2P-related: BORDERLINE
- Protocol surface: Go runtime
- Confidence: low
- Rationale: Underlying Go stdlib DoS (CVE-2020-28362, math/big). Network-reachable in general, but not a geth-specific p2p protocol bug.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `< 1.9.24`, patched `>= 1.9.24`

## Description (verbatim from advisory)

### Impact
Versions of Geth built with Go `<1.15.5` or `<1.14.12` are most likely affected by a critical DoS-related security vulnerability. The golang team has registered the underlying flaw as ‘CVE-2020-28362’.

We recommend all users to rebuild (ideally `v1.9.24`) with Go `1.15.5` or `1.14.12`, to avoid node crashes. Alternatively, if you are running binaries distributed via one of our official channels, we’re going to release `v1.9.24` ourselves built with Go `1.15.5`.

### Patches
This is not an issue in go-ethereum, rebuilding an older version with Go `1.15.5` or `1.14.12` will suffice to address the vulnerability. 

### Workarounds
Rebuilding with Go `1.15.5` or `1.14.12` will suffice to address the vulnerability. 

### References
- https://blog.ethereum.org/2020/11/12/geth_security_release/
- https://groups.google.com/g/golang-announce/c/NpBGTTmKzpM

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [go-ethereum](https://github.com/ethereum/go-ethereum)
* Email us at [security@ethereum.org](mailto:security@ethereum.org)

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-m6gx-rhvj-fh52
