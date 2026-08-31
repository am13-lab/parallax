# GHSA-r33q-22hv-j29q: LES Server DoS via GetProofsV2

| Field | Value |
|---|---|
| GHSA | [GHSA-r33q-22hv-j29q](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-r33q-22hv-j29q) |
| CVE | CVE-2020-26264 |
| Severity | medium |
| Published | 2020-12-11 |
| Updated | 2020-12-11 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: les
- Confidence: high
- Rationale: LES server crash via a malicious GetProofsV2 request from a connected LES client.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `< 1.9.25`, patched `>= 1.9.25`

## Description (verbatim from advisory)

### Impact

A DoS vulnerability can make a LES server crash via malicious `GetProofsV2` request from a connected LES client.

### Patches

The vulnerability was patched in https://github.com/ethereum/go-ethereum/pull/21896. 

### Workarounds

This vulnerability only concerns users explicitly enabling `les` server; disabling `les` prevents the exploit. 
It can also be patched by manually applying the patch in https://github.com/ethereum/go-ethereum/pull/21896. 


### For more information
If you have any questions or comments about this advisory:
* Open an issue in [go-ethereum](https://github.com/ethereum/go-ethereum)
* Email us at [security@ethereum.org](mailto:security@ethereum.org)

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-r33q-22hv-j29q
