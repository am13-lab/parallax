# GHSA-wjxw-gh3m-7pm5: DoS via malicious p2p message

| Field | Value |
|---|---|
| GHSA | [GHSA-wjxw-gh3m-7pm5](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-wjxw-gh3m-7pm5) |
| CVE | CVE-2022-29177 |
| Severity | low |
| Published | 2022-05-11 |
| Updated | 2022-05-11 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: devp2p message
- Confidence: high
- Rationale: Crash on a crafted p2p message when high-verbosity logging is enabled.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `< 1.10.17`, patched `>= 1.10.17`

## Description (verbatim from advisory)

### Impact

A vulnerable node, if configured to use high verbosity logging, can be made to crash when handling specially crafted p2p messages sent from an attacker node. 

### Patches

The following PR addresses the problem: https://github.com/ethereum/go-ethereum/pull/24507

### Workarounds

Aside from applying the PR linked above, setting loglevel to default level (`INFO`) makes the node not vulnerable to this attack.

### Credits

This bug was reported by `nrv` via bounty@ethereum.org, who has gracefully requested that the bounty rewards be donated to Médecins sans frontières.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [go-ethereum](https://github.com/ethereum/go-ethereum)

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-wjxw-gh3m-7pm5
