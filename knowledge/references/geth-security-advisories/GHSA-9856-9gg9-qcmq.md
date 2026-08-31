# GHSA-9856-9gg9-qcmq: RETURNDATA corruption via datacopy

| Field | Value |
|---|---|
| GHSA | [GHSA-9856-9gg9-qcmq](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-9856-9gg9-qcmq) |
| CVE | CVE-2021-39137 |
| Severity | high |
| Published | 2021-08-24 |
| Updated | 2021-09-07 |
| CWE | none listed |

## Classification (ours)

- P2P-related: NO
- Protocol surface: EVM
- Confidence: high
- Rationale: RETURNDATA/datacopy memory corruption yields a divergent stateRoot; triggered by a crafted transaction, not a p2p message.

## Affected versions

- `go-ethereum`: vulnerable `>= 1.10.0, < 1.10.8`, patched `>= 1.10.8`

## Description (verbatim from advisory)

### Impact

A vulnerability in the Geth EVM could cause a node to reject the canonical chain. 

### Description 

A memory-corruption bug within the EVM can cause a consensus error, where vulnerable nodes obtain a different `stateRoot` when processing a maliciously crafted transaction. This, in turn, would lead to the chain being split in two forks.

All Geth versions supporting the London hard fork are vulnerable (which predates London), so all users should update.

This bug was exploited on Mainnet at block 13107518, leading to a minority chain split. 

### Patches

A patch is included in the `v1.10.8` release.
The exact patch to fix the issue is contained within this [commit](https://github.com/ethereum/go-ethereum/pull/23381/commits/4d4879cafd1b3c906fc184a8c4a357137465128f)

### Workarounds

No workarounds exist, save to update and/or apply the patch commit. 

### References. 

Post-mortem [write-up](https://github.com/ethereum/go-ethereum/blob/master/docs/postmortems/2021-08-22-split-postmortem.md).

### Credits

The bug was found by @guidovranken (working for [Sentnl](https://sentnl.io/) during an audit of the [Telos EVM](https://www.telos.net/evm)) and reported via bounty@ethereum.org.

### For more information
If you have any questions or comments about this advisory:

* Open an issue in [go-ethereum](https://github.com/ethereum/go-ethereum/)
* Email us at [security@ethereum.org](mailto:security@ethereum.org)

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-9856-9gg9-qcmq
