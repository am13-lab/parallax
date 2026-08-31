# GHSA-xw37-57qp-9mm4: Consensus flaw during block processing

| Field | Value |
|---|---|
| GHSA | [GHSA-xw37-57qp-9mm4](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-xw37-57qp-9mm4) |
| CVE | CVE-2020-26265 |
| Severity | high |
| Published | 2020-12-11 |
| Updated | 2021-03-25 |
| CWE | none listed |

## Classification (ours)

- P2P-related: NO
- Protocol surface: consensus/EVM
- Confidence: high
- Rationale: A particular transaction sequence causes a chain split during block processing.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `>= v1.9.4, < 1.9.20`, patched `>= 1.9.20`

## Description (verbatim from advisory)

### Impact

A consensus-vulnerability in Geth could cause a chain split, where vulnerable versions refuse to accept the canonical chain. 

### Description


A flaw was repoted at 2020-08-11 by John Youngseok Yang (Software Platform Lab), where a particular sequence of transactions could cause a consensus failure.

- Tx 1:
  - `sender` invokes `caller`.
  - `caller` invokes `0xaa`. `0xaa` has 3 wei, does a self-destruct-to-self
  - `caller` does a  `1 wei` -call to `0xaa`, who thereby has 1 wei (the code in `0xaa` still executed, since the tx is still ongoing, but doesn't redo the selfdestruct, it takes a different path if callvalue is non-zero)

- Tx 2:
  - `sender` does a 5-wei call to 0xaa. No exec (since no code). 

In geth, the result would be that `0xaa` had `6 wei`, whereas OE reported (correctly) `5` wei. Furthermore, in geth, if the second tx was not executed, the `0xaa` would be destructed, resulting in `0 wei`. Thus obviously wrong. 

It was determined that the root cause was this [commit](https://github.com/ethereum/go-ethereum/commit/223b950944f494a5b4e0957fd9f92c48b09037ad) from [this PR](https://github.com/ethereum/go-ethereum/pull/19953). The semantics of `createObject` was subtly changd, into returning a non-nil object (with `deleted=true`) where it previously did not if the account had been destructed. This return value caused the new object to inherit the old `balance`:

```golang
func (s *StateDB) CreateAccount(addr common.Address) {
	newObj, prev := s.createObject(addr)
	if prev != nil {
		newObj.setBalance(prev.data.Balance)
	}
}
```

It was determined that the minimal possible correct fix was

```diff
+++ b/core/state/statedb.go
@@ -589,7 +589,10 @@ func (s *StateDB) createObject(addr common.Address) (newobj, prev *stateObject)
                s.journal.append(resetObjectChange{prev: prev, prevdestruct: prevdestruct})
        }
        s.setStateObject(newobj)
-       return newobj, prev
+       if prev != nil && !prev.deleted {
+               return newobj, prev
+       }
+       return newobj, nil
```

### Patches

See above. The fix was included in Geth `v1.9.20` "Paragade".

### Workarounds

No individual workaround patches have been made -- all users are recommended to upgrade to a newer version.

### References


### Credits

The bug was found by @johnyangk and reported via bounty@ethereum.org.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [go-ethereum](https://github.com/ethereum/go-ethereum)
* Email us at [security@ethereum.org](mailto:security@ethereum.org)

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-xw37-57qp-9mm4
