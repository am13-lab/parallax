# GHSA-59hh-656j-3p7v: DoS via malicious snap/1 request

| Field | Value |
|---|---|
| GHSA | [GHSA-59hh-656j-3p7v](https://github.com/ethereum/go-ethereum/security/advisories/GHSA-59hh-656j-3p7v) |
| CVE | CVE-2021-41173 |
| Severity | medium |
| Published | 2021-10-25 |
| Updated | 2021-11-23 |
| CWE | none listed |

## Classification (ours)

- P2P-related: YES
- Protocol surface: snap/1
- Confidence: high
- Rationale: Malformed snap/1 GetTrieNodes request crashes the node.

## Affected versions

- `github.com/ethereum/go-ethereum`: vulnerable `< 1.10.9`, patched `>= 1.10.9`

## Description (verbatim from advisory)

### Impact

A vulnerable node is susceptible to crash when processing a maliciously crafted message from a peer, via the `snap/1` protocol. The crash can be triggered by sending a malicious `snap/1` `GetTrieNodes` package. 

### Details

On September 21, 2021, geth-team member Gary Rong (@rjl493456442) found a way to crash the snap request handler . 
By using this vulnerability, a peer connected on the `snap/1` protocol could cause a vulnerable node to crash with a `panic`.

In the `trie.TryGetNode` implementation, if the requested path is reached, the associated node will be returned. However the nilness is
not checked there.

```golang
func (t *Trie) tryGetNode(origNode node, path []byte, pos int) (item []byte, newnode node, resolved int, err error) {
	// If we reached the requested path, return the current node
	if pos >= len(path) {
		// Although we most probably have the original node expanded, encoding
		// that into consensus form can be nasty (needs to cascade down) and
		// time consuming. Instead, just pull the hash up from disk directly.
		var hash hashNode
		if node, ok := origNode.(hashNode); ok {
			hash = node
		} else {
			hash, _ = origNode.cache()
		}
```
More specifically the `origNode` can be nil(e.g. the child of fullnode) and system can panic at line `hash, _ = origNode.cache()`. 

When investigating this, @holiman tried to find it via fuzzing, which uncovered a second crasher, also related to the snap `GetTrieNodes` package. If the caller requests a storage trie:
```golang
				// Storage slots requested, open the storage trie and retrieve from there
				account, err := snap.Account(common.BytesToHash(pathset[0]))
				loads++ // always account database reads, even for failures
				if account == nil {
					break
				}
				stTrie, err := trie.NewSecure(common.BytesToHash(account.Root), triedb)
```
The code assumes that `snap.Account` returns _either_ a non-nil response unless `error` is also provided. This is however not the case, since `snap.Account` can return `nil, nil`. 

### Patches

```diff
--- a/eth/protocols/snap/handler.go
+++ b/eth/protocols/snap/handler.go
@@ -469,7 +469,7 @@ func handleMessage(backend Backend, peer *Peer) error {
 				// Storage slots requested, open the storage trie and retrieve from there
 				account, err := snap.Account(common.BytesToHash(pathset[0]))
 				loads++ // always account database reads, even for failures
-				if err != nil {
+				if err != nil || account == nil {
 					break
 				}
 				stTrie, err := trie.NewSecure(common.BytesToHash(account.Root), triedb)
diff --git a/trie/trie.go b/trie/trie.go
index 7ea7efa835..d0f0d4e2bc 100644
--- a/trie/trie.go
+++ b/trie/trie.go
@@ -174,6 +174,10 @@ func (t *Trie) TryGetNode(path []byte) ([]byte, int, error) {
 }
 
 func (t *Trie) tryGetNode(origNode node, path []byte, pos int) (item []byte, newnode node, resolved int, err error) {
+	// If non-existent path requested, abort
+	if origNode == nil {
+		return nil, nil, 0, nil
+	}
 	// If we reached the requested path, return the current node
 	if pos >= len(path) {
 		// Although we most probably have the original node expanded, encoding
@@ -193,10 +197,6 @@ func (t *Trie) tryGetNode(origNode node, path []byte, pos int) (item []byte, new
 	}
 	// Path still needs to be traversed, descend into children
 	switch n := (origNode).(type) {
-	case nil:
-		// Non-existent path requested, abort
-		return nil, nil, 0, nil
-
 	case valueNode:
 		// Path prematurely ended, abort
 		return nil, nil, 0, nil

``` 
The fixes were merged into [#23657](https://github.com/ethereum/go-ethereum/pull/23657), with commit [f1fd963](https://github.com/ethereum/go-ethereum/pull/23657/commits/f1fd963a5a965e643e52fcf805a2a02a323c32b8), and released as part of Geth [v1.10.9](https://github.com/ethereum/go-ethereum/tree/v1.10.9) on Sept 29, 2021. 

### Workarounds

Apply the patch above or upgrade to a version which is not vulnerable.

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [go-ethereum](https://github.com/ethereum/go-ethereum/)
* Email us at [security@ethereum.org](mailto:security@ethereum.org)

## References

- https://github.com/ethereum/go-ethereum/security/advisories/GHSA-59hh-656j-3p7v
