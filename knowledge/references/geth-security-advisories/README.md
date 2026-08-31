# go-ethereum security advisories: P2P attack-vector catalog

Catalog of every published GitHub Security Advisory for `ethereum/go-ethereum`, classified by
whether the vulnerability is exploitable over the peer-to-peer network. Built to back the paper's
claim that P2P is a primary attack vector for Ethereum clients.

Source: GitHub Security Advisories for go-ethereum, fetched 2026-08-06 via the GitHub REST API.
Reproduce with:

```
gh api /repos/ethereum/go-ethereum/security-advisories --paginate | jq '.'
```

Raw API dump is in `advisories.json`; one file per advisory is in `GHSA-*.md` (verbatim
description, dates, affected versions, references, and our classification).

Note on scope: go-ethereum is an execution-layer (EL) client. These advisories characterize the
EL client's attack surface, not the consensus-layer (CL) clients the paper tests. We label the
layer honestly; the P2P skew below is an EL data point, offered as supporting evidence for a
general "P2P is a primary attack vector" statement, not as a direct CL measurement.

## Classification methodology

An advisory is P2P-related if exploitation requires sending data over a peer-to-peer wire protocol
reachable by any connected peer: the RLPx transport/handshake, or a devp2p subprotocol (`eth/*`,
`snap/*`, `les/*`), or node discovery. It is not P2P-related if it is triggered through the
EVM/consensus path (a crafted transaction or block that the node processes) or through mining,
even when the impact is a crash or a chain split. One advisory is genuinely borderline (a Go
standard-library DoS not specific to geth's p2p code) and is counted separately.

## Summary statistics

- Total published advisories: 17
- P2P-related: 11 of 17 (65%)
- Not P2P-related (EVM / consensus / mining): 5 of 17 (29%)
- Borderline (Go runtime DoS, network-reachable but not a geth p2p bug): 1 of 17 (6%)

Recency skew: every go-ethereum advisory published since 2022 (9 of 9) is P2P-related. All of the
non-P2P advisories are 2020–2021 EVM/consensus/mining-era bugs.

By year (P2P-related / total):

| Year | P2P | Total |
|---|---|---|
| 2026 | 5 | 5 |
| 2025 | 1 | 1 |
| 2024 | 1 | 1 |
| 2023 | 1 | 1 |
| 2022 | 1 | 1 |
| 2021 | 1 | 2 |
| 2020 | 1 | 6 |

(The 2020 borderline Go-runtime advisory is excluded from the P2P column above; counting it would
make 2020 read 2/6.)

## Index

P2P? column: YES = exploitable over a p2p protocol; NO = EVM/consensus/mining; BORDER = borderline.

| GHSA | CVE | Severity | Published | Year | P2P? | Surface | Rationale |
|---|---|---|---|---|---|---|---|
| [GHSA-m6j8-rg6r-7mv8](GHSA-m6j8-rg6r-7mv8.md) | CVE-2026-26315 | medium | 2026-02-17 | 2026 | YES | RLPx handshake | ECIES flaw in RLPx handshake leaks node key bits |
| [GHSA-2gjw-fg97-vg3r](GHSA-2gjw-fg97-vg3r.md) | CVE-2026-26314 | high | 2026-02-17 | 2026 | YES | devp2p message | crash via crafted p2p message |
| [GHSA-689v-6xwf-5jf3](GHSA-689v-6xwf-5jf3.md) | CVE-2026-26313 | medium | 2026-02-17 | 2026 | YES | devp2p message | high memory via crafted p2p message |
| [GHSA-mq3p-rrmp-79jg](GHSA-mq3p-rrmp-79jg.md) | CVE-2026-22868 | medium | 2026-01-13 | 2026 | YES | devp2p message | high CPU via crafted p2p message |
| [GHSA-mr7q-c9w9-wh4h](GHSA-mr7q-c9w9-wh4h.md) | CVE-2026-22862 | high | 2026-01-13 | 2026 | YES | devp2p message | crash via crafted p2p message |
| [GHSA-q26p-9cq4-7fc2](GHSA-q26p-9cq4-7fc2.md) | CVE-2025-24883 | high | 2025-01-30 | 2025 | YES | RLPx handshake | invalid EC public key in handshake crashes node |
| [GHSA-4xc9-8hmq-j652](GHSA-4xc9-8hmq-j652.md) | CVE-2024-32972 | high | 2024-05-06 | 2024 | YES | eth/GetBlockHeaders | count=0 underflow bypasses maxHeadersServe → large memory |
| [GHSA-ppjg-v974-84cm](GHSA-ppjg-v974-84cm.md) | CVE-2023-40591 | high | 2023-09-06 | 2023 | YES | devp2p ping | ping handler spawns unbounded goroutines |
| [GHSA-wjxw-gh3m-7pm5](GHSA-wjxw-gh3m-7pm5.md) | CVE-2022-29177 | low | 2022-05-11 | 2022 | YES | devp2p message | crash on crafted message under high-verbosity logging |
| [GHSA-59hh-656j-3p7v](GHSA-59hh-656j-3p7v.md) | CVE-2021-41173 | medium | 2021-10-25 | 2021 | YES | snap/1 | malformed GetTrieNodes crash |
| [GHSA-r33q-22hv-j29q](GHSA-r33q-22hv-j29q.md) | CVE-2020-26264 | medium | 2020-12-11 | 2020 | YES | les | LES server crash via GetProofsV2 |
| [GHSA-m6gx-rhvj-fh52](GHSA-m6gx-rhvj-fh52.md) | CVE-2020-28362 | critical | 2020-11-24 | 2020 | BORDER | Go runtime | Go stdlib DoS (math/big); network-reachable but not a geth p2p bug |
| [GHSA-9856-9gg9-qcmq](GHSA-9856-9gg9-qcmq.md) | CVE-2021-39137 | high | 2021-08-24 | 2021 | NO | EVM | RETURNDATA/datacopy stateRoot divergence (tx-triggered) |
| [GHSA-xw37-57qp-9mm4](GHSA-xw37-57qp-9mm4.md) | CVE-2020-26265 | high | 2020-12-11 | 2020 | NO | consensus/EVM | tx-sequence chain split |
| [GHSA-jm5c-rv3w-w83m](GHSA-jm5c-rv3w-w83m.md) | CVE-2020-26242 | high | 2020-11-24 | 2020 | NO | EVM | MULMOD(_,_,0) panic during block processing |
| [GHSA-69v6-xc2j-r2jf](GHSA-69v6-xc2j-r2jf.md) | CVE-2020-26241 | high | 2020-11-24 | 2020 | NO | EVM | 0x4 precompile shallow copy → chain split |
| [GHSA-v592-xf75-856p](GHSA-v592-xf75-856p.md) | CVE-2020-26240 | medium | 2020-11-24 | 2020 | NO | mining/PoW | Ethash DAG generation bug (miners only) |

## Cross-reference with the project knowledge base

Four of these are already recorded in `../p2p-vulnerabilities.json` as EL transfer patterns
(`source_type: github_security_advisory`, `layer: EL`). This catalog does not modify that file;
it is a standalone, complete snapshot of all 17 advisories.

| GHSA | knowledge-base entry ID |
|---|---|
| GHSA-ppjg-v974-84cm | EL-GETH-GHSA-ppjg-v974-84cm |
| GHSA-4xc9-8hmq-j652 | EL-GETH-GHSA-4xc9-8hmq-j652 |
| GHSA-59hh-656j-3p7v | EL-GETH-GHSA-59hh-656j-3p7v |
| GHSA-q26p-9cq4-7fc2 | EL-GETH-GHSA-q26p-9cq4-7fc2 |
