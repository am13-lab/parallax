# knowledge/

The knowledge base that Parallax test cases trace back to. All content is
read-only reference data migrated from the previous p2p-testing repository.

- spec/: machine-readable consensus-spec P2P rules (534 entries parsed
  Phase0 through Gloas: spec_rules_generated.json is the catalog, with
  rule_ast.json, protocol_model.json, invariant_rules.json, test_overlay.json
  and the SPEC-* legacy map alongside).
- references/: audit and advisory material (Sigma Prime public-audits
  reference for CL-relevant findings, geth security advisories, P2P
  vulnerability patterns), plus references/index.json which anchors the
  external KnowledgeIDs used by test cases.
- known_divergences.json: the triage allowlist consumed by
  `parallax analyze --allowlist knowledge/known_divergences.json`.

Cases declare traceability through Metadata.KnowledgeIDs (external anchors:
SHERLOCK-*, RETH-*, CL-*, PROSE-*, GSR-*) and Metadata.SpecRules (slugs).
The parallax/knowledge package resolves KnowledgeIDs against this directory
and its coverage test fails on any dangling reference.
