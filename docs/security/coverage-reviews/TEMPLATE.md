# Source coverage policy review

A coverage review authorizes one exact inventory of configured scanners, exclusions and inline suppression annotations. It does not accept a vulnerability, label unknown suppression reasons as false positives, or waive missing scans. The owner reviews the inventory together with the source/configuration it identifies, verifies intended language/rule coverage and records limits before dispatching the trusted approval workflow with a `CR-NNNN` record. An absent or invalid review leaves `coverage_complete:false`.

The exporter writes `source-policy-inventory.json` privately. Its digest is SHA256 of canonical JSON (sorted keys, compact separators, UTF-8, no trailing newline). Source file hashes bind the surrounding code, rather than just trusting a suppression comment. Changing that inventory requires a new explicit policy approval. Individual suppressed CodeQL, Semgrep and Sonar findings still need their own `RA-NNNN` disposition.

Copy this front matter into `CR-NNNN.md`, followed by public-safe reasoning, coverage verified, exclusions reviewed, and known limits. The `CR-NNNN.approval.json` descriptor is authenticated by the same owner-only default-branch manual workflow and protected environment as risk acceptance. This example grants no approval.

```markdown
---
{
  "schema_version": 1,
  "id": "CR-0001",
  "inventory_sha256": "REPLACE_WITH_EXACT_64_CHARACTER_SHA256",
  "reason": "Describe configured coverage, reviewed exclusions and suppression annotations without inventing scanner findings",
  "owner": "lorconksu",
  "authorized_approver": "lorconksu",
  "approval_time": "2026-10-31T12:00:00Z",
  "expires_at": "2026-11-30T12:00:00Z",
  "private_evidence_reference": "evidence:coverage-review-1"
}
---

Record coverage assessment and follow-up here.
```
