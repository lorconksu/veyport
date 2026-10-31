# Risk acceptance template

Copy the following to a new `RA-NNNN.md`. Replace every example. Keep the record public-safe; approval is a separate authenticated owner action described in [the policy](../risk-acceptance.md). This template is not an approved exception.

```markdown
---
{
  "schema_version": 1,
  "id": "RA-0001",
  "findings": [
    {"scope": "source:sast:codeql", "scanner": "codeql", "id": "alert:123", "component": "hub/example.go", "version": "2.0.58"}
  ],
  "classification": "accepted-risk",
  "severity": "high",
  "reason": "Disclosure-safe justification",
  "compensating_controls": "Concrete controls and their verification",
  "owner": "lorconksu",
  "authorized_approver": "lorconksu",
  "approval_time": "2026-10-31T12:00:00Z",
  "expires_at": "2026-11-07T12:00:00Z",
  "remediation_reference": "issue:123",
  "private_evidence_reference": "evidence:review-1"
}
---

Explain the assessment, exact report scope, impact, controls and remediation follow-up. List an additional finding entry for each independently approved source manifest or runtime image; changing or adding scope requires renewed approval.
```
