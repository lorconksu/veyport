# OWASP ZAP baseline policy

`rules.tsv` is a reviewed baseline, not a wildcard suppression list. The CI
DAST job changes only known, currently accepted alerts to `INFO`; every alert
whose rule ID is absent remains a warning and fails the check through
`fail_action: true`.

The rule comments carry the most recent review date. Reproduce the scan against
the disposable local Hub before adding or changing a disposition. Do not point
an active scan at production or add credentials to this directory.

Rule `10055` remains informational only because the current React interface
uses inline style attributes. The CSP still restricts scripts to same-origin
files and explicitly sets `frame-ancestors`, `form-action`, `object-src`, and
`base-uri`. Removing the inline-style dependency should be tracked separately;
after that change, remove `10055` from the baseline so it becomes blocking.
