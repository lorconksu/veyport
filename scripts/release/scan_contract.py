"""Active release coverage contract, separate from historical approval grammar."""
from risk_acceptance import SOURCE_SCOPES as HISTORICAL_SOURCE_SCOPES, IMAGE_SCOPES, NATIVE_SCOPES

POLICY_VERSION = "ssdf-2026-11-08-v2"
SAST_SCANNERS = ("codeql", "sonar")
SOURCE_SCOPES = HISTORICAL_SOURCE_SCOPES - {"source:sast:semgrep"}
REQUIRED_SCOPES = SOURCE_SCOPES | IMAGE_SCOPES | NATIVE_SCOPES
