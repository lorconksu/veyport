#!/usr/bin/env python3
"""Export completed exact-revision SAST evidence without starting another scan."""
import argparse
import datetime as dt
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request
from risk_acceptance import GitHub, REPOSITORY, canonical, now, sha, strict_json, load_record, verify

CODEQL_CATEGORIES = {"/language:" + n for n in ("go", "javascript-typescript", "python", "ruby", "actions")}
MAX_BYTES = 16 << 20
PROJECT = "lorconksu_veyport"


def date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None


def fresh(value, at=None):
    parsed = date(value)
    if parsed is None:
        raise ValueError("scanner completion time missing")
    instant = dt.datetime.fromisoformat(parsed.replace("Z", "+00:00"))
    if not dt.timedelta(0) <= (at or now()) - instant <= dt.timedelta(hours=24):
        raise ValueError("source scan evidence exceeded 24 hour freshness")


def classify(tags):
    tags = " ".join(str(t).lower() for t in tags)
    if re.search(r"cwe[-/ ]*(?:0*287|0*306|0*307|0*308|0*290|0*294)\b", tags):
        return "authentication"
    if re.search(r"cwe[-/ ]*(?:0*285|0*639|0*862|0*863|0*732)\b", tags):
        return "authorization"
    if re.search(r"cwe[-/ ]*0*778\b", tags):
        return "required-audit"
    return "unresolved"


def severity(rule, result):
    score = rule.get("properties", {}).get("security-severity")
    if score is not None:
        score = float(score)
        if not 0 <= score <= 10:
            raise ValueError("invalid security severity")
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}[result.get("level", "warning")]


def sarif_findings(raw, scanner, revision, version, alerts=()):
    if raw.get("version") != "2.1.0" or not isinstance(raw.get("runs"), list) or not raw["runs"]:
        raise ValueError("complete SARIF runs required")
    findings = []
    alert_map = {a["number"]: a for a in alerts}
    for run in raw["runs"]:
        driver = run.get("tool", {}).get("driver", {})
        if scanner == "codeql":
            if driver.get("name") != "CodeQL" or not any(p.get("revisionId") == revision and p.get("repositoryUri", "").removesuffix(".git") == "https://github.com/" + REPOSITORY for p in run.get("versionControlProvenance", [])):
                raise ValueError("SARIF source identity mismatch")
        elif driver.get("name", "").lower() != "semgrep oss":
            if driver.get("name", "").lower() != "semgrep":
                raise ValueError("unexpected Semgrep producer")
        if any(i.get("executionSuccessful") is False for i in run.get("invocations", [])):
            raise ValueError("SARIF execution failure")
        components = [driver] + run.get("tool", {}).get("extensions", [])
        rules = {r["id"]: r for component in components for r in component.get("rules", [])}
        if not isinstance(run.get("results"), list):
            raise ValueError("SARIF result inventory missing")
        for result in run["results"]:
            rule_id = result["ruleId"]
            rule = rules.get(rule_id)
            if rule is None:
                raise ValueError("SARIF rule metadata missing")
            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                raise ValueError("SARIF finding location missing")
            physical = locations[0].get("physicalLocation", {})
            component = physical.get("artifactLocation", {}).get("uri")
            if not isinstance(component, str) or not 1 <= len(component) <= 256:
                raise ValueError("unscoped SARIF finding")
            number = result.get("properties", {}).get("github/alertNumber")
            alert = alert_map.get(number)
            identity = "alert:" + str(number) if number is not None else rule_id + ":" + sha(canonical({"locations": locations, "fingerprints": result.get("partialFingerprints", {})}))[:20]
            if len(identity) > 256:
                identity = "rule:" + sha(identity.encode())
            classification = classify(rule.get("properties", {}).get("tags", []))
            if result.get("suppressions") or (alert and alert.get("state") == "dismissed"):
                reason = alert.get("dismissed_reason") if alert else None
                classification = "false-positive" if reason == "false positive" else "not-affected" if reason == "used in tests" else classification
            findings.append({"scanner": scanner, "id": identity, "component": component, "version": version,
                             "severity": severity(rule, result), "classification": classification,
                             "first_seen": date(alert.get("created_at")) if alert else None,
                             "rule_id": rule_id, "suppressed": bool(result.get("suppressions")) or bool(alert and alert.get("state") == "dismissed"),
                             "provider_state": alert.get("state") if alert else None})
    return findings


class ExportAPI(GitHub):
    def sarif(self, analysis_id):
        request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}/code-scanning/analyses/{analysis_id}", headers={"Authorization": "Bearer " + self.token, "Accept": "application/sarif+json", "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("SARIF exceeds evidence bound")
        return strict_json(raw)

    def pages(self, path):
        rows = []
        for page in range(1, 101):
            result = self.get(path + ("&" if "?" in path else "?") + f"per_page=100&page={page}")
            if not isinstance(result, list) or len(result) > 100:
                raise ValueError("unexpected API pagination")
            rows.extend(result)
            if len(result) < 100:
                return rows
        raise ValueError("complete pagination exceeded bound")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Sonar:
    def __init__(self, public_project=False):
        self.public_project = public_project

    def get(self, endpoint, params):
        headers = {"Accept": "application/json"}
        if self.public_project and endpoint != "ce/task":
            selectors = {"components/show": "component", "project_pull_requests/list": "project",
                         "project_analyses/search": "project", "issues/search": "componentKeys",
                         "hotspots/search": "projectKey"}
            if endpoint == "qualitygates/project_status":
                if set(params) != {"analysisId"} or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", params["analysisId"]):
                    raise ValueError("Sonar exact analysis identity required")
            elif endpoint not in selectors or params.get(selectors[endpoint]) != PROJECT:
                raise ValueError("Sonar public reader requires the fixed project")
            # This is a deliberate mode, never a fallback after an auth error.
            # Analysis credentials are sent only to ce/task in this mode.
        else:
            token = os.environ.get("SONAR_TOKEN")
            if not token:
                raise ValueError("Sonar authentication missing")
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request("https://sonarcloud.io/api/" + endpoint + "?" + urllib.parse.urlencode(params), headers=headers)
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            data = response.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("Sonar evidence exceeds bound")
        return strict_json(data)

    def pages(self, endpoint, params, key):
        pages, rows, total = [], [], None
        for page in range(1, 101):
            result = self.get(endpoint, {**params, "ps": 500, "p": page})
            count = result.get("paging", {}).get("total")
            if type(count) is not int or count < 0 or total is not None and count != total or not isinstance(result.get(key), list):
                raise ValueError("Sonar inventory changed or is incomplete")
            total = count
            rows.extend(result[key])
            pages.append(result)
            if len(rows) == total:
                return rows, pages
            if len(rows) > total or not result[key]:
                raise ValueError("Sonar pagination is incomplete")
        raise ValueError("Sonar complete pagination exceeded bound")


def save(root, name, value):
    path = Path(root) / name
    path.write_bytes(canonical(value) + b"\n")
    path.chmod(0o600)


def verify_public_sonar(api, root, name):
    value = api.get("components/show", {"component": PROJECT})
    save(root, name, value)
    component = value.get("component") if isinstance(value, dict) else None
    if not isinstance(component, dict) or component.get("key") != PROJECT or component.get("visibility") != "public":
        raise ValueError("Sonar public reader requires verified public project visibility")


def export_codeql(api, root, revision, version):
    analyses = api.pages("code-scanning/analyses?tool_name=CodeQL&ref=refs%2Fheads%2Fmain")
    selected = {}
    for item in analyses:
        if item.get("commit_sha") == revision and item.get("category") in CODEQL_CATEGORIES:
            selected.setdefault(item["category"], item)
    if set(selected) != CODEQL_CATEGORIES:
        raise ValueError("all exact-main-revision CodeQL languages required")
    all_alerts = api.pages("code-scanning/alerts?ref=refs%2Fheads%2Fmain")
    save(root, "codeql-alerts.json", all_alerts)
    save(root, "codeql-analyses.json", list(selected.values()))
    findings = []
    for index, item in enumerate(selected.values()):
        fresh(item["created_at"])
        if item.get("error") or item.get("warning") or item.get("tool", {}).get("name") != "CodeQL":
            raise ValueError("incomplete CodeQL analysis")
        raw = api.sarif(item["id"])
        save(root, f"codeql-{index}.sarif", raw)
        results = sarif_findings(raw, "codeql", revision, version, all_alerts)
        if len(results) != item.get("results_count"):
            raise ValueError("CodeQL full result count mismatch")
        findings.extend(results)
    # Default-branch full analyses are reused only for this exact revision;
    # PR/new-code-only analyses are never accepted as the baseline.
    return findings


def export_sonar(api, root, revision, version, branch, public_project=False):
    if public_project:
        verify_public_sonar(api, root, "sonar-project-before.json")
    params = {"project": PROJECT, "branch": branch, "p": 1, "ps": 1}
    before = api.get("project_analyses/search", params)
    analyses = before.get("analyses", [])
    if len(analyses) != 1 or analyses[0].get("revision") != revision:
        raise ValueError("latest full Sonar branch analysis must match candidate")
    fresh(analyses[0]["date"])
    issues, issue_pages = api.pages("issues/search", {"componentKeys": PROJECT, "branch": branch, "additionalFields": "_all", "issueStatuses": "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED"}, "issues")
    hotspots, hotspot_pages = api.pages("hotspots/search", {"projectKey": PROJECT, "branch": branch}, "hotspots")
    gate = api.get("qualitygates/project_status", {"analysisId": analyses[0]["key"]})
    if gate.get("projectStatus", {}).get("status") != "OK":
        raise ValueError("Sonar quality gate did not pass")
    after = api.get("project_analyses/search", params)
    if after != before:
        raise ValueError("Sonar mutable branch changed during evidence export")
    if public_project:
        verify_public_sonar(api, root, "sonar-project-after.json")
    save(root, "sonar-analysis.json", before)
    save(root, "sonar-issues.json", issue_pages)
    save(root, "sonar-hotspots.json", hotspot_pages)
    save(root, "sonar-quality-gate.json", gate)
    findings = []
    for issue in issues:
        impacts = [i for i in issue.get("impacts", []) if i.get("softwareQuality") == "SECURITY"]
        if issue.get("type") != "VULNERABILITY" and not impacts:
            continue
        state = issue.get("issueStatus", issue.get("status"))
        if state in ("FIXED", "CLOSED") and issue.get("resolution") not in ("FALSE-POSITIVE", "WONTFIX"):
            continue
        classification = "false-positive" if state == "FALSE_POSITIVE" or issue.get("resolution") == "FALSE-POSITIVE" else classify(issue.get("tags", []))
        level = max((i.get("severity") for i in impacts), default=None, key=lambda v: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "BLOCKER": 3}.get(v, -1))
        severity_value = {"BLOCKER": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(level) if level else {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium", "MINOR": "low", "INFO": "info"}.get(issue.get("severity"))
        if severity_value is None:
            raise ValueError("unknown Sonar security severity")
        findings.append({"scanner": "sonar", "id": issue["key"], "component": issue["component"], "version": version, "severity": severity_value, "classification": classification, "first_seen": date(issue.get("creationDate")), "provider_state": state, "rule_id": issue["rule"]})
    for hotspot in hotspots:
        classification = "not-affected" if hotspot.get("resolution") == "SAFE" else classify([hotspot.get("securityCategory")])
        findings.append({"scanner": "sonar", "id": hotspot["key"], "component": hotspot["component"], "version": version, "severity": {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}[hotspot["vulnerabilityProbability"]], "classification": classification, "first_seen": date(hotspot.get("creationDate")), "provider_state": hotspot["status"], "rule_id": hotspot["ruleKey"]})
    return findings


def suppression_inventory(root):
    root = Path(root)
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    configs, annotations = [], []
    for name in sorted(n for n in tracked if n):
        path = root / name
        is_config = name in ("sonar-project.properties", ".github/workflows/ci.yml", ".semgrepignore", ".snyk") or name.startswith((".github/codeql/", ".semgrep/"))
        is_source = name.startswith(("hub/", "agent/", "cli/", "web/src/", "proto/")) and path.suffix in (".go", ".ts", ".tsx", ".js", ".py", ".rb") and not name.endswith(".pb.go")
        if not is_config and not is_source:
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 4 << 20:
            raise ValueError("source policy inventory is incomplete")
        raw = path.read_bytes()
        digest = sha(raw)
        if is_config:
            configs.append({"path": name, "sha256": digest})
        if is_source:
            for index, line in enumerate(raw.decode().splitlines(), 1):
                kinds = []
                if "NOSONAR" in line:
                    kinds.append("sonar")
                if re.search(r"\bnosem(?:grep)?\b", line):
                    kinds.append("semgrep")
                if "lgtm[" in line or re.search(r"codeql.*(?:disable|suppress)", line, re.I):
                    kinds.append("codeql")
                if kinds:
                    annotations.append({"path": name, "line": index, "scanners": kinds, "annotation_sha256": sha(line.encode()), "source_sha256": digest})
    return {"schema_version": 1, "repository": REPOSITORY, "configurations": configs, "annotations": annotations}


def reviewed_inventory(inventory_hash, directory, api):
    for path in sorted(Path(directory).glob("CR-*.md")):
        record, _ = load_record(path)
        if record["inventory_sha256"] != inventory_hash:
            continue
        descriptor = path.with_suffix(".approval.json")
        if not descriptor.is_file() or descriptor.is_symlink() or descriptor.stat().st_size > 65536:
            raise ValueError("coverage approval descriptor missing")
        approved = verify(api, path, strict_json(descriptor.read_bytes()))
        if approved.get("inventory_sha256") != inventory_hash:
            raise ValueError("coverage review inventory mismatch")
        return {"id": approved["id"], "record_sha256": sha(path.read_bytes()), "expires_at": approved["expires_at"]}
    raise ValueError("exact suppression/configuration inventory needs owner policy review")


def collect(args, api=None, sonar=None):
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    envelope = {"schema_version": 1, "candidate_id": args.candidate_id, "revision": args.revision, "artifact_manifest_sha256": sha(Path(args.artifact_manifest).read_bytes()), "status": "failed", "required_scopes": ["source:sast:" + n for n in ("semgrep", "codeql", "sonar")], "scopes": []}
    for scanner in ("semgrep", "codeql", "sonar"):
        scope = {"id": "source:sast:" + scanner, "status": "failed", "authenticated": False, "coverage_complete": False, "findings": []}
        envelope["scopes"].append(scope)
        try:
            if scanner == "semgrep":
                source = Path(args.semgrep)
                if source.is_symlink() or not 0 < source.stat().st_size <= MAX_BYTES:
                    raise ValueError("current-run Semgrep report missing")
                # The delivery caller runs the unchanged required Semgrep gate
                # once locally; required-ci explicitly defers that same scan.
                raw = strict_json(source.read_bytes())
                save(root, "semgrep.sarif", raw)
                findings = sarif_findings(raw, scanner, args.revision, args.version)
            elif scanner == "codeql":
                findings = export_codeql(api or ExportAPI(), root, args.revision, args.version)
            else:
                public_project = getattr(args, "sonar_public_project", False)
                findings = export_sonar(sonar or Sonar(public_project=public_project), root, args.revision, args.version, args.sonar_branch, public_project)
                if public_project:
                    # authenticated records trusted report provenance, as for
                    # local same-run Semgrep; it is not a client login claim.
                    scope.update(provider_access="public-project-anonymous", client_authenticated=False)
            scope.update(status="completed", authenticated=True, coverage_complete=True, findings=findings)
        except (ValueError, OSError, KeyError, TypeError):
            scope["error"] = "Exact-source full baseline export incomplete; private diagnostics required."
    try:
        inventory = suppression_inventory(getattr(args, "root", "."))
        inventory_hash = sha(canonical(inventory))
        save(root, "source-policy-inventory.json", inventory)
        review = reviewed_inventory(inventory_hash, getattr(args, "coverage_reviews", "docs/security/coverage-reviews"), api or ExportAPI())
        envelope["coverage_policy"] = {"inventory_sha256": inventory_hash, "status": "reviewed", "approval": review}
    except (ValueError, OSError, KeyError, TypeError):
        envelope["coverage_policy"] = {"status": "pending-owner-policy-review", "inventory_sha256": locals().get("inventory_hash")}
        for scope in envelope["scopes"]:
            scope["coverage_complete"] = False
    if all(s["status"] == "completed" for s in envelope["scopes"]):
        envelope["status"] = "completed"
    save(root, "assessment.json", envelope)
    Path(args.assessment).write_bytes(canonical(envelope) + b"\n")
    return envelope["status"] == "completed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("output", "assessment", "revision", "version", "candidate-id", "artifact-manifest", "semgrep", "sonar-branch"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--root", default=".")
    parser.add_argument("--coverage-reviews", default="docs/security/coverage-reviews")
    parser.add_argument("--sonar-public-project", action="store_true", help="Read fixed-project public Sonar results anonymously after visibility verification")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", args.revision) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.candidate_id):
            raise ValueError("exact candidate identity required")
        if not collect(args):
            parser.exit(1, "full-baseline SAST export incomplete; publication prohibited\n")
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "source SAST evidence failed; publication prohibited\n")


if __name__ == "__main__":
    main()
