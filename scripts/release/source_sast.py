#!/usr/bin/env python3
"""Export full exact-revision SAST evidence from trusted completed scans."""
import argparse
from bisect import bisect_right
import datetime as dt
import os
from pathlib import Path
import re
import shlex
import subprocess
import urllib.parse
import urllib.request
from risk_acceptance import GitHub, REPOSITORY, canonical, now, sha, strict_json, load_record, verify

CODEQL_CATEGORIES = {"/language:" + n for n in ("go", "javascript-typescript", "python", "ruby", "actions")}
CODEQL_DEFAULT_KEY = "dynamic/github-code-scanning/codeql:analyze"
MAX_BYTES = 16 << 20
PROJECT = "lorconksu_veyport"
# Bind the current frontend measurement inputs, including the locked provider's
# implicit defaults and source transforms. This is a bounded path inventory,
# not a dependency graph for arbitrary executable configuration imports.
FRONTEND_MEASUREMENT_CONFIG = re.compile(r"web/(?:(?:vite|vitest)\.(?:config|workspace)\.[cm]?[jt]s|tsconfig(?:\.[^/]+)?\.json|package(?:-lock)?\.json|\.(?:gitignore|npmrc|nvmrc|node-version))$")
# ast-v8-to-istanbul (locked through web/package-lock.json) accepts all four
# namespaces. start/stop are raw source text hints; other forms are comments
# after transforms. Conservatively inventory candidate text, including hints
# spanning whitespace/newlines, without claiming to parse JS/TS or transforms.
# JS's word boundary is ASCII; its whitespace also includes U+FEFF.
COVERAGE_HINT = re.compile(r"(?:istanbul|[cv]8|node:coverage)[\s\ufeff]+ignore[\s\ufeff]+(?:if|else|next|file|start|stop)(?![A-Za-z0-9_])")


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


def sarif_findings(raw, scanner, revision, version, alerts=(), local_codeql=False):
    if not isinstance(raw, dict) or raw.get("version") != "2.1.0" or not isinstance(raw.get("runs"), list) or not raw["runs"]:
        raise ValueError("complete SARIF runs required")
    findings = []
    alert_map = {a["number"]: a for a in alerts}
    for run in raw["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("tool"), dict) or not isinstance(run["tool"].get("driver"), dict):
            raise ValueError("SARIF producer metadata missing")
        driver = run.get("tool", {}).get("driver", {})
        if scanner == "codeql":
            provenance = run.get("versionControlProvenance", [])
            if driver.get("name") != "CodeQL" or (not provenance and not local_codeql) or any(p.get("revisionId") != revision or p.get("repositoryUri", "").removesuffix(".git") != "https://github.com/" + REPOSITORY for p in provenance):
                raise ValueError("SARIF source identity mismatch")
            validate_codeql_run(run, local=local_codeql)
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
                         "hotspots/search": "projectKey", "project_branches/list": "project"}
            if endpoint == "qualitygates/project_status":
                exact_analysis = set(params) == {"analysisId"} and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", params["analysisId"])
                exact_pr = set(params) == {"projectKey", "pullRequest"} and params["projectKey"] == PROJECT and re.fullmatch(r"[1-9][0-9]*", params["pullRequest"])
                if not (exact_analysis or exact_pr):
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


def validate_codeql_run(run, local=False):
    """Reject reduced analyses and incomplete execution, including zero-result runs."""
    properties = run.get("properties", {})
    if not isinstance(properties, dict) or not isinstance(run.get("tool", {}).get("extensions", []), list):
        raise ValueError("CodeQL configuration metadata malformed")
    components = [run.get("tool", {}).get("driver", {})] + run.get("tool", {}).get("extensions", [])
    if any(not isinstance(component, dict) for component in components):
        raise ValueError("CodeQL component metadata malformed")
    if any(re.search(r"pr-diff-range|diff.?informed|incremental|overlay", component.get("name", ""), re.I) for component in components):
        raise ValueError("CodeQL incremental query extension is not a full baseline")
    for key, value in properties.items():
        if re.search(r"incremental|diff.?informed|truncat|partial.?analysis|overlay", key, re.I) and value not in (None, False, "", "none", "full"):
            raise ValueError("CodeQL full analysis required")
    invocations = run.get("invocations", [])
    if not isinstance(invocations, list) or any(not isinstance(i, dict) for i in invocations):
        raise ValueError("CodeQL execution receipt malformed")
    if local and not invocations:
        raise ValueError("local CodeQL execution receipt required")
    for invocation in invocations:
        if invocation.get("executionSuccessful") is not True:
            raise ValueError("CodeQL execution incomplete")
        for key in ("toolExecutionNotifications", "toolConfigurationNotifications"):
            if any(n.get("level", "warning") in ("warning", "error") for n in invocation.get(key, [])):
                raise ValueError("CodeQL diagnostic requires review")
    if any(result.get("baselineState") in ("new", "updated", "absent") for result in run.get("results", [])):
        raise ValueError("CodeQL differential results are not a full baseline")
    if local and properties.get("codeqlConfigSummary") != {"disableDefaultQueries": False, "queries": [{"type": "builtinSuite", "uses": "security-extended"}]}:
        raise ValueError("known full CodeQL configuration receipt required")


def default_codeql_configuration(api):
    config = api.get("code-scanning/default-setup")
    languages = set(config.get("languages", []))
    if config.get("state") != "configured" or config.get("query_suite") not in ("default", "extended") or not {c.removeprefix("/language:") for c in CODEQL_CATEGORIES} <= languages or date(config.get("updated_at")) is None:
        raise ValueError("known complete default CodeQL configuration required")
    return config


def export_codeql(api, root, revision, version):
    configuration = default_codeql_configuration(api)
    analyses = api.pages("code-scanning/analyses?tool_name=CodeQL&ref=refs%2Fheads%2Fmain")
    selected = {}
    for item in analyses:
        if item.get("commit_sha") == revision and item.get("category") in CODEQL_CATEGORIES and item.get("ref") == "refs/heads/main" and item.get("analysis_key") == CODEQL_DEFAULT_KEY:
            selected.setdefault(item["category"], item)
    if set(selected) != CODEQL_CATEGORIES:
        raise ValueError("all exact-main-revision CodeQL languages required")
    all_alerts = api.pages("code-scanning/alerts?ref=refs%2Fheads%2Fmain")
    save(root, "codeql-alerts.json", all_alerts)
    save(root, "codeql-analyses.json", list(selected.values()))
    findings = []
    for index, item in enumerate(selected.values()):
        fresh(item["created_at"])
        if item.get("error") or item.get("warning") or item.get("tool", {}).get("name") != "CodeQL" or date(configuration["updated_at"]) > date(item["created_at"]) or type(item.get("results_count")) is not int or item["results_count"] < 0:
            raise ValueError("incomplete CodeQL analysis")
        raw = api.sarif(item["id"])
        save(root, f"codeql-{index}.sarif", raw)
        if any(r.get("automationDetails", {}).get("id", "").rstrip("/") != item["category"] or any(p.get("branch") != "refs/heads/main" for p in r.get("versionControlProvenance", [])) for r in raw.get("runs", [])):
            raise ValueError("CodeQL category/ref mismatch")
        results = sarif_findings(raw, "codeql", revision, version, all_alerts)
        if len(results) != item.get("results_count"):
            raise ValueError("CodeQL full result count mismatch")
        findings.extend(results)
    if default_codeql_configuration(api) != configuration:
        raise ValueError("CodeQL configuration changed during export")
    save(root, "codeql-default-setup.json", configuration)
    # Default-branch full analyses are reused only for this exact revision;
    # PR/new-code-only analyses are never accepted as the baseline.
    return findings


def _codeql_history_location(run, value):
    physical = value.get("physicalLocation", {})
    artifact = physical.get("artifactLocation", {})
    uri = artifact.get("uri")
    if uri is None and type(artifact.get("index")) is int:
        index = artifact["index"]
        artifacts = run.get("artifacts", [])
        if 0 <= index < len(artifacts):
            uri = artifacts[index].get("location", {}).get("uri")
    region = physical.get("region", {})
    start = region.get("startLine")
    coordinates = [start, region.get("endLine", start), region.get("startColumn"), region.get("endColumn")]
    if not isinstance(uri, str) or not uri or any(type(n) is not int or n < 1 for n in coordinates):
        raise ValueError("complete history coordinates required")
    return [uri, *coordinates]


def _codeql_history_flow(run, flow):
    return [[_codeql_history_location(run, value["location"]) for value in thread["locations"]]
            for thread in flow["threadFlows"]]


def codeql_history_signature(run, result):
    """Conservative identity across exports; never match by line or rule alone."""
    fingerprint = result.get("partialFingerprints", {}).get("primaryLocationLineHash")
    if not isinstance(fingerprint, str) or not 1 <= len(fingerprint) <= 256:
        return None
    try:
        locations = [_codeql_history_location(run, value) for value in result.get("locations", [])]
        flows = [_codeql_history_flow(run, flow) for flow in result.get("codeFlows", [])]
        if not locations or not isinstance(result.get("ruleId"), str):
            return None
        return sha(canonical({"rule": result["ruleId"], "fingerprint": fingerprint,
                              "locations": locations, "flows": flows}))
    except (KeyError, TypeError, ValueError):
        return None


def _codeql_history_signatures(raw):
    return [codeql_history_signature(run, result) for run in raw["runs"] for result in run["results"]]


def _codeql_history_inventory_matches(findings, normalized):
    fields = ("scanner", "id", "component", "version", "rule_id", "severity", "classification", "suppressed", "provider_state")
    actual = [[finding.get(key) for key in fields] for finding in findings]
    expected = [[finding.get(key) for key in fields] for finding in normalized]
    return actual == expected


def _codeql_current_history(root, revision, version, findings):
    local = Path(root) / "codeql-local"
    if not local.is_dir() or local.is_symlink():
        raise ValueError("current local CodeQL evidence required for history")
    current, normalized = [], []
    for path in sorted(local.glob("*.sarif")):
        if path.is_symlink() or not 0 < path.stat().st_size <= MAX_BYTES:
            raise ValueError("bounded local CodeQL history source required")
        raw = strict_json(path.read_bytes())
        # Validate these bytes independently before using their identity.
        normalized.extend(sarif_findings(raw, "codeql", revision, version, local_codeql=True))
        current.extend(_codeql_history_signatures(raw))
    if len(current) != len(findings) or not _codeql_history_inventory_matches(findings, normalized):
        raise ValueError("CodeQL history finding inventory mismatch")
    return current


def _codeql_history_alert_map(alerts):
    alert_map = {}
    for alert in alerts:
        number = alert.get("number")
        if type(number) is not int or number < 1 or number in alert_map:
            raise ValueError("ambiguous CodeQL alert history")
        alert_map[number] = alert
    return alert_map


def _codeql_history_analyses(analyses):
    selected = {}
    for item in analyses:
        if item.get("category") in CODEQL_CATEGORIES and item.get("ref") == "refs/heads/main" and item.get("analysis_key") == CODEQL_DEFAULT_KEY:
            selected.setdefault(item["category"], item)
    return list(selected.values())


def _codeql_history_analysis_identity(item, observed_at):
    source_revision = item.get("commit_sha", "")
    created = date(item.get("created_at"))
    if (type(item.get("id")) is not int or item["id"] < 1 or not re.fullmatch(r"[0-9a-f]{40}", source_revision)
            or created is None or created > observed_at or item.get("error") or item.get("warning")
            or item.get("tool", {}).get("name") != "CodeQL" or type(item.get("results_count")) is not int):
        raise ValueError("invalid CodeQL history analysis")
    return source_revision, created


def _codeql_history_run_scope(run, category):
    return (run.get("automationDetails", {}).get("id", "").rstrip("/") == category
            and all(p.get("branch") == "refs/heads/main" for p in run.get("versionControlProvenance", [])))


def _codeql_history_report(api, root, index, item, version, observed_at, alerts_hash):
    source_revision, created = _codeql_history_analysis_identity(item, observed_at)
    raw = api.sarif(item["id"])
    name = f"codeql-history-{index}.sarif"
    save(root, name, raw)
    historic = sarif_findings(raw, "codeql", source_revision, version)
    if len(historic) != item["results_count"] or any(
            not _codeql_history_run_scope(run, item["category"]) for run in raw["runs"]):
        raise ValueError("CodeQL history scope mismatch")
    source = {"analysis_id": item["id"], "revision": source_revision, "sarif": name,
              "sarif_sha256": sha((Path(root) / name).read_bytes()), "alerts_sha256": alerts_hash}
    return raw, source, created


def _codeql_history_result(run, result, alert_map, source, created):
    signature = codeql_history_signature(run, result)
    alert = alert_map.get(result.get("properties", {}).get("github/alertNumber"))
    if signature is None or alert is None:
        return None
    first_seen = date(alert.get("created_at"))
    if (alert.get("tool", {}).get("name") != "CodeQL" or alert.get("rule", {}).get("id") != result["ruleId"]
            or first_seen is None or first_seen > created):
        return None
    return {"analysis_id": source["analysis_id"], "alert_number": alert["number"], "first_seen": first_seen,
            "match_sha256": signature, "provider_sarif_sha256": source["sarif_sha256"],
            "provider_alerts_sha256": source["alerts_sha256"], "source_revision": source["revision"]}


def _codeql_history_report_matches(raw, alert_map, source, created, matches):
    for run in raw["runs"]:
        for result in run["results"]:
            evidence = _codeql_history_result(run, result, alert_map, source, created)
            if evidence is not None:
                matches.setdefault(evidence["match_sha256"], []).append(evidence)


def _codeql_history_matches(api, root, version, ledger):
    analyses = api.pages("code-scanning/analyses?tool_name=CodeQL&ref=refs%2Fheads%2Fmain")
    alerts = api.pages("code-scanning/alerts?ref=refs%2Fheads%2Fmain")
    alert_map = _codeql_history_alert_map(alerts)
    save(root, "codeql-history-alerts.json", alerts)
    alerts_hash = sha((Path(root) / "codeql-history-alerts.json").read_bytes())
    selected = _codeql_history_analyses(analyses)
    save(root, "codeql-history-analyses.json", selected)
    matches = {}
    for index, item in enumerate(selected):
        raw, source, created = _codeql_history_report(api, root, index, item, version, ledger["observed_at"], alerts_hash)
        ledger["sources"].append(source)
        _codeql_history_report_matches(raw, alert_map, source, created, matches)
    return matches


def _apply_codeql_history(findings, current, matches, ledger):
    linked = []
    for finding, signature in zip(findings, current):
        item = dict(finding)
        candidates = matches.get(signature, [])
        # Multiple provider identities are ambiguous even when dates agree.
        if len(candidates) == 1:
            evidence = candidates[0]
            if item.get("first_seen") not in (None, evidence["first_seen"]):
                raise ValueError("conflicting CodeQL first-seen history")
            item.update(first_seen=evidence["first_seen"], first_seen_evidence=evidence)
            ledger["matches"].append({"finding_id": item["id"], **evidence})
        else:
            ledger["unmatched"].append({"finding_id": item["id"], "reason": "ambiguous-history" if candidates else "no-exact-history"})
        linked.append(item)
    return linked


def link_codeql_history(api, root, revision, version, findings):
    """Archive authenticated historical dates without importing dismissals.

    Historical analyses supply identity/date evidence only. They never replace
    the current full scan or establish that its findings have been approved.
    The ledger and its source payloads travel in the encrypted per-run archive.
    """
    current = _codeql_current_history(root, revision, version, findings)
    ledger = {"schema_version": 1, "repository": REPOSITORY, "revision": revision,
              "observed_at": now().strftime("%Y-%m-%dT%H:%M:%SZ"),
              "purpose": "first-seen-only; no finding disposition or release authority",
              "matches": [], "unmatched": [], "sources": []}
    linked = findings
    if current:
        matches = _codeql_history_matches(api, root, version, ledger)
        linked = _apply_codeql_history(findings, current, matches, ledger)
    save(root, "codeql-first-seen-history.json", ledger)
    return linked


def sonar_gate_snapshot(api, context, revision):
    """An independent genuine PR/main gate; the candidate inventory is not a gate."""
    values = shlex.split(context)
    if any(not item.startswith("-D") or "=" not in item for item in values):
        raise ValueError("explicit Sonar gate context required")
    args = dict(item[2:].split("=", 1) for item in values)
    if len(args) != len(values):
        raise ValueError("duplicate Sonar gate context")
    if set(args) == {"sonar.pullrequest.key", "sonar.pullrequest.branch", "sonar.pullrequest.base"}:
        key, branch = args["sonar.pullrequest.key"], args["sonar.pullrequest.branch"]
        if not re.fullmatch(r"[1-9][0-9]*", key) or not re.fullmatch(r"[A-Za-z0-9_./+@-]{1,240}", branch) or args["sonar.pullrequest.base"] != "main":
            raise ValueError("exact Sonar PR gate context required")
        rows = api.get("project_pull_requests/list", {"project": PROJECT})["pullRequests"]
        matches = [row for row in rows if row.get("key") == key]
        if len(matches) != 1 or matches[0].get("commit", {}).get("sha") != revision or matches[0].get("branch") != branch or matches[0].get("base") != "main" or matches[0].get("status", {}).get("qualityGateStatus") != "OK":
            raise ValueError("Sonar PR gate source changed or did not pass")
        fresh(matches[0].get("analysisDate"))
        source = {"scope": "pull-request-new-code", "pull_request": matches[0]}
        gate = api.get("qualitygates/project_status", {"projectKey": PROJECT, "pullRequest": key})
    elif args == {"sonar.branch.name": "main"}:
        rows = api.get("project_branches/list", {"project": PROJECT})["branches"]
        matches = [row for row in rows if row.get("name") == "main"]
        if len(matches) != 1 or matches[0].get("type") != "LONG" or matches[0].get("isMain") is not True or matches[0].get("commit", {}).get("sha", revision) != revision:
            raise ValueError("Sonar main gate source changed")
        analyses = api.get("project_analyses/search", {"project": PROJECT, "branch": "main", "ps": 1, "p": 1})["analyses"]
        if len(analyses) != 1 or analyses[0].get("revision") != revision or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", analyses[0].get("key", "")):
            raise ValueError("Sonar main gate must match the exact candidate")
        fresh(analyses[0].get("date"))
        source = {"scope": "main-quality-gate", "branch": matches[0], "analysis": analyses[0]}
        gate = api.get("qualitygates/project_status", {"analysisId": analyses[0]["key"]})
    else:
        raise ValueError("Sonar gate must be an exact PR or established main")
    if gate.get("projectStatus", {}).get("status") != "OK":
        raise ValueError("Sonar required quality gate did not pass")
    return {**source, "quality_gate": gate}


def export_sonar(api, root, revision, version, branch, public_project=False):
    if branch not in ("main", "release-ssdf-candidate-" + revision):
        raise ValueError("full reviewed Sonar source branch required")
    if public_project:
        verify_public_sonar(api, root, "sonar-project-before.json")
    def branch_identity():
        value = api.get("project_branches/list", {"project": PROJECT})
        matches = [b for b in value.get("branches", []) if b.get("name") == branch]
        if len(matches) != 1 or matches[0].get("type") != "LONG" or matches[0].get("isMain") is not (branch == "main") or matches[0].get("commit", {}).get("sha", revision) != revision:
            raise ValueError("Sonar full long-lived branch required")
        return value, matches[0]
    branches_before, branch_before = branch_identity()
    params = {"project": PROJECT, "branch": branch, "p": 1, "ps": 1}
    before = api.get("project_analyses/search", params)
    analyses = before.get("analyses", [])
    if len(analyses) != 1 or analyses[0].get("revision") != revision:
        raise ValueError("latest full Sonar branch analysis must match candidate")
    fresh(analyses[0]["date"])
    candidate = branch != "main"
    gate_before = gate_context = None
    if candidate:
        from sonar_context import runtime_gate_context
        gate_context = runtime_gate_context(revision)
        gate_before = sonar_gate_snapshot(api, gate_context, revision)
        save(root, "sonar-required-gate-before.json", gate_before)
    issues, issue_pages = api.pages("issues/search", {"componentKeys": PROJECT, "branch": branch, "additionalFields": "_all", "issueStatuses": "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED"}, "issues")
    hotspots, hotspot_pages = api.pages("hotspots/search", {"projectKey": PROJECT, "branch": branch}, "hotspots")
    gate = api.get("qualitygates/project_status", {"analysisId": analyses[0]["key"]})
    save(root, "sonar-quality-gate.json", gate)
    # A first-ever LONG inventory has no new-code baseline. NONE is retained
    # as not computed; only the independent exact-source gate can pass.
    if gate.get("projectStatus", {}).get("status") not in (("OK", "NONE") if candidate else ("OK",)):
        raise ValueError("Sonar quality gate did not pass")
    after = api.get("project_analyses/search", params)
    branches_after, branch_after = branch_identity()
    if after != before or branch_after != branch_before:
        raise ValueError("Sonar mutable branch changed during evidence export")
    if candidate:
        gate_after = sonar_gate_snapshot(api, gate_context, revision)
        save(root, "sonar-required-gate-after.json", gate_after)
        if gate_before != gate_after or runtime_gate_context(revision) != gate_context:
            raise ValueError("Sonar required gate changed during inventory export")
    if public_project:
        verify_public_sonar(api, root, "sonar-project-after.json")
    save(root, "sonar-analysis.json", before)
    save(root, "sonar-branches-before.json", branches_before)
    save(root, "sonar-branches-after.json", branches_after)
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
        is_config = name in ("sonar-project.properties", ".github/workflows/ci.yml", ".github/workflows/delivery.yml", ".github/workflows/staging.yml", ".github/workflows/release.yml", ".github/workflows/ssdf-rehearsal.yml", "scripts/release/codeql_evidence.py", "scripts/release/source_sast.py", "scripts/release/sonar_context.py", "scripts/release/sonar_job_evidence.py", ".semgrepignore", ".snyk") or name.startswith((".github/codeql/", ".semgrep/")) or FRONTEND_MEASUREMENT_CONFIG.fullmatch(name) is not None
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
            text = raw.decode()
            lines = text.splitlines(keepends=True)
            coverage_lines = set()
            if name.startswith("web/src/") and path.suffix in (".ts", ".tsx", ".js"):
                starts, offset = [], 0
                for line in lines:
                    starts.append(offset)
                    offset += len(line)
                coverage_lines = {bisect_right(starts, match.start()) for match in COVERAGE_HINT.finditer(text)}
            for index, line in enumerate(text.splitlines(), 1):
                kinds = []
                if "NOSONAR" in line:
                    kinds.append("sonar")
                if re.search(r"\bnosem(?:grep)?\b", line):
                    kinds.append("semgrep")
                if "lgtm[" in line or re.search(r"codeql.*(?:disable|suppress)", line, re.I):
                    kinds.append("codeql")
                if index in coverage_lines:
                    kinds.append("coverage-v8")
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
                if getattr(args, "codeql_evidence", None):
                    from codeql_evidence import consume
                    findings = consume(args.codeql_evidence, args.artifact_manifest, getattr(args, "root", "."), root, args.revision, args.version, args.candidate_id)
                    if (root / "codeql-local").is_dir():
                        findings = link_codeql_history(api or ExportAPI(), root, args.revision, args.version, findings)
                else:
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
    parser.add_argument("--codeql-evidence", help="Same-job sealed full CodeQL evidence directory")
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
