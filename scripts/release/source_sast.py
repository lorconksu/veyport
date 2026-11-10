#!/usr/bin/env python3
"""Export full exact-revision SAST evidence from trusted completed scans."""
import argparse
from bisect import bisect_right
import contextlib
import datetime as dt
import os
from pathlib import Path
import re
import shlex
import subprocess
import stat
import tempfile
import urllib.parse
import urllib.request
import urllib.error
from risk_acceptance import GitHub, REPOSITORY, canonical, now, sha, strict_json, load_record, verify
from scan_contract import SAST_SCANNERS

CODEQL_CATEGORIES = {"/language:" + n for n in ("go", "javascript-typescript", "python", "ruby", "actions")}
CODEQL_DEFAULT_KEY = "dynamic/github-code-scanning/codeql:analyze"
MAX_BYTES = 16 << 20
SONAR_PAGE_SIZE = 500
MAX_SONAR_PAGES = 100
MAX_SONAR_INVENTORY_BYTES = 64 << 20
MAX_SONAR_ARCHIVE_BYTES = 2 * MAX_SONAR_INVENTORY_BYTES
MAX_SONAR_ARCHIVE_PAGES = 4 * MAX_SONAR_PAGES
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

# Conservative tracked-file superset of the active CodeQL languages, including
# JS-associated templates/data. Source roots must not narrow Python/Actions to
# Sonar's smaller roots. Source paths bind the coverage inventory; only annotated
# sources bind complete file bytes. Candidate revision separately binds ordinary
# unannotated code changes. This inventory is not a proof of extraction.
SCANNED_SUFFIXES = frozenset({
    '.go', '.py', '.rb', '.erb', '.gemspec', '.js', '.jsx', '.mjs', '.cjs',
    '.es', '.es6', '.ts', '.tsx', '.mts', '.cts', '.htm', '.html', '.xhtm',
    '.xhtml', '.vue', '.hbs', '.ejs', '.njk', '.json', '.yaml', '.yml', '.raml', '.xml',
})
POLICY_HELPER_ROOTS = ('scripts/release/', 'scripts/security/', 'scripts/native-candidate/',
                       'scripts/proto/', 'scripts/review/')
MAX_INVENTORY_FILES = 10000
MAX_INVENTORY_TOTAL = 64 << 20
MAX_INVENTORY_FILE = 4 << 20
# Inventory keyword candidates conservatively: this covers bracket/whitespace
# and disable/suppress forms without pretending to parse extractor semantics.
CODEQL_HINT = re.compile(r'\b(?:lgtm|codeql)\b', re.I)
PYTHON_HINT = re.compile(r'\b(?:noqa|nosec)\b', re.I)


def inventory_kind(name):
    path = Path(name)
    source = path.suffix.lower() in SCANNED_SUFFIXES or path.name == 'Gemfile'
    action = (name.startswith('.github/workflows/') and path.suffix in ('.yml', '.yaml')
              or path.name in ('action.yml', 'action.yaml'))
    config = (name in ('sonar-project.properties', '.semgrepignore', 'lgtm.yml', '.lgtm.yml', 'Makefile')
              or path.name in ('.snyk', '.gitignore', '.gitattributes', '.gitleaks.toml', '.gitleaksignore',
                               '.semgrepignore', '.coveragerc', 'pyproject.toml',
                               'setup.cfg', 'tox.ini', '.flake8', '.bandit')
              or action or name.startswith(('.github/codeql/', '.semgrep/'))
              or (name.startswith(POLICY_HELPER_ROOTS) and path.suffix in ('.py', '.sh'))
              or FRONTEND_MEASUREMENT_CONFIG.fullmatch(name) is not None)
    return source or action, config


def inventory_read(root, name):
    # Git does not track links to directories, but an untrusted workspace can
    # replace a tracked parent after checkout. Open every component without links.
    parts = name.split('/')
    if not parts or any(part in ('', '.', '..') for part in parts) or '\\' in name:
        raise ValueError('source policy inventory is incomplete')
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        source_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        with os.fdopen(source_fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INVENTORY_FILE:
                raise ValueError('source policy inventory is incomplete')
            raw = source.read(MAX_INVENTORY_FILE + 1)
            if len(raw) > MAX_INVENTORY_FILE:
                raise ValueError('source policy inventory is incomplete')
            return raw
    except OSError as exc:
        raise ValueError('source policy inventory is incomplete') from exc
    finally:
        os.close(descriptor)


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
    # Include Sonar's documented category CWE members as well as the original
    # policy CWEs. Sonar security standards use cwe:NNN; SARIF also uses paths.
    # https://github.com/SonarSource/sonarqube/blob/master/server/sonar-server-common/src/main/java/org/sonar/server/security/SecurityStandards.java
    classes = {
        "authentication": (287, 306, 307, 308, 290, 294, 798, 640, 620, 549, 522, 521, 263, 262, 261, 259),
        "authorization": (285, 639, 862, 863, 732, 266, 269, 284, 668),
        "required-audit": (778,),
    }
    for classification, identifiers in classes.items():
        identifiers = "|".join("0*" + str(value) for value in identifiers)
        if re.search(r"(?<![a-z0-9])cwe[-/: ]*(?:" + identifiers + r")\b", tags):
            return classification
    return "unresolved"


def classify_sonar(tags):
    # Issues inherit rule tags; hotspots supply a native securityCategory.
    # Use exact normalized tokens, never rule names/messages or substrings.
    # https://docs.sonarsource.com/sonarqube-server/quality-standards-administration/managing-rules/built-in-rule-tags
    # SecurityStandards.java (above): AUTH, PERMISSION, TRACEABILITY (CWE778).
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("invalid Sonar classification metadata")
    tokens = {tag.strip().lower() for tag in tags}
    for classification, labels in (
        ("authentication", {"auth", "authentication"}),
        ("authorization", {"permission", "authorization", "authz"}),
        ("required-audit", {"traceability", "required-audit"}),
    ):
        if tokens & labels:
            return classification
    return classify(tokens)


def severity(rule, result):
    score = rule.get("properties", {}).get("security-severity")
    if score is not None:
        score = float(score)
        if not 0 <= score <= 10:
            raise ValueError("invalid security severity")
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}[result.get("level", "warning")]



def _codeql_alert_map(alerts):
    if not isinstance(alerts, (list, tuple)):
        raise ValueError("CodeQL alert inventory malformed")
    mapped = {}
    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError("CodeQL alert inventory malformed")
        number = alert.get("number")
        if type(number) is not int or number < 1 or number in mapped:
            raise ValueError("ambiguous CodeQL alert inventory")
        mapped[number] = alert
    return mapped


def _sarif_alert_number(result):
    properties = result.get("properties", {})
    if not isinstance(properties, dict):
        raise ValueError("SARIF alert metadata malformed")
    if "github/alertNumber" not in properties:
        return None
    number = properties["github/alertNumber"]
    if type(number) is not int or number < 1:
        raise ValueError("SARIF alert identity malformed")
    return number


def _sarif_suppressions(result):
    records = result.get("suppressions")
    if records is None:
        return None, False
    if not isinstance(records, list) or any(not isinstance(record, dict)
            or record.get("kind") not in ("inSource", "external")
            or "status" in record and record["status"] not in ("accepted", "underReview", "rejected")
            for record in records):
        raise ValueError("SARIF suppression metadata malformed")
    # SARIF 2.1 + Errata01 3.27.23 / 3.35.3 specifies optional status
    # without an accepted default. Preserve absent/review/rejected information;
    # only an explicitly accepted request is effective.
    return strict_json(canonical(records)), any(record.get("status") == "accepted" for record in records)


def _codeql_correlation_location(value, provider=False, artifacts=None):
    """Compare only independently representable primary source ranges."""
    if not isinstance(value, dict):
        raise ValueError("CodeQL correlation location missing")
    if provider:
        path, region = value.get("path"), value
        start, end = region.get("start_line"), region.get("end_line")
        left, right = region.get("start_column"), region.get("end_column")
        if any(key in region and type(region[key]) is not int for key in ("start_column", "end_column")):
            raise ValueError("CodeQL correlation column metadata malformed")
        # CodeQL whole-line locations use zero columns. Missing/zero columns
        # never establish a precise character range; match only whole lines.
        if ((left is None or type(left) is int and left in (0, 1))
                and (right is None or type(right) is int and right == 0)):
            left, right = 1, None
        elif type(left) is not int or left < 1 or type(right) is not int or right < 1:
            raise ValueError("CodeQL correlation column precision unknown")
    else:
        physical = value.get("physicalLocation", {})
        if not isinstance(physical, dict):
            raise ValueError("CodeQL correlation physical location malformed")
        artifact = physical.get("artifactLocation", {})
        region = physical.get("region", {})
        if not all(isinstance(item, dict) for item in (physical, artifact, region)):
            raise ValueError("CodeQL correlation location malformed")
        # No guessed checkout root or artifact-table alias may change the path
        # used to associate an independently supplied GitHub alert.
        if "uriBaseId" in artifact:
            raise ValueError("CodeQL correlation URI alias unresolved")
        if "index" in artifact:
            index = artifact["index"]
            if (type(index) is not int or index < 0 or not isinstance(artifacts, list)
                    or index >= len(artifacts) or not isinstance(artifacts[index], dict)):
                raise ValueError("CodeQL correlation URI alias unresolved")
            indexed = artifacts[index].get("location")
            if (not isinstance(indexed, dict) or indexed.get("uri") != artifact.get("uri")
                    or "uriBaseId" in indexed or "index" in indexed and
                    (type(indexed["index"]) is not int or indexed["index"] != index)):
                raise ValueError("CodeQL correlation URI alias unresolved")
        uri = artifact.get("uri")
        if not isinstance(uri, str) or re.search(r"%(?![0-9A-Fa-f]{2})", uri):
            raise ValueError("CodeQL correlation URI malformed")
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
            raise ValueError("CodeQL correlation requires repository relative URI")
        try:
            path = urllib.parse.unquote_to_bytes(parsed.path).decode("utf-8")
        except UnicodeError as error:
            raise ValueError("CodeQL correlation URI encoding malformed") from error
        start, end = region.get("startLine"), region.get("endLine", region.get("startLine"))
        left, right = region.get("startColumn", 1), region.get("endColumn")
        if (type(left) is not int or left < 1 or ("endColumn" in region and (type(right) is not int or right < 1))
                or any(key in region for key in ("charOffset", "charLength", "byteOffset", "byteLength"))):
            raise ValueError("CodeQL correlation requires line/column region")
    if (not isinstance(path, str) or not path or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or type(start) is not int or start < 1 or type(end) is not int or end < start
            or start == end and right is not None and right < left):
        raise ValueError("CodeQL correlation source range malformed")
    return path, start, end, left, right


def _codeql_provider_key(alert):
    instance = alert.get("most_recent_instance")
    rule, tool = alert.get("rule"), alert.get("tool")
    if (not isinstance(instance, dict) or not isinstance(rule, dict) or not isinstance(tool, dict)
            or tool.get("name") != "CodeQL" or not isinstance(rule.get("id"), str) or not rule["id"]
            or any(not isinstance(instance.get(key), str) or not instance[key] for key in ("ref", "analysis_key", "category"))
            or not isinstance(instance.get("commit_sha"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", instance["commit_sha"])):
        raise ValueError("CodeQL correlation provider identity missing")
    return (rule["id"], instance["ref"], instance["analysis_key"], instance["category"].rstrip("/"),
            instance["commit_sha"], _codeql_correlation_location(instance.get("location"), provider=True))


def _codeql_result_key(run, result, revision):
    automation = run.get("automationDetails", {})
    provenance = run.get("versionControlProvenance", [])
    locations = result.get("locations")
    if (not isinstance(automation, dict) or not isinstance(automation.get("id"), str)
            or not isinstance(provenance, list) or not provenance or any(not isinstance(p, dict) or p.get("branch") != "refs/heads/main" for p in provenance)
            or not isinstance(locations, list) or not locations):
        raise ValueError("CodeQL correlation source scope missing")
    category = automation["id"].rstrip("/")
    if category not in CODEQL_CATEGORIES:
        raise ValueError("CodeQL correlation source scope missing")
    return (result["ruleId"], "refs/heads/main", CODEQL_DEFAULT_KEY, category, revision,
            _codeql_correlation_location(result["locations"][0], artifacts=run.get("artifacts")))


def _codeql_correlated_alerts(raw, alert_map, revision, historical=False):
    # Alert numbers are not a license to transfer another result's disposition.
    # GitHub exposes primary ranges/context, not SARIF flow fingerprints; reject
    # collisions in those available dimensions instead of pretending otherwise.
    results, seen = [], set()
    for run in raw["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            raise ValueError("CodeQL correlation result inventory malformed")
        for result in run["results"]:
            if not isinstance(result, dict) or not isinstance(result.get("ruleId"), str):
                raise ValueError("CodeQL correlation result identity malformed")
            number = _sarif_alert_number(result)
            if number is not None:
                if number in seen:
                    raise ValueError("duplicate SARIF alert number")
                seen.add(number)
            results.append((run, result, number))
    requested = {number for _, _, number in results if number in alert_map}
    if not requested:
        return {}
    rules = {result["ruleId"] for _, result, number in results if number in requested}
    normalize = (lambda key: key[:4] + key[5:]) if historical else (lambda key: key)
    provider_keys, counts = {}, {}
    for number, alert in alert_map.items():
        tool, rule = alert.get("tool"), alert.get("rule")
        if number in requested or (isinstance(tool, dict) and tool.get("name") == "CodeQL"
                and isinstance(rule, dict) and rule.get("id") in rules):
            key = normalize(_codeql_provider_key(alert))
            provider_keys[number] = key
            counts[key] = counts.get(key, 0) + 1
    result_keys, result_counts = {}, {}
    for run, result, number in results:
        if result["ruleId"] in rules:
            key = normalize(_codeql_result_key(run, result, revision))
            result_keys[id(result)] = key
            result_counts[key] = result_counts.get(key, 0) + 1
    matched = {}
    for _, result, number in results:
        if number not in requested:
            continue
        key = result_keys[id(result)]
        if provider_keys[number] != key:
            raise ValueError("CodeQL alert/result correlation mismatch")
        if counts[key] != 1 or result_counts[key] != 1:
            raise ValueError("ambiguous CodeQL alert/result correlation")
        matched[number] = alert_map[number]
    return matched


def sarif_findings(raw, scanner, revision, version, alerts=(), local_codeql=False):
    if not isinstance(raw, dict) or raw.get("version") != "2.1.0" or not isinstance(raw.get("runs"), list) or not raw["runs"]:
        raise ValueError("complete SARIF runs required")
    findings = []
    alert_map = _codeql_alert_map(alerts)
    if scanner == "codeql":
        alert_map = _codeql_correlated_alerts(raw, alert_map, revision)
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
            number = _sarif_alert_number(result)
            alert = alert_map.get(number)
            identity = "alert:" + str(number) if number is not None else rule_id + ":" + sha(canonical({"locations": locations, "fingerprints": result.get("partialFingerprints", {})}))[:20]
            if len(identity) > 256:
                identity = "rule:" + sha(identity.encode())
            classification = classify(rule.get("properties", {}).get("tags", []))
            suppressions, sarif_suppressed = _sarif_suppressions(result)
            provider_dismissed = bool(alert and alert.get("state") == "dismissed")
            if provider_dismissed:
                reason = alert.get("dismissed_reason")
                classification = "false-positive" if reason == "false positive" else "not-affected" if reason == "used in tests" else classification
            findings.append({"scanner": scanner, "id": identity, "component": component, "version": version,
                             "severity": severity(rule, result), "classification": classification,
                             "first_seen": date(alert.get("created_at")) if alert else None,
                             "rule_id": rule_id, "suppressed": sarif_suppressed or provider_dismissed,
                             "sarif_suppressions": suppressions,
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


def private_sonar_bytes(path, data):
    with path.open('xb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class SonarArchiveBudget:
    """One direct export: shared raw-byte/page bounds across both endpoints."""
    def __init__(self, root):
        self.root = Path(root)
        self.remaining = MAX_SONAR_ARCHIVE_BYTES
        self.pages = 0
        self.omission_recorded = False

    def omission(self, path, reason):
        if not self.omission_recorded:
            private_sonar_bytes(path, canonical({'status': 'not-requested', 'reason': reason,
                                                 'received_bytes': 0, 'retained_bytes': 0}))
            self.omission_recorded = True


class SonarPageArchive:
    """Private direct-export attempt; never stores request headers or URLs."""
    def __init__(self, budget, key):
        parent = budget.root / 'sonar-page-attempts'
        parent.mkdir(mode=0o700, exist_ok=True)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('private Sonar page archive required')
        self.root = Path(tempfile.mkdtemp(prefix=key + '-', dir=parent))
        self.budget = budget

    def page(self, observation, page):
        name = observation + '-page-' + str(page)
        if self.budget.pages >= MAX_SONAR_ARCHIVE_PAGES or self.budget.remaining == 0:
            self.budget.omission(self.root / (name + '.json'), 'archive-budget-exhausted')
            raise ValueError('Sonar page archive budget exhausted')
        self.budget.pages += 1
        return SonarPageCapture(self, name)


class SonarPageCapture:
    def __init__(self, archive, name):
        self.archive, self.name, self.saved = archive, name, False

    def write(self, raw, representation, http_status=None):
        if self.saved:
            raise ValueError('Sonar page already captured')
        retained = raw[:min(MAX_BYTES, self.archive.budget.remaining)]
        self.archive.budget.remaining -= len(retained)
        receipt = {'representation': representation, 'received_bytes': len(raw),
                   'retained_bytes': len(retained), 'sha256': sha(retained),
                   'truncated': len(retained) != len(raw), 'http_status': http_status}
        for suffix, data in (('.body', retained), ('.json', canonical(receipt))):
            private_sonar_bytes(self.archive.root / (self.name + suffix), data)
        self.saved = True
        if receipt['truncated']:
            raise ValueError('Sonar response archive exceeded bound')

    def unavailable(self):
        if not self.saved:
            private_sonar_bytes(self.archive.root / (self.name + '.json'),
                                canonical({'status': 'response-unavailable', 'received_bytes': None,
                                           'retained_bytes': 0}))
            self.saved = True


@contextlib.contextmanager
def archive_sonar_pages(api, root):
    """Direct delivery exports need capture; AttemptAPI already records its reads."""
    previous = getattr(api, '_page_archive_budget', None)
    api._page_archive_budget = SonarArchiveBudget(root)
    try:
        yield
    finally:
        api._page_archive_budget = previous


class Sonar:
    def __init__(self, public_project=False):
        self.public_project = public_project

    def get(self, endpoint, params):
        headers = {"Accept": "application/json"}
        if self.public_project:
            selectors = {"components/show": "component", "project_pull_requests/list": "project",
                         "project_analyses/search": "project", "issues/search": "componentKeys",
                         "hotspots/search": "projectKey", "project_branches/list": "project"}
            if endpoint == "ce/component":
                if params != {"component": PROJECT}:
                    raise ValueError("Sonar public task reader requires the fixed project")
            elif endpoint == "qualitygates/project_status":
                exact_analysis = set(params) == {"analysisId"} and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", params["analysisId"])
                exact_pr = set(params) == {"projectKey", "pullRequest"} and params["projectKey"] == PROJECT and re.fullmatch(r"[1-9][0-9]*", params["pullRequest"])
                if not (exact_analysis or exact_pr):
                    raise ValueError("Sonar exact analysis identity required")
            elif endpoint not in selectors or params.get(selectors[endpoint]) != PROJECT:
                raise ValueError("Sonar public reader requires the fixed project")
            # This is a deliberate mode, never a fallback after an auth error.
            # Public task identity also uses a fixed-project anonymous read.
            # ce/task requires analysis credentials and is unavailable here.
        else:
            token = os.environ.get("SONAR_TOKEN")
            if not token:
                raise ValueError("Sonar authentication missing")
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request("https://sonarcloud.io/api/" + endpoint + "?" + urllib.parse.urlencode(params), headers=headers)
        capture = getattr(self, '_page_capture', None)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
                data = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as error:
            # Do not consume a delegated AttemptAPI error body: it archives that
            # body itself. Direct exports archive only bounded bytes, never the
            # exception URL or credential-bearing request headers.
            if capture is not None:
                try:
                    capture.write(error.read(MAX_BYTES + 1), 'wire', error.code)
                finally:
                    error.close()
            raise
        if capture is not None:
            capture.write(data, 'wire')
        if len(data) > MAX_BYTES:
            raise ValueError("Sonar evidence exceeds bound")
        return strict_json(data)

    def pages(self, endpoint, params, key):
        """Require two complete, duplicate-free observations of the same rows.

        Sonar search is mutable and exposes no immutable export token. Matching
        ID/full-row inventories plus caller analysis/gate checks establish bounded
        observed consistency, not an atomic provider snapshot or protection from
        arbitrary changes between reads. Drift fails this attempt; callers may
        retry the entire export under their existing deadline, never partial pages.
        """
        if {"issues/search": "issues", "hotspots/search": "hotspots"}.get(endpoint) != key:
            raise ValueError("unsupported Sonar inventory")
        proofs = dict(getattr(self, 'inventory_readback', {}))
        proofs.pop(endpoint, None)
        self.inventory_readback = proofs
        budget = getattr(self, '_page_archive_budget', None)
        archive = SonarPageArchive(budget, key) if budget is not None else None
        rows, pages, inventory, metadata, page_hashes = self._page_pass(endpoint, params, key, retain=True, archive=archive)
        _, _, repeated, repeated_metadata, repeated_hashes = self._page_pass(endpoint, params, key, retain=False, metadata=metadata, archive=archive, observation='readback')
        if inventory != repeated or metadata != repeated_metadata:
            raise ValueError("Sonar inventory changed during readback")
        proofs[endpoint] = {"observations": 2, "consistency": "matching-id-and-full-row-inventories",
                            "immutable_snapshot": False, "total": metadata[0], "page_size": metadata[1],
                            "inventory_sha256": sha(canonical(inventory)),
                            "page_sha256": page_hashes, "readback_page_sha256": repeated_hashes}
        return rows, pages

    def _page_pass(self, endpoint, params, key, retain, metadata=None, archive=None, observation='initial'):
        rows, pages, inventory, hashes = [], [], {}, []
        retained_bytes = 0
        for page in range(1, MAX_SONAR_PAGES + 1):
            previous = getattr(self, '_page_capture', None)
            capture = archive.page(observation, page) if archive is not None else None
            self._page_capture = capture
            try:
                result = self.get(endpoint, {**params, "ps": SONAR_PAGE_SIZE, "p": page})
                if capture is not None and not capture.saved:
                    # Custom adapters can return decoded objects instead of
                    # exposing transport bytes. Label that representation; do
                    # not falsely describe re-serialized JSON as original wire.
                    capture.write(canonical(result), 'canonical-decoded-json')
            except (ValueError, OSError, TypeError, KeyError):
                if capture is not None:
                    capture.unavailable()
                raise
            finally:
                self._page_capture = previous
            chunk, current = sonar_page(result, key, page)
            if metadata is not None and current != metadata:
                raise ValueError("Sonar pagination metadata changed")
            metadata = current
            raw = canonical(result)
            retained_bytes += len(raw)
            if retained_bytes > MAX_SONAR_INVENTORY_BYTES:
                raise ValueError("Sonar inventory exceeded byte bound")
            hashes.append(sha(raw))
            for row in chunk:
                identity = sonar_row_identity(row)
                if identity in inventory:
                    raise ValueError("Sonar duplicate finding identity")
                inventory[identity] = sha(canonical(row))
            if retain:
                rows.extend(chunk)
                pages.append(result)
            if len(inventory) == metadata[0]:
                return rows, pages, inventory, metadata, hashes
        raise ValueError("Sonar complete pagination exceeded bound")


def sonar_page(result, key, page):
    """Validate actual returned page size; valid provider clamping is allowed."""
    paging = result.get('paging') if isinstance(result, dict) else None
    if not isinstance(paging, dict):
        raise ValueError("Sonar pagination metadata missing")
    total, size, index = (paging.get(name) for name in ('total', 'pageSize', 'pageIndex'))
    if (type(total) is not int or type(size) is not int or type(index) is not int
            or not 1 <= size <= SONAR_PAGE_SIZE or not 0 <= total <= size * MAX_SONAR_PAGES or index != page):
        raise ValueError("Sonar pagination metadata invalid")
    chunk = result.get(key)
    remaining = total - (page - 1) * size
    if not isinstance(chunk, list) or remaining < 0 or len(chunk) != min(size, remaining):
        raise ValueError("Sonar pagination incomplete or made no progress")
    return chunk, (total, size)


def sonar_row_identity(row):
    # Both issues/search and hotspots/search expose the opaque issue identity as
    # `key`; component/rule/message are not identities and may legitimately repeat.
    identity = row.get('key') if isinstance(row, dict) else None
    if not isinstance(identity, str) or re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identity) is None:
        raise ValueError("Sonar finding identity invalid")
    return identity


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
    fields = ("scanner", "id", "component", "version", "rule_id", "severity", "classification", "suppressed", "provider_state", "sarif_suppressions")
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
    return _codeql_alert_map(alerts)


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
    alert = alert_map.get(_sarif_alert_number(result))
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
    try:
        alert_map = _codeql_correlated_alerts(raw, alert_map, source["revision"], historical=True)
    except ValueError as error:
        source["alert_correlation_error"] = str(error)
        # Latest provider coordinates can legitimately differ from a historical
        # result. Keep its date unknown; never import current dismissal state.
        return
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
    # Delivery invokes this direct path without AttemptAPI. Archive each bounded
    # received page before parsing/pagination checks, including failed readback.
    # Unique private attempt directories retain failures without success proofs.
    with archive_sonar_pages(api, root):
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
    if getattr(api, 'inventory_readback', None):
        save(root, "sonar-inventory-readback.json", api.inventory_readback)
    save(root, "sonar-quality-gate.json", gate)
    findings = []
    for issue in issues:
        impacts = [i for i in issue.get("impacts", []) if i.get("softwareQuality") == "SECURITY"]
        if issue.get("type") != "VULNERABILITY" and not impacts:
            continue
        state = issue.get("issueStatus", issue.get("status"))
        if state in ("FIXED", "CLOSED") and issue.get("resolution") not in ("FALSE-POSITIVE", "WONTFIX"):
            continue
        classification = "false-positive" if state == "FALSE_POSITIVE" or issue.get("resolution") == "FALSE-POSITIVE" else classify_sonar(issue.get("tags", []) + issue.get("internalTags", []))
        impact_levels = [impact.get("severity") for impact in impacts]
        impact_rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "BLOCKER": 4}
        if any(not isinstance(value, str) or value not in impact_rank for value in impact_levels):
            raise ValueError("unknown Sonar security severity")
        level = max(impact_levels, default=None, key=impact_rank.get)
        severity_value = {"BLOCKER": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}.get(level) if level else {"BLOCKER": "critical", "CRITICAL": "high", "MAJOR": "medium", "MINOR": "low", "INFO": "info"}.get(issue.get("severity"))
        if severity_value is None:
            raise ValueError("unknown Sonar security severity")
        findings.append({"scanner": "sonar", "id": issue["key"], "component": issue["component"], "version": version, "severity": severity_value, "classification": classification, "first_seen": date(issue.get("creationDate")), "provider_state": state, "rule_id": issue["rule"]})
    for hotspot in hotspots:
        classification = "not-affected" if hotspot.get("resolution") == "SAFE" else classify_sonar([hotspot.get("securityCategory", "")])
        findings.append({"scanner": "sonar", "id": hotspot["key"], "component": hotspot["component"], "version": version, "severity": {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}[hotspot["vulnerabilityProbability"]], "classification": classification, "first_seen": date(hotspot.get("creationDate")), "provider_state": hotspot["status"], "rule_id": hotspot["ruleKey"]})
    return findings


def suppression_inventory(root):
    root = Path(root)
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    configs, sources, annotations, total = [], [], [], 0
    names = [name for name in tracked if name]
    if len(names) > MAX_INVENTORY_FILES or len(names) != len(set(names)):
        raise ValueError('source policy inventory is incomplete')
    for name in sorted(names):
        path = root / name
        is_source, is_config = inventory_kind(name)
        if not is_config and not is_source:
            continue
        raw = inventory_read(root, name)
        total += len(raw)
        if total > MAX_INVENTORY_TOTAL:
            raise ValueError('source policy inventory is incomplete')
        digest = sha(raw)
        if is_config:
            configs.append({'path': name, 'sha256': digest})
        if is_source:
            sources.append(name)
            text = raw.decode()
            lines = text.splitlines(keepends=True)
            coverage_lines = set()
            if name.startswith("web/src/") and path.suffix.lower() in (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"):
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
                if CODEQL_HINT.search(line):
                    kinds.append("codeql")
                if path.suffix == ".py" and PYTHON_HINT.search(line):
                    kinds.append("python-suppression")
                if index in coverage_lines:
                    kinds.append("coverage-v8")
                if kinds:
                    annotations.append({"path": name, "line": index, "scanners": kinds, "annotation_sha256": sha(line.encode()), "source_sha256": digest})
    return {"schema_version": 2, "repository": REPOSITORY, "configurations": configs, "sources": sources, "annotations": annotations}


def reviewed_inventory(inventory_hash, directory, api):
    """Historical v1 evidence validator; operational collection does not call it."""
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
    envelope = {"schema_version": 1, "candidate_id": args.candidate_id, "revision": args.revision, "artifact_manifest_sha256": sha(Path(args.artifact_manifest).read_bytes()), "status": "failed", "required_scopes": ["source:sast:" + n for n in SAST_SCANNERS], "scopes": []}
    for scanner in SAST_SCANNERS:
        scope = {"id": "source:sast:" + scanner, "status": "failed", "authenticated": False, "coverage_complete": False, "findings": []}
        envelope["scopes"].append(scope)
        try:
            if scanner == "codeql":
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
                    # authenticated records trusted report provenance;
                    # it is not a client login claim.
                    scope.update(provider_access="public-project-anonymous", client_authenticated=False)
            scope.update(status="completed", authenticated=True, coverage_complete=True, findings=findings)
        except (ValueError, OSError, KeyError, TypeError, ImportError, AttributeError):
            scope["error"] = "Exact-source full baseline export incomplete; private diagnostics required."
    try:
        inventory = suppression_inventory(getattr(args, "root", "."))
        inventory_hash = sha(canonical(inventory))
        save(root, "source-policy-inventory.json", inventory)
        inventory_complete = True
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        inventory_complete = False
    # Preserve exporter truth separately from the missing owner policy decision.
    # Legacy consumers still see coverage_complete:false and cannot pass. Only a
    # private consumer with exact CR proof may combine these independent facts.
    envelope["coverage_policy"] = {"status": "pending-owner-policy-review", "inventory_sha256": locals().get("inventory_hash"),
                                   "technical_status": "completed" if inventory_complete else "failed"}
    for scope in envelope["scopes"]:
        scope["technical_coverage_complete"] = scope["coverage_complete"]
        scope["coverage_complete"] = False
    if inventory_complete and all(s["status"] == "completed" for s in envelope["scopes"]):
        envelope["status"] = "completed"
    save(root, "assessment.json", envelope)
    Path(args.assessment).write_bytes(canonical(envelope) + b"\n")
    return envelope["status"] == "completed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("output", "assessment", "revision", "version", "candidate-id", "artifact-manifest", "sonar-branch"):
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
    except (ValueError, OSError, KeyError, TypeError, AttributeError):
        parser.exit(1, "source SAST evidence failed; publication prohibited\n")


if __name__ == "__main__":
    main()
