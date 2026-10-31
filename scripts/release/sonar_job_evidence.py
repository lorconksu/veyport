#!/usr/bin/env python3
"""Capture available Sonar job results before mutable provider state moves."""
import argparse
from pathlib import Path
import re
import shlex
import time
import urllib.error
from source_sast import Sonar, PROJECT, save, verify_public_sonar


class CaptureFailure(ValueError):
    """A fixed reason code, never a provider exception or response body."""


class AttemptAPI(Sonar):
    def __init__(self, provider, root, deadline, clock):
        self.provider, self.root, self.deadline, self.clock = provider, root, deadline, clock

    def get(self, endpoint, params):
        if self.clock() >= self.deadline:
            raise CaptureFailure("export-deadline-exceeded")
        try:
            value = self.provider.get(endpoint, params)
        except urllib.error.HTTPError as error:
            # Only the encrypted private evidence receives a bounded response
            # body. Never record exception URLs, request headers or credentials.
            try:
                body = error.read(65537)
            except OSError:
                body = b"[provider error body unavailable]"
            save(self.root, "provider-error.json", {"http_status": error.code,
                 "body": body[:65536].decode("utf-8", errors="replace"), "truncated": len(body) > 65536})
            raise
        # Keep every successful page, including pages preceding a pagination or
        # later endpoint failure. Endpoint names come only from this module.
        name = {"ce/task": "task", "qualitygates/project_status": "quality-gate",
                "project_pull_requests/list": "pull-requests", "project_analyses/search": "analyses",
                "issues/search": "issues", "hotspots/search": "hotspots", "components/show": "project"}[endpoint]
        if "p" in params:
            name += "-page-" + str(params["p"])
        path = self.root / (name + ".json")
        if path.exists():
            name += "-after"
        save(self.root, name + ".json", value)
        if self.clock() >= self.deadline:
            raise CaptureFailure("export-deadline-exceeded")
        return value


def reason(error):
    if isinstance(error, CaptureFailure):
        return str(error)
    if isinstance(error, urllib.error.HTTPError):
        code = error.code
        error.close()
        return "provider-http-" + str(code)
    return {KeyError: "provider-field-missing", TypeError: "provider-shape-invalid",
            AttributeError: "provider-shape-invalid", ValueError: "provider-result-invalid"}.get(type(error), "provider-unavailable")


def collect(report_task, context, revision, output, api=None, timeout=60, clock=None, pause=None, public_project=False):
    api = api or Sonar(public_project=public_project)
    clock, pause = clock or time.monotonic, pause or time.sleep
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    result = {"schema_version": 1, "revision": revision, "status": "partial", "missing": [], "attempts": []}
    stage = "input"
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", revision) or not 1 <= timeout <= 120:
            raise CaptureFailure("invalid-source-or-deadline")
        path = Path(report_task)
        if path.is_symlink() or not 0 < path.stat().st_size <= 65536:
            raise CaptureFailure("scanner-task-identity-unavailable")
        properties = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
        task_id = properties.get("ceTaskId", "")
        if properties.get("serverUrl", "").rstrip("/") != "https://sonarcloud.io" or properties.get("projectKey") != PROJECT or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", task_id):
            raise CaptureFailure("scanner-task-identity-invalid")
        args = dict(arg[2:].split("=", 1) for arg in shlex.split(context) if arg.startswith("-D") and "=" in arg)
        is_pr = "sonar.pullrequest.key" in args
        if is_pr == ("sonar.branch.name" in args):
            raise CaptureFailure("analysis-context-ambiguous-or-missing")
        identity = args["sonar.pullrequest.key"] if is_pr else args["sonar.branch.name"]
        if not re.fullmatch(r"[1-9][0-9]*" if is_pr else r"[A-Za-z0-9_./+@-]{1,240}", identity):
            raise CaptureFailure("analysis-context-invalid")
        result["scope"] = "pull-request-new-code" if is_pr else "full-branch"
        params = {"pullRequest" if is_pr else "branch": identity}
        stage = "task"
        task = api.get("ce/task", {"id": task_id})
        save(root, "task.json", task)
        current = task["task"]
        if current.get("id") != task_id or current.get("componentKey") != PROJECT or current.get("status") != "SUCCESS":
            raise CaptureFailure("scanner-task-not-successful-or-mismatched")
        if is_pr and current.get("pullRequest") != identity or not is_pr and current.get("pullRequest"):
            raise CaptureFailure("scanner-task-context-mismatch")
        analysis_id = current["analysisId"]
        if not isinstance(analysis_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", analysis_id):
            raise CaptureFailure("scanner-analysis-identity-invalid")
        result["analysis_id"] = analysis_id
        if public_project:
            result.update(provider_access="public-project-anonymous", client_authenticated=False,
                          task_access="analysis-token")
        deadline = clock() + timeout

        def snapshot(provider):
            if is_pr:
                matches = [p for p in provider.get("project_pull_requests/list", {"project": PROJECT})["pullRequests"] if p["key"] == identity]
                if len(matches) != 1 or matches[0].get("commit", {}).get("sha") != revision:
                    raise CaptureFailure("pr-source-unavailable-or-superseded")
                return matches[0]
            rows = provider.get("project_analyses/search", {"project": PROJECT, "branch": identity, "ps": 1, "p": 1})["analyses"]
            if len(rows) != 1 or rows[0].get("revision") != revision or rows[0].get("key") != analysis_id:
                raise CaptureFailure("branch-analysis-unavailable-or-superseded")
            return rows[0]

        # A successful CE task can precede convergence of mutable export views.
        # Retry only read-only retrieval, preserving the same task/analysis and
        # exact source checks. Never start another scan or accept a stale view.
        for attempt in range(1, 32):
            attempt_root = root / ("attempt-" + str(attempt).zfill(4))
            attempt_root.mkdir(mode=0o700)
            provider = AttemptAPI(api, attempt_root, deadline, clock)
            try:
                stage = "task-recheck"
                repeated = task if attempt == 1 else provider.get("ce/task", {"id": task_id})
                if repeated != task:
                    # Task status/source fields may never change underneath an
                    # export bound to this successful scanner invocation.
                    for field in ("id", "componentKey", "status", "analysisId", "pullRequest"):
                        if repeated["task"].get(field) != current.get(field):
                            raise CaptureFailure("scanner-task-identity-changed")
                if public_project:
                    stage = "project-visibility-before"
                    verify_public_sonar(provider, attempt_root, "project-before.json")
                stage = "quality-gate"
                gate = provider.get("qualitygates/project_status", {"analysisId": analysis_id})
                save(root, "quality-gate.json", gate)
                stage = "snapshot-before"
                before = snapshot(provider)
                save(attempt_root, "context-before.json", before)
                stage = "issues"
                _, issues = provider.pages("issues/search", {**params, "componentKeys": PROJECT, "additionalFields": "_all", "issueStatuses": "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED"}, "issues")
                save(root, "issues.json", issues)
                stage = "hotspots"
                _, hotspots = provider.pages("hotspots/search", {**params, "projectKey": PROJECT}, "hotspots")
                save(root, "hotspots.json", hotspots)
                stage = "snapshot-after"
                after = snapshot(provider)
                save(attempt_root, "context-after.json", after)
                if before != after:
                    raise CaptureFailure("snapshot-changed-during-export")
                if public_project:
                    stage = "project-visibility-after"
                    verify_public_sonar(provider, attempt_root, "project-after.json")
                save(root, "context.json", before)
                result.update(status="completed", snapshot_binding="stable-exact-revision-context", quality_gate=gate.get("projectStatus", {}).get("status"))
                result.pop("failure_stage", None)
                result.pop("failure_reason", None)
                result["attempts"].append({"attempt": attempt, "status": "completed"})
                break
            except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
                failure_reason = reason(error)
                failure = {"attempt": attempt, "status": "partial", "stage": stage, "reason": failure_reason}
                result["attempts"].append(failure)
                result.update(failure_stage=stage, failure_reason=failure_reason)
                remaining = deadline - clock()
                permanent_http = isinstance(error, urllib.error.HTTPError) and error.code in (400, 401, 403, 404, 405, 410, 422)
                if permanent_http or remaining <= 0 or attempt == 31 or isinstance(error, CaptureFailure) and str(error) == "scanner-task-identity-changed":
                    break
                pause(min(2, remaining))
    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
        result.update(failure_stage=stage, failure_reason=reason(error))
    if result["status"] != "completed":
        result["missing"].append("provider-results-incomplete-or-superseded")
    save(root, "capture.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("report-task", "context", "revision", "output"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--public-project-results", action="store_true", help="Use the analysis token only for task identity; read verified public project results anonymously")
    args = parser.parse_args()
    try:
        result = collect(args.report_task, args.context, args.revision, args.output, timeout=args.timeout, public_project=args.public_project_results)
        if result["status"] != "completed":
            parser.exit(1, "Sonar evidence is partial; independent reconciliation required\n")
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "Sonar evidence capture failed; independent reconciliation required\n")


if __name__ == "__main__":
    main()
