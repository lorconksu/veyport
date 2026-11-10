#!/usr/bin/env python3
"""Capture available Sonar job results before mutable provider state moves."""
import argparse
from pathlib import Path
import re
import shlex
import time
import urllib.error
from source_sast import Sonar, PROJECT, save, verify_public_sonar, sonar_gate_snapshot
from sonar_context import candidate_branch, runtime_gate_context


class CaptureFailure(ValueError):
    """A fixed reason code, never a provider exception or response body."""


class AttemptAPI(Sonar):
    def __init__(self, provider, root, deadline, clock):
        self.provider, self.root, self.deadline, self.clock = provider, root, deadline, clock
        self.read_counts = {}

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
        name = {"ce/task": "task", "ce/component": "task-component", "qualitygates/project_status": "quality-gate",
                "project_pull_requests/list": "pull-requests", "project_analyses/search": "analyses",
                "project_branches/list": "branches",
                "issues/search": "issues", "hotspots/search": "hotspots", "components/show": "project"}[endpoint]
        if "p" in params:
            name += "-page-" + str(params["p"])
        count = self.read_counts.get(name, 0) + 1
        self.read_counts[name] = count
        if count > 1:
            name += "-read-" + str(count).zfill(4)
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


def collect(report_task, context, revision, output, api=None, timeout=60, clock=None, pause=None, public_project=False, gate_context=None):
    api = api or Sonar(public_project=public_project)
    clock, pause = clock or time.monotonic, pause or time.sleep
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    result = {"schema_version": 1, "revision": revision, "status": "partial", "missing": [], "attempts": []}
    stage = "input"
    try:
        if not re.fullmatch(r"[0-9a-f]{40}", revision) or not 1 <= timeout <= 600:
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
        if not is_pr and identity not in ("main", candidate_branch(revision)):
            raise CaptureFailure("full-branch-context-not-source-bound")
        result["scope"] = "pull-request-new-code" if is_pr else "full-branch"
        inventory_only = not is_pr and identity != "main"
        params = {"pullRequest" if is_pr else "branch": identity}
        def task_snapshot(provider, current_only=False):
            if not public_project and not current_only:
                return provider.get("ce/task", {"id": task_id})
            # The public component view exposes pending/current tasks, not
            # arbitrary historical task details. Never substitute another task
            # when the scanner's exact id is absent or has been superseded.
            component = provider.get("ce/component", {"component": PROJECT})
            queue = component.get("queue")
            current = component.get("current")
            if not isinstance(queue, list) or len(queue) > 1000 or current is not None and not isinstance(current, dict):
                raise CaptureFailure("scanner-task-public-view-invalid")
            tasks = queue + ([current] if current is not None else [])
            if any(not isinstance(task, dict) for task in tasks):
                raise CaptureFailure("scanner-task-public-view-invalid")
            matches = [task for task in tasks if task.get("id") == task_id]
            if len(matches) != 1 or current_only and (current is None or current.get("id") != task_id):
                raise CaptureFailure("scanner-task-unavailable-or-superseded")
            return {"task": matches[0]}

        stage = "task"
        deadline = clock() + timeout
        while True:
            if clock() >= deadline:
                raise CaptureFailure("scanner-task-deadline-exceeded")
            task = task_snapshot(api)
            save(root, "task.json", task)
            current = task["task"]
            if current.get("id") != task_id or current.get("componentKey") != PROJECT:
                raise CaptureFailure("scanner-task-not-successful-or-mismatched")
            if is_pr and current.get("pullRequest") != identity or not is_pr and current.get("pullRequest"):
                raise CaptureFailure("scanner-task-context-mismatch")
            if current.get("status") == "SUCCESS":
                break
            if current.get("status") not in ("PENDING", "IN_PROGRESS"):
                raise CaptureFailure("scanner-task-not-successful-or-mismatched")
            pause(min(2, max(0, deadline - clock())))
        analysis_id = current["analysisId"]
        if not isinstance(analysis_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", analysis_id):
            raise CaptureFailure("scanner-analysis-identity-invalid")
        result["analysis_id"] = analysis_id
        if public_project:
            result.update(provider_access="public-project-anonymous", client_authenticated=False,
                          task_access="public-project-component", task_binding="exact-scanner-task-id")

        def snapshot(provider):
            if is_pr:
                matches = [p for p in provider.get("project_pull_requests/list", {"project": PROJECT})["pullRequests"] if p["key"] == identity]
                if len(matches) != 1 or matches[0].get("commit", {}).get("sha") != revision:
                    raise CaptureFailure("pr-source-unavailable-or-superseded")
                # The PR view has no authoritative analysis id. Compare its
                # current gate with the exact task's analysis-specific gate;
                # independent current-component reads bind the observed task.
                current_gate = provider.get("qualitygates/project_status", {"projectKey": PROJECT, "pullRequest": identity})
                if current_gate != gate or matches[0].get("status", {}).get("qualityGateStatus") != gate.get("projectStatus", {}).get("status"):
                    raise CaptureFailure("pr-current-quality-gate-not-task-bound")
                return matches[0]
            branches = provider.get("project_branches/list", {"project": PROJECT})["branches"]
            matches = [b for b in branches if b.get("name") == identity]
            if len(matches) != 1 or matches[0].get("type") != "LONG" or matches[0].get("isMain") is not (identity == "main"):
                raise CaptureFailure("branch-not-long-lived-or-source-mismatched")
            rows = provider.get("project_analyses/search", {"project": PROJECT, "branch": identity, "ps": 1, "p": 1})["analyses"]
            if len(rows) != 1 or rows[0].get("revision") != revision or rows[0].get("key") != analysis_id:
                raise CaptureFailure("branch-analysis-unavailable-or-superseded")
            return {"branch": matches[0], "analysis": rows[0]}

        # A successful CE task can precede convergence of mutable export views.
        # Retry only read-only retrieval, preserving the same task/analysis and
        # exact source checks. Never start another scan or accept a stale view.
        retry_delay = min(5, timeout / 4)
        trusted_gate_context = None
        for attempt in range(1, int(timeout / retry_delay) + 2):
            if clock() >= deadline:
                break
            attempt_root = root / ("attempt-" + str(attempt).zfill(4))
            attempt_root.mkdir(mode=0o700)
            provider = AttemptAPI(api, attempt_root, deadline, clock)
            try:
                stage = "task-recheck"
                repeated = task_snapshot(provider, current_only=True)
                save(attempt_root, "task-before.json", repeated)
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
                required_before = None
                if inventory_only:
                    stage = "required-quality-gate-before"
                    if trusted_gate_context is None:
                        if not gate_context or runtime_gate_context(revision) != gate_context:
                            raise CaptureFailure("required-quality-gate-context-mismatch")
                        trusted_gate_context = gate_context
                    required_before = sonar_gate_snapshot(provider, gate_context, revision)
                    save(attempt_root, "required-quality-gate-before.json", required_before)
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
                if inventory_only:
                    stage = "required-quality-gate-after"
                    required_after = sonar_gate_snapshot(provider, gate_context, revision)
                    save(attempt_root, "required-quality-gate-after.json", required_after)
                    if required_before != required_after or runtime_gate_context(revision) != gate_context:
                        raise CaptureFailure("required-quality-gate-changed")
                    if gate.get("projectStatus", {}).get("status") not in ("OK", "NONE"):
                        raise CaptureFailure("inventory-quality-gate-failed")
                    save(root, "required-quality-gate.json", required_after)
                    result.update(required_quality_gate="OK", required_quality_gate_scope=required_after["scope"],
                                  inventory_quality_gate=gate.get("projectStatus", {}).get("status"))
                if public_project:
                    stage = "project-visibility-after"
                    verify_public_sonar(provider, attempt_root, "project-after.json")
                # Both authenticated ce/task history and the public queue can
                # retain an older task. Success requires the component's CURRENT
                # completed task to still be this exact analysis after export.
                # These are bounded observations, not an atomic provider snapshot;
                # an unrelated later component task conservatively fails closed.
                stage = "task-final-recheck"
                final_task = task_snapshot(provider, current_only=True)
                save(attempt_root, "task-after.json", final_task)
                if any(final_task["task"].get(field) != current.get(field)
                       for field in ("id", "componentKey", "status", "analysisId", "pullRequest")):
                    raise CaptureFailure("scanner-task-identity-changed")
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
                permanent_context = isinstance(error, CaptureFailure) and str(error) in (
                    "scanner-task-identity-changed", "scanner-task-unavailable-or-superseded",
                    "required-quality-gate-context-mismatch", "inventory-quality-gate-failed")
                if permanent_http or remaining <= 0 or permanent_context:
                    break
                pause(min(retry_delay, remaining))
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
    parser.add_argument("--public-project-results", action="store_true", help="Read verified public project results and exact scanner-task identity anonymously")
    parser.add_argument("--gate-context", help="Separate source-bound PR/main gate for candidate inventory")
    args = parser.parse_args()
    try:
        result = collect(args.report_task, args.context, args.revision, args.output, timeout=args.timeout, public_project=args.public_project_results, gate_context=args.gate_context)
        if result["status"] != "completed":
            parser.exit(1, "Sonar evidence is partial; independent reconciliation required\n")
        required = result.get("required_quality_gate", result.get("quality_gate"))
        if required != "OK":
            parser.exit(1, "Sonar required quality gate failed; provider reports retained\n")
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "Sonar evidence capture failed; independent reconciliation required\n")


if __name__ == "__main__":
    main()
