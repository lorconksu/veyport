#!/usr/bin/env python3
"""Capture available Sonar job results before mutable provider state moves."""
import argparse
from pathlib import Path
import re
import shlex
from risk_acceptance import canonical
from source_sast import Sonar, PROJECT, save


def collect(report_task, context, revision, output, api=None):
    api = api or Sonar()
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    result = {"schema_version": 1, "revision": revision, "status": "partial", "missing": []}
    try:
        path = Path(report_task)
        if path.is_symlink() or not 0 < path.stat().st_size <= 65536:
            raise ValueError("scanner task identity unavailable")
        properties = dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line)
        task_id = properties.get("ceTaskId", "")
        if properties.get("serverUrl", "").rstrip("/") != "https://sonarcloud.io" or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", task_id):
            raise ValueError("scanner task identity invalid")
        task = api.get("ce/task", {"id": task_id})
        save(root, "task.json", task)
        current = task["task"]
        if current.get("componentKey") != PROJECT or current.get("status") != "SUCCESS":
            raise ValueError("Sonar execution incomplete")
        analysis_id = current["analysisId"]
        gate = api.get("qualitygates/project_status", {"analysisId": analysis_id})
        save(root, "quality-gate.json", gate)
        args = dict(arg[2:].split("=", 1) for arg in shlex.split(context) if arg.startswith("-D") and "=" in arg)
        if "sonar.pullrequest.key" in args:
            identity = args["sonar.pullrequest.key"]
            if not re.fullmatch(r"[1-9][0-9]*", identity):
                raise ValueError("invalid PR context")
            def snapshot():
                matches = [p for p in api.get("project_pull_requests/list", {"project": PROJECT})["pullRequests"] if p["key"] == identity]
                if len(matches) != 1 or matches[0].get("commit", {}).get("sha") != revision:
                    raise ValueError("Sonar PR source superseded")
                return matches[0]
            params = {"pullRequest": identity}
            result["scope"] = "pull-request-new-code"
        else:
            branch = args["sonar.branch.name"]
            def snapshot():
                rows = api.get("project_analyses/search", {"project": PROJECT, "branch": branch, "ps": 1, "p": 1})["analyses"]
                if len(rows) != 1 or rows[0].get("revision") != revision or rows[0].get("key") != analysis_id:
                    raise ValueError("Sonar full branch analysis superseded")
                return rows[0]
            params = {"branch": branch}
            result["scope"] = "full-branch"
        before = snapshot()
        _, issues = api.pages("issues/search", {**params, "componentKeys": PROJECT, "additionalFields": "_all", "issueStatuses": "OPEN,CONFIRMED,FALSE_POSITIVE,ACCEPTED,FIXED"}, "issues")
        _, hotspots = api.pages("hotspots/search", {**params, "projectKey": PROJECT}, "hotspots")
        after = snapshot()
        if before != after:
            raise ValueError("Sonar snapshot changed during export")
        save(root, "context.json", before)
        save(root, "issues.json", issues)
        save(root, "hotspots.json", hotspots)
        result.update(status="completed", analysis_id=analysis_id, snapshot_binding="stable-exact-revision-context", quality_gate=gate.get("projectStatus", {}).get("status"))
    except (ValueError, OSError, KeyError, TypeError):
        result["missing"].append("provider-results-incomplete-or-superseded")
    save(root, "capture.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("report-task", "context", "revision", "output"):
        parser.add_argument("--" + flag, required=True)
    args = parser.parse_args()
    try:
        result = collect(args.report_task, args.context, args.revision, args.output)
        if result["status"] != "completed":
            parser.exit(1, "Sonar evidence is partial; independent reconciliation required\n")
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(1, "Sonar evidence capture failed; independent reconciliation required\n")


if __name__ == "__main__":
    main()
