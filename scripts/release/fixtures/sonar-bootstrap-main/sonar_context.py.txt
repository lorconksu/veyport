"""Resolve an explicit source-bound Sonar context without writing GitHub state."""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request

import metadata


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_branch(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_./+@-]{1,240}", value),
            "Unsafe Sonar branch metadata")
    return value


def pr_context(pr, repository, revision, branch=None, same_repository=False):
    require(type(pr["number"]) is int and pr["number"] > 0 and pr["state"] == "open" and
            pr.get("merged") is not True and pr.get("merged_at") is None and
            pr["base"]["repo"]["full_name"] == repository and pr["base"]["ref"] == "main" and
            pr["head"]["sha"] == revision, "Sonar PR is closed, merged or belongs to another source/base")
    head = safe_branch(pr["head"]["ref"])
    require(head != "main" and (branch is None or head == branch) and
            (not same_repository or pr["head"]["repo"]["full_name"] == repository),
            "Sonar PR head branch/repository differs")
    return " ".join(("-Dsonar.pullrequest.key=" + str(pr["number"]),
                     "-Dsonar.pullrequest.branch=" + head, "-Dsonar.pullrequest.base=main"))


def public_api(path):
    # The repository is public. No token/permission expansion or API writes are
    # needed to identify its actual open PR; any API failure stops the scan.
    request = urllib.request.Request("https://api.github.com/" + path,
        headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "veyport-ci-sonar-context"})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def open_source_pr(repository, revision, branch, fetch):
    params = {"state": "open", "base": "main", "per_page": 100}
    if branch is not None:
        params["head"] = repository.split("/", 1)[0] + ":" + branch
    rows = []
    for page in range(1, 101):
        response = fetch("repos/" + repository + "/pulls?" + urllib.parse.urlencode({**params, "page": page}))
        require(isinstance(response, list) and len(response) <= 100, "Malformed Sonar PR lookup")
        rows.extend(response)
        if len(response) < 100:
            break
    else:
        raise ValueError("Sonar PR lookup exceeded complete pagination bound")
    require(len({row["number"] for row in rows}) == len(rows), "Sonar PR lookup changed during pagination")
    candidates = [row for row in rows if row["head"]["sha"] == revision and
                  row["head"]["repo"]["full_name"] == repository and row["base"]["repo"]["full_name"] == repository and
                  row["base"]["ref"] == "main" and (branch is None or row["head"]["ref"] == branch)]
    require(len(candidates) == 1, "Exactly one open same-repository PR must match this source")
    selected = candidates[0]
    # Re-read the exact selected PR to reject a concurrent close/merge/head move.
    current = fetch("repos/" + repository + "/pulls/" + str(selected["number"]))
    require(current["number"] == selected["number"] and current.get("merged") is False,
            "Actual Sonar PR identity/merged state differs")
    return pr_context(current, repository, revision, branch, same_repository=True)


def main_source(ref, revision):
    if ref.startswith("refs/tags/"):
        tag = ref.removeprefix("refs/tags/")
        actual = subprocess.check_output(["git", "rev-parse", "refs/tags/" + tag + "^{commit}"], text=True).strip()
        if actual != revision:
            return False
    return subprocess.run(["git", "merge-base", "--is-ancestor", revision, "refs/remotes/origin/main"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def stable_ref(ref, revision):
    if not ref.startswith("refs/tags/"):
        return False
    tag = ref.removeprefix("refs/tags/")
    try:
        metadata.identity(tag[1:], tag, revision, ref, False)
        return True
    except ValueError:
        return False


def resolve(event_name, event, repository, ref, revision, require_pr, fetch=public_api, belongs_to_main=main_source):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or "") and
            re.fullmatch(r"[0-9a-f]{40}", revision or "") and
            event["repository"]["full_name"] == repository and event["repository"]["private"] is False,
            "Exact public repository/source context required")
    require(event_name in ("pull_request", "push", "workflow_dispatch", "workflow_call"), "Unsupported Sonar event context")
    if event_name == "pull_request":
        return pr_context(event["pull_request"], repository, revision)
    if ref == "refs/heads/main":
        require(not require_pr and belongs_to_main(ref, revision), "Prototype/foreign source cannot be analyzed as main")
        return "-Dsonar.branch.name=main"
    if stable_ref(ref, revision):
        require(not require_pr and belongs_to_main(ref, revision), "Prototype/foreign source cannot be analyzed as a stable tag")
        # Releases historically have separate Sonar branches. An old release
        # must not replace the current main baseline used for PR comparisons.
        return "-Dsonar.branch.name=" + ref
    if ref.startswith("refs/heads/"):
        return open_source_pr(repository, revision, safe_branch(ref.removeprefix("refs/heads/")), fetch)
    if ref.startswith("refs/tags/") and metadata.PROTOTYPE_TAG.fullmatch(ref.removeprefix("refs/tags/")):
        return open_source_pr(repository, revision, None, fetch)
    raise ValueError("No explicit Sonar branch/PR context for this source")


def main():
    revision = os.environ["EXPECTED_SOURCE_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Exact expected Sonar revision required")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == revision,
            "Checked-out Sonar source differs from expected revision")
    required = os.environ.get("SONAR_PULL_REQUEST_REQUIRED", "")
    require(required in ("", "false", "true"), "Invalid Sonar prototype context requirement")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    args = resolve(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_REPOSITORY"],
                   os.environ["GITHUB_REF"], revision, required == "true")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("args=" + args + "\n")
    print("Exact source Sonar PR/branch context verified")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Sonar context refused; no fallback analysis or API writes performed")
