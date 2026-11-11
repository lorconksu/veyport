"""Resolve an explicit source-bound Sonar context without writing GitHub state."""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.parse
import urllib.request

import metadata

PROJECT = "lorconksu_veyport"
# Analysis admission does not grant a publication channel. The protected
# prerequisite keeps metadata.py's existing publication allowlist unchanged.
SONAR_PROTOTYPE_TAG = re.compile(r"prototype-(?:ssh-passthrough|application-access|ssdf)\.[1-9][0-9]*")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_branch(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_./+@-]{1,240}", value),
            "Unsafe Sonar branch metadata")
    return value


def candidate_branch(revision):
    require(re.fullmatch(r"[0-9a-f]{40}", revision or ""), "Exact candidate revision required")
    return "release-ssdf-candidate-" + revision


def public_sonar_api(endpoint, params):
    # Fixed public project reads only. Analysis credentials never enter this
    # preflight, and no project or settings mutation is permitted.
    require((endpoint, tuple(sorted(params))) in (
        ("components/show", ("component",)),
        ("settings/values", ("component", "keys")),
        ("project_branches/list", ("project",)),
        ("project_analyses/search", ("branch", "p", "project", "ps"))), "Unsupported Sonar preflight")
    require(params.get("component", params.get("project")) == PROJECT, "Unexpected Sonar project")
    require(endpoint != "settings/values" or params["keys"] == "sonar.branch.longLivedBranches.regex",
            "Unsupported Sonar settings read")
    request = urllib.request.Request("https://sonarcloud.io/api/" + endpoint + "?" + urllib.parse.urlencode(params),
                                     headers={"Accept": "application/json"})
    with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
        raw = response.read((16 << 20) + 1)
    require(len(raw) <= 16 << 20, "Sonar preflight exceeds evidence bound")
    return json.loads(raw)


def full_branch_context(revision, fetch):
    branch = candidate_branch(revision)
    component = fetch("components/show", {"component": PROJECT})["component"]
    require(component.get("key") == PROJECT and component.get("visibility") == "public",
            "Candidate analysis requires the verified public project")
    settings = fetch("settings/values", {"component": PROJECT, "keys": "sonar.branch.longLivedBranches.regex"})["settings"]
    patterns = [s["value"] for s in settings if s.get("key") == "sonar.branch.longLivedBranches.regex"]
    require(len(patterns) == 1 and isinstance(patterns[0], str) and len(patterns[0]) <= 1024 and
            re.fullmatch(patterns[0], branch), "Candidate branch must match actual long-lived pattern")
    branches = fetch("project_branches/list", {"project": PROJECT})["branches"]
    matches = [b for b in branches if b.get("name") == branch]
    require(len(matches) <= 1 and all(b.get("type") == "LONG" and b.get("isMain") is False for b in matches),
            "Existing candidate branch is not a full exact-source branch")
    if matches:
        rows = fetch("project_analyses/search", {"project": PROJECT, "branch": branch, "ps": 1, "p": 1})["analyses"]
        require(len(rows) == 1 and rows[0].get("revision") == revision,
                "Existing candidate analysis belongs to another source")
    return "-Dsonar.branch.name=" + branch


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


def resolve(event_name, event, repository, ref, revision, require_pr, fetch=public_api, belongs_to_main=main_source,
            full_branch=False, sonar_fetch=public_sonar_api, workflow_ref=None, details=False):
    def resolved(args, gate_args=None):
        plan = {"args": args, "gate_args": gate_args or args,
                "quality_gate_wait": "false" if gate_args else "true"}
        return plan if details else args

    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or "") and
            re.fullmatch(r"[0-9a-f]{40}", revision or "") and
            event["repository"]["full_name"] == repository and event["repository"]["private"] is False,
            "Exact public repository/source context required")
    require(event_name in ("pull_request", "push", "workflow_dispatch", "workflow_call"), "Unsupported Sonar event context")
    if full_branch:
        require(require_pr and event_name == "workflow_dispatch" and
                workflow_ref == repository + "/.github/workflows/staging.yml@" + ref and
                event.get("inputs", {}).get("prototype") in (True, "true"),
                "Full candidate baseline requires the trusted staging prototype caller")
        require((ref.startswith("refs/heads/") and ref != "refs/heads/main") or
                (ref.startswith("refs/tags/") and SONAR_PROTOTYPE_TAG.fullmatch(ref.removeprefix("refs/tags/"))),
                "Full candidate baseline requires an unmerged candidate source")
        branch = safe_branch(ref.removeprefix("refs/heads/")) if ref.startswith("refs/heads/") else None
        gate_args = open_source_pr(repository, revision, branch, fetch)
        return resolved(full_branch_context(revision, sonar_fetch), gate_args)
    if event_name == "pull_request":
        return resolved(pr_context(event["pull_request"], repository, revision))
    if ref == "refs/heads/main":
        require(not require_pr and belongs_to_main(ref, revision), "Prototype/foreign source cannot be analyzed as main")
        return resolved("-Dsonar.branch.name=main")
    if stable_ref(ref, revision):
        require(not require_pr and belongs_to_main(ref, revision), "Prototype/foreign source cannot be analyzed as a stable tag")
        # Historical tag-named branches can be SHORT. Use a dedicated LONG
        # exact-source branch without replacing main or relabeling that history.
        return resolved(full_branch_context(revision, sonar_fetch), "-Dsonar.branch.name=main")
    if ref.startswith("refs/heads/"):
        return resolved(open_source_pr(repository, revision, safe_branch(ref.removeprefix("refs/heads/")), fetch))
    if ref.startswith("refs/tags/") and SONAR_PROTOTYPE_TAG.fullmatch(ref.removeprefix("refs/tags/")):
        return resolved(open_source_pr(repository, revision, None, fetch))
    raise ValueError("No explicit Sonar branch/PR context for this source")


def runtime_gate_context(revision, fetch=public_api):
    """Revalidate the trusted caller and gate source, independently of CLI flags."""
    repository, ref = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_REF", "")
    workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    require(repository == "lorconksu/veyport" and
            event.get("repository", {}).get("full_name") == repository and
            event["repository"].get("private") is False,
            "Exact trusted Sonar gate source required")
    # Reusable workflows expose the caller's workflow_ref. Restrict this
    # temporary entry point to the admitted CI consumer's actual job_id instead
    # of trying to infer Delivery from that caller identity. This operation
    # boundary relies on reviewed workflow bytes, not a new attestation.
    require(os.environ.get("GITHUB_JOB") == "sonarcloud",
            "Protected Sonar bootstrap gate capture requires the admitted sonarcloud job")
    require(os.environ.get("GITHUB_SHA") == revision, "Legacy Sonar gate source differs from runtime")
    if workflow_ref == repository + "/.github/workflows/staging.yml@" + ref:
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
                event.get("inputs", {}).get("prototype") in (True, "true") and
                ((ref.startswith("refs/heads/") and ref != "refs/heads/main") or
                 (ref.startswith("refs/tags/") and SONAR_PROTOTYPE_TAG.fullmatch(ref.removeprefix("refs/tags/")))),
                "Sonar PR gate requires trusted prototype dispatch")
        branch = safe_branch(ref.removeprefix("refs/heads/")) if ref.startswith("refs/heads/") else None
        return open_source_pr(repository, revision, branch, fetch)
    require(workflow_ref == repository + "/.github/workflows/release.yml@" + ref and
            os.environ.get("GITHUB_EVENT_NAME") in ("push", "workflow_dispatch") and stable_ref(ref, revision),
            "Sonar main gate requires a trusted stable release")
    comparison = fetch("repos/" + repository + "/compare/" + revision + "...main")
    require(comparison.get("status") in ("ahead", "identical") and
            comparison.get("merge_base_commit", {}).get("sha") == revision,
            "Stable Sonar source is outside main history")
    return "-Dsonar.branch.name=main"


def main():
    revision = os.environ["EXPECTED_SOURCE_SHA"]
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Exact expected Sonar revision required")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == revision,
            "Checked-out Sonar source differs from expected revision")
    required = os.environ.get("SONAR_PULL_REQUEST_REQUIRED", "")
    require(required in ("", "false", "true"), "Invalid Sonar prototype context requirement")
    full_branch = os.environ.get("SONAR_FULL_BRANCH_REQUIRED", "")
    require(full_branch in ("", "false", "true"), "Invalid Sonar full baseline requirement")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    plan = resolve(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_REPOSITORY"],
                   os.environ["GITHUB_REF"], revision, required == "true", full_branch=full_branch == "true",
                   workflow_ref=os.environ.get("GITHUB_WORKFLOW_REF"), details=True)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for key, value in plan.items():
            output.write(key + "=" + value + "\n")
    print("Exact source Sonar PR/branch context verified")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Sonar context refused; no fallback analysis or API writes performed")
