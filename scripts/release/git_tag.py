"""Require an exact remote Git tag before any artifact publication."""

import json
import re
import subprocess
import sys


def lookup(tag):
    reference = "refs/tags/" + tag
    result = subprocess.run(["git", "ls-remote", "--tags", "origin", reference, reference + "^{}"], capture_output=True, timeout=30, check=True)
    if len(result.stdout) > 4096:
        raise ValueError("bounded remote tag response required")
    refs = {}
    for line in result.stdout.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", fields[0]) or fields[1] not in (reference, reference + "^{}") or fields[1] in refs:
            raise ValueError("unambiguous exact remote tag required")
        refs[fields[1]] = fields[0]
    if reference not in refs:
        if refs:
            raise ValueError("tag peel without tag reference")
        return None
    return refs.get(reference + "^{}", refs[reference])


def verify(tag, revision, repository, create):
    if not re.fullmatch(r"prototype-ssh-passthrough\.[1-9][0-9]*|v[0-9]+\.[0-9]+\.[0-9]+", tag) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("validated release identity required")
    existing = lookup(tag)
    if existing is not None:
        if existing != revision:
            raise ValueError("existing Git tag has a different source")
        return
    if not create:
        raise ValueError("required source tag is absent")
    payload = json.dumps({"ref": "refs/tags/" + tag, "sha": revision}).encode()
    # GitHub's ref creation is atomic and cannot move an existing ref. A lost
    # reply/conflicting creator is acceptable only after an exact remote recheck.
    try:
        subprocess.run(["gh", "api", "--method", "POST", "repos/" + repository + "/git/refs", "--input", "-"], input=payload, capture_output=True, timeout=30, check=True)
    except (subprocess.SubprocessError, OSError):
        if lookup(tag) != revision:
            raise ValueError("exact Git tag creation was not confirmed") from None
        return
    if lookup(tag) != revision:
        raise ValueError("created Git tag does not match the source")


if __name__ == "__main__":
    try:
        mode, tag, revision, repository = sys.argv[1:]
        if mode not in ("ensure", "check"):
            raise ValueError("unknown tag verification mode")
        verify(tag, revision, repository, mode == "ensure")
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError):
        raise SystemExit("remote Git tag identity could not be verified") from None
