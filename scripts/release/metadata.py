#!/usr/bin/env python3
"""Validate release identity before build or publication."""
import argparse
import json
import re


# Prototype feature names are deliberately explicit. A generic prototype-* tag
# would silently admit unrelated publication channels.
PROTOTYPE_TAG = re.compile(r"prototype-(?:ssh-passthrough|application-access|ssdf)\.[1-9][0-9]*")


def identity(version, tag, revision, ref, prototype):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("exact commit required")
    if prototype:
        if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-prototype\.[1-9][0-9]*", version) or not PROTOTYPE_TAG.fullmatch(tag) or not ref.startswith("refs/heads/") or ref == "refs/heads/main":
            raise ValueError("prototype identity must use a feature branch and non-release tag")
    elif not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or version != tag[1:] or ref != "refs/tags/" + tag:
        raise ValueError("stable release requires its exact stable tag")
    return {"version": version, "tag": tag, "revision": revision, "prototype": prototype}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("version", "tag", "revision", "ref"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--prototype", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(identity(args.version, args.tag, args.revision, args.ref, args.prototype), sort_keys=True))
    except ValueError:
        parser.exit(1, "release identity rejected\n")
