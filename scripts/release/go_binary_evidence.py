#!/usr/bin/env python3
"""Record exact-binary Go vulnerability evidence without dropping findings."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from artifacts import BINARIES


def decode_stream(raw):
    if not 0 < len(raw) <= 64 << 20:
        raise ValueError("bounded Go scanner evidence required")
    decoder = json.JSONDecoder()
    messages, remaining = [], raw.decode()
    while remaining.strip():
        message, end = decoder.raw_decode(remaining.lstrip())
        if not isinstance(message, dict):
            raise ValueError("Go scanner object required")
        messages.append(message)
        remaining = remaining.lstrip()[end:]
    configurations = [m["config"] for m in messages if "config" in m]
    sboms = [m["SBOM"] for m in messages if "SBOM" in m]
    if len(configurations) != 1 or configurations[0].get("scanner_name") != "govulncheck" or configurations[0].get("scan_mode") != "binary" or configurations[0].get("scan_level") != "symbol" or len(sboms) != 1 or not sboms[0].get("go_version") or not isinstance(sboms[0].get("modules"), list):
        raise ValueError("complete symbol-level binary Go evidence required")
    return messages


def package_absent(messages, vulnerability, module):
    # This is an explicit, reviewed classification for one unsafe unused Go
    # package, rather than a rule allowing arbitrary module-level advisories.
    # Keep the raw advisory in both scanner reports and the release assessment.
    if vulnerability != "GO-2026-5932" or module != "golang.org/x/crypto":
        return False
    findings = [m["finding"] for m in messages if m.get("finding", {}).get("osv") == vulnerability]
    definitions = [m["osv"] for m in messages if m.get("osv", {}).get("id") == vulnerability]
    if len(definitions) != 1 or not findings:
        return False
    imports = [i.get("path") for affected in definitions[0].get("affected", []) if affected.get("package", {}).get("name") == module for i in affected.get("ecosystem_specific", {}).get("imports", [])]
    if "golang.org/x/crypto/openpgp" not in imports:
        return False
    return all(f.get("trace") and all(frame.get("module") == module and frame.get("version") and not frame.get("package") and not frame.get("function") for frame in f["trace"]) for f in findings)


def record(directory, output, scanner):
    directory, output = Path(directory), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name in BINARIES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("fixed public binary required")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        process = subprocess.run([scanner, "-mode=binary", "-json", str(path)], capture_output=True, timeout=120, check=True)
        messages = decode_stream(process.stdout)
        evidence = {"schema_version": 1, "binary": name, "sha256": digest, "messages": messages}
        (output / (name + ".go.json")).write_text(json.dumps(evidence, indent=2) + "\n")
        for finding in (m["finding"] for m in messages if "finding" in m):
            trace = finding.get("trace", [])
            if not trace or not package_absent(messages, finding.get("osv"), trace[0].get("module")):
                raise ValueError("unclassified Go binary vulnerability")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("output")
    parser.add_argument("--scanner", default="govulncheck")
    args = parser.parse_args()
    try:
        record(args.directory, args.output, args.scanner)
    except (ValueError, OSError, subprocess.SubprocessError, TypeError, KeyError):
        parser.exit(1, "exact-binary Go vulnerability gate failed\n")
