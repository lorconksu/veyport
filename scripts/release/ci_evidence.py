#!/usr/bin/env python3
"""Encrypt bounded per-job evidence chunks; never upload plaintext reports."""
import argparse
import glob
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from risk_acceptance import canonical, sha, strict_json
import ci_evidence_crypto as crypto

PART = 8 << 20
MAX_TOTAL = 512 << 20
JOBS = {"unit", "test", "integration", "smoke", "e2e", "sonar", "sast", "secrets", "vulnerability"} | {"server-" + str(i) for i in range(6)}
TEXT_SUFFIXES = {".json", ".jsonl", ".sarif", ".txt", ".log", ".out", ".info", ".properties", ".stdout", ".stderr"}

# CI diagnostics retain text only. Native packages, OCI content and other
# supply-chain binaries use their separate evidence paths, not this exporter.
CAPTURE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.bmp', '.ico', '.svg',
                    '.avif', '.heic', '.tif', '.tiff', '.webm', '.mp4', '.mov', '.mkv',
                    '.avi', '.zip', '.har', '.trace', '.network', '.html', '.htm', '.mhtml'}
MEDIA_FIELDS = {'attachments', 'image', 'images', 'screenshot', 'screenshots', 'video', 'videos',
                'browsertrace', 'browsertraces', 'screencastframe', 'screencastframes'}
# Finite known credential-label catalog, aligned with collector policy without
# importing its larger runtime. Unrelated token/digest/public-key metadata stays.
CREDENTIAL_LABEL = (
    r'cookie|set[_-]?cookie|authorization|proxy[_-]?authorization|password|passwd|secret|token|'
    r'access[_-]?token|refresh[_-]?token|totp[_-]?secret|client[_-]?secret|api[_-]?key|registration[_-]?token|'
    r'x[_-](?:api[_-]key|auth[_-]token|amz[_-]security[_-]token)|'
    r'aws[_-](?:secret[_-]access[_-]key|access[_-]key[_-]id|session[_-]token|security[_-]token)|'
    r'(?:github|gh|sonar|snyk|dockerhub|dhi)[_-]token|gitleaks[_-]license')
KNOWN_CREDENTIAL_FIELDS = {
    name.lower().replace('_', '').replace('-', '') for name in (
        'cookie', 'set-cookie', 'authorization', 'proxy-authorization', 'password', 'passwd', 'secret', 'token',
        'access-token', 'refresh-token', 'totp-secret', 'client-secret', 'api-key', 'registration-token',
        'X-API-Key', 'X-Auth-Token', 'X-Amz-Security-Token', 'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID',
        'AWS_SESSION_TOKEN', 'AWS_SECURITY_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'SONAR_TOKEN', 'SNYK_TOKEN',
        'DOCKERHUB_TOKEN', 'DHI_TOKEN', 'GITLEAKS_LICENSE')}
SENSITIVE_FIELDS = {'password', 'passwd', 'secret', 'clientsecret', 'token', 'accesstoken',
                    'refreshtoken', 'totpsecret', 'authorization', 'proxyauthorization',
                    'cookie', 'cookies', 'setcookie', 'setcookies', 'body', 'requestbody',
                    'responsebody', 'postdata', 'storagestate', 'auth', 'authstate',
                    'credentials', 'httpcredentials', 'apikey', 'xapikey', 'xauthtoken',
                    'xamzsecuritytoken'} | KNOWN_CREDENTIAL_FIELDS
CREDENTIAL_HEADERS = {'cookie', 'setcookie', 'authorization', 'proxyauthorization',
                      'xapikey', 'xauthtoken', 'xamzsecuritytoken'} | KNOWN_CREDENTIAL_FIELDS
HEADER_LINES = re.compile(
    r'^((?:(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[ \t])?'
    r'(?P<log_debug>(?:##)?\[debug\])(?P<log_debug_space>[ \t]*)(?:[<>][ \t])?'
    r'|[^\r\n]*?)\b(?:' + CREDENTIAL_LABEL + r')["\']?[ \t]*:)[^\r\n]*'
    r'(?:\r?\n(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[ \t])?'
    r'(?(log_debug)(?:(?:##)?\[debug\](?P=log_debug_space))?|)'
    r'(?:[<>][ \t])?[ \t]+[^\r\n]*)*', re.I | re.M)
FORMAT_SPACE = re.compile(rb'[ \t\r\n]*(?:\xef\xbb\xbf[ \t\r\n]*)?')
XML_PREFIX = re.compile(rb'<(?:\?xml\b|!--|!DOCTYPE\b|!\[CDATA\[|/?[A-Za-z_][A-Za-z0-9_.:-]*[ \t\r\n/>])', re.I)
XML_BODY_CARRIER = re.compile(
    rb'<[ \t\r\n]*(?:/[ \t\r\n]*)?(?:[A-Za-z_][A-Za-z0-9_.-]*:)?'
    rb'(?:body|request[-_]?body|response[-_]?body|post[-_]?data|storage[-_]?state|credentials|auth[-_]?state)'
    rb'(?=[ \t\r\n/>]|$)', re.I)
TEXT_BODY_MAPPING = re.compile(
    rb'''(?:^|[\r\n{,])[ \t]*(?:-[ \t]+)?["']?'''
    rb'''(?:body|request[-_]?body|response[-_]?body|post[-_]?data|storage[-_]?state|auth|auth[-_]?state|credentials|http[-_]?credentials|cookies)'''
    rb'''["']?[ \t]*[:=]''', re.I)
PRIVATE_KEY_MARKERS = re.compile(r'-----(BEGIN|END) ([A-Z0-9 ]*PRIVATE KEY)(-{5})?', re.I)
CREDENTIAL_ASSIGNMENTS = re.compile(
    r'(?<![A-Za-z0-9_.-])(?:' + CREDENTIAL_LABEL + r')[ \t]*=[ \t]*', re.I)


class UnsafeDiagnostic(ValueError):
    """A recognized carrier cannot be safely retained; fixed omission reason."""


def unsupported_structured_diagnostic(raw):
    # Classify unsupported diagnostic formats without parsing XML/YAML,
    # resolving entities or copying a potentially large whitespace prefix.
    start = FORMAT_SPACE.match(raw).end()
    if XML_PREFIX.match(raw, start):
        return 'xml-diagnostic-excluded'
    xml_body = XML_BODY_CARRIER.search(raw) is not None
    body_mapping = TEXT_BODY_MAPPING.search(raw) is not None
    if not (xml_body or body_mapping):
        return None
    if raw[start:start + 1] in (b'{', b'[', b'"'):
        try:
            strict_json(raw)
        except (ValueError, UnicodeError):
            pass
        else:
            # Native JSON/SARIF retains its existing recursive field policy;
            # source snippets are not reinterpreted as another language.
            return None
    if not xml_body and report_hints(raw) & (SENSITIVE_FIELDS | MEDIA_FIELDS | {'headers', 'requestheaders', 'responseheaders'}):
        # Existing malformed JSON/media diagnostics retain their established
        # explicit omission reasons and markers. This is not a new parser.
        return None
    return 'xml-diagnostic-excluded' if xml_body else 'unsupported-structured-body-diagnostic-excluded'


def sanitize_text(text):
    # Walk markers once instead of repeatedly searching an unterminated block.
    parts, cursor, opened = [], 0, None
    for marker in PRIVATE_KEY_MARKERS.finditer(text):
        if marker[3] is None:
            raise UnsafeDiagnostic('malformed-private-key-diagnostic-excluded')
        if marker[1].upper() == 'BEGIN':
            if opened is not None:
                raise UnsafeDiagnostic('malformed-private-key-diagnostic-excluded')
            opened = (marker.start(), marker[2].upper())
        else:
            if opened is None or marker[2].upper() != opened[1]:
                raise UnsafeDiagnostic('malformed-private-key-diagnostic-excluded')
            parts.extend((text[cursor:opened[0]], '[OMITTED private key]'))
            cursor, opened = marker.end(), None
    if opened is not None:
        raise UnsafeDiagnostic('malformed-private-key-diagnostic-excluded')
    parts.append(text[cursor:])
    text = ''.join(parts)
    parts, cursor = [], 0
    for assignment in CREDENTIAL_ASSIGNMENTS.finditer(text):
        if assignment.start() < cursor:
            continue
        start = end = assignment.end()
        if start < len(text) and text[start] in ('"', "'"):
            quote, end = text[start], start + 1
            while end < len(text):
                if text[end] == '\\':
                    end += 2
                elif text[end] == quote:
                    end += 1
                    break
                else:
                    end += 1
            else:
                raise UnsafeDiagnostic('ambiguous-credential-assignment-excluded')
            if end < len(text) and text[end] not in ' \t\r\n;':
                # Adjacent quoted/unquoted segments form one shell value.
                # Do not retain its unparsed suffix after the first quote.
                raise UnsafeDiagnostic('ambiguous-credential-assignment-excluded')
        else:
            while end < len(text) and text[end] not in ('\r', '\n'):
                if text[end] in ('"', "'"):
                    raise UnsafeDiagnostic('ambiguous-credential-assignment-excluded')
                if text[end] == '\\':
                    if end + 1 >= len(text) or text[end + 1] in ('"', "'"):
                        raise UnsafeDiagnostic('ambiguous-credential-assignment-excluded')
                    end += 2
                else:
                    end += 1
        parts.extend((text[cursor:start], '[REDACTED]'))
        cursor = end
    parts.append(text[cursor:])
    return HEADER_LINES.sub(r'\1 [REDACTED]', ''.join(parts))


def field_name(value):
    return value.lower().replace('_', '').replace('-', '')


def report_hints(raw):
    # Walk adjacent raw quote positions once. Any older candidate spanning an
    # escaped quote decodes to a literal quote in its name, which cannot match
    # a known sensitive/media/header carrier. Adjacent pairing still recognizes
    # known keys after malformed log prefixes without rescanning the remainder.
    names = set()
    opening = raw.find(b'"')
    while opening != -1:
        closing = raw.find(b'"', opening + 1)
        if closing == -1:
            break
        cursor = closing + 1
        while cursor < len(raw) and raw[cursor] in b' \t\r\n\v\f':
            cursor += 1
        if cursor < len(raw) and raw[cursor] == 58:  # JSON-like member colon
            try:
                names.add(field_name(json.loads(raw[opening:closing + 1])))
            except (ValueError, UnicodeError):
                pass
        opening = closing
    return names


def diagnostic_omission(path, raw):
    suffix = path.suffix.lower()
    if suffix == '.xml':
        return 'xml-diagnostic-excluded'
    if suffix in CAPTURE_SUFFIXES:
        return 'browser-capture-excluded'
    if suffix not in TEXT_SUFFIXES:
        return 'unsupported-diagnostic-format'
    # A text suffix is not enough: reject misnamed binary/capture payloads.
    if (b'\x00' in raw or raw.startswith((b'\x89PNG', b'\xff\xd8', b'GIF87a', b'GIF89a', b'RIFF',
                                          b'PK\x03\x04', b'\x1aE\xdf\xa3')) or raw[4:8] == b'ftyp'):
        return 'non-text-diagnostic-excluded'
    if re.match(rb'\s*(?:<\?xml[^>]*>\s*)?(?:<(?:svg|html)\b|<!doctype\s+html\b)', raw[:4096], re.I):
        return 'browser-capture-excluded'
    unsupported = unsupported_structured_diagnostic(raw)
    if unsupported is not None:
        return unsupported
    try:
        raw.decode('utf-8')
    except UnicodeError:
        return 'non-text-diagnostic-excluded'
    hints = report_hints(raw)
    if not hints & MEDIA_FIELDS and hints & (SENSITIVE_FIELDS | {'headers', 'requestheaders', 'responseheaders'}):
        try:
            strict_json(raw)
        except ValueError:
            return 'unparseable-sensitive-diagnostic-excluded'
    return None


def omit_report_attachments(raw):
    """Keep outcomes/identity; omit known capture and credential carriers."""
    changed = False
    def safe(value, depth=0, header_pairs=False):
        nonlocal changed
        if depth > 32:
            raise ValueError('diagnostic nesting exceeds bound')
        if isinstance(value, dict):
            result = {}
            credential_header = any(field_name(key) in {'name', 'key'} and isinstance(item, str)
                                    and field_name(item) in CREDENTIAL_HEADERS for key, item in value.items())
            for key, item in value.items():
                normalized = field_name(key)
                if normalized in MEDIA_FIELDS:
                    result[key] = '[OMITTED browser capture]'
                    changed = True
                elif normalized in SENSITIVE_FIELDS or (credential_header and normalized in {'value', 'values'}):
                    # Omit the whole carrier regardless of its JSON type;
                    # scalar-only substitutions leave nested bodies intact.
                    result[key] = '[REDACTED]'
                    changed = True
                else:
                    result[key] = safe(item, depth + 1, normalized in {'headers', 'requestheaders', 'responseheaders'})
            return result
        if isinstance(value, list):
            # Headers.entries() represents each value as a [name, value] pair.
            # Interpret that shape only within an explicitly named carrier.
            if header_pairs and len(value) == 2 and isinstance(value[0], str) and field_name(value[0]) in CREDENTIAL_HEADERS:
                changed = True
                return [value[0], '[REDACTED]']
            return [safe(item, depth + 1, header_pairs) for item in value]
        if isinstance(value, str):
            retained = sanitize_text(value)
            changed = changed or retained != value
            return retained
        return value
    try:
        value = strict_json(raw)
    except (ValueError, UnicodeError):
        # A mixed/malformed report cannot safely isolate nested attachment
        # payloads. Preserve an explicit marker instead of falling back raw.
        hints = report_hints(raw)
        if hints & MEDIA_FIELDS:
            return b'[OMITTED unparseable browser report]\n'
        if hints & (SENSITIVE_FIELDS | {'headers', 'requestheaders', 'responseheaders'}):
            return b'[OMITTED unparseable credential report]\n'
        return sanitize_text(raw.decode('utf-8')).encode()
    value = safe(value)
    return canonical(value) if changed else raw


def redact(data):
    unsupported = unsupported_structured_diagnostic(data)
    if unsupported is not None:
        raise UnsafeDiagnostic(unsupported)
    text = omit_report_attachments(data).decode("utf-8")
    # Credentials are never an evidence requirement. Apply redaction before
    # calculating retained-payload digests. Do not provision extra secrets to
    # untrusted jobs merely to build this evidence bundle.
    for name in ("GITHUB_TOKEN", "GH_TOKEN", "SONAR_TOKEN", "SNYK_TOKEN", "DOCKERHUB_TOKEN", "GITLEAKS_LICENSE"):
        secret = os.environ.get(name)
        if secret and len(secret) >= 8:
            text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]{8,}", r"\1[REDACTED]", text)
    text = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "[REDACTED-JWT]", text)
    text = re.sub(r'(?i)([?&](?:access_token|token|api_key|key|sig|signature|password)=)[^&\s"<>]+', r'\1[REDACTED]', text)
    # Browser trace request/response bodies, cookies and auth state must not
    # survive merely to preserve every original log byte.
    text = re.sub(r'(?i)("(?:password|secret|token|access_token|refresh_token|totp_secret|authorization|cookie|set-cookie|body|postdata|storagestate)"\s*:\s*)"(?:[^"\\]|\\.)*"', r'\1"[REDACTED]"', text)
    text = re.sub(r'(?i)data:(?:image|video)/[A-Za-z0-9.+-]+;base64,[A-Za-z0-9+/=]+',
                  '[OMITTED browser capture]', text)
    return text.encode()


def available(root, patterns):
    root = Path(root).resolve()
    paths, missing = set(), []
    for pattern in patterns:
        if not isinstance(pattern, str) or pattern.startswith("/") or ".." in Path(pattern).parts:
            raise ValueError("unsafe evidence pattern")
        matched = glob.glob(str(root / pattern), recursive=True)
        found = []
        for value in matched:
            path = Path(value)
            if path.is_dir() and not path.is_symlink():
                found.extend(p for p in path.rglob("*") if not p.is_dir() or p.is_symlink())
            else:
                found.append(path)
        if not found:
            missing.append(pattern)
        for path in found:
            relative = path.relative_to(root)
            current = root
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    raise ValueError("evidence symlinks are forbidden")
            if not path.is_file() or path.stat().st_size > MAX_TOTAL:
                raise ValueError("invalid evidence source")
            paths.add(path)
    return sorted(paths), missing


def encrypt_job(root, output, recipient, job, status, patterns, revision, workflow, runner_results=None, source_root=None):
    if job not in JOBS or status not in {"success", "failure", "cancelled", "skipped"} or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("invalid job source binding")
    repository = os.environ["GITHUB_REPOSITORY"]
    workflow = workflow.removeprefix(repository + "/").split("@", 1)[0]
    if repository != "lorconksu/veyport" or workflow not in {".github/workflows/ci.yml", ".github/workflows/release.yml", ".github/workflows/staging.yml"}:
        raise ValueError("unexpected job workflow")
    root, output = Path(root).resolve(), Path(output)
    source_root = root if source_root is None else Path(source_root).resolve()
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source_root).decode().strip() != revision:
        raise ValueError("job checkout differs from declared source")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    paths, missing = available(root, patterns)
    names = {path: path.relative_to(root).as_posix() for path in paths}
    if runner_results is not None:
        trusted = Path(os.environ["RUNNER_TEMP"]) / "ssdf-results"
        if Path(runner_results) != trusted:
            raise ValueError("unexpected runner evidence root")
        if trusted.exists():
            extra, absent = available(trusted, ["**/*"])
            missing.extend("runner-results/" + value for value in absent)
            for path in extra:
                names[path] = "runner-results/" + path.relative_to(trusted).as_posix()
            paths.extend(extra)
        else:
            missing.append("runner-results")
    chunks, current, current_bytes, part_index = [], [], 0, {}
    originals, omitted, total = [], [], 0
    with tempfile.TemporaryDirectory() as directory:
        staging = Path(directory)
        (staging / "parts").mkdir()
        for path in paths:
            raw = path.read_bytes()
            reason = diagnostic_omission(path, raw)
            if reason is not None:
                omitted.append({'name': names[path], 'original_sha256': sha(raw), 'size': len(raw), 'reason': reason})
                continue
            try:
                retained = redact(raw)
            except UnsafeDiagnostic as error:
                omitted.append({'name': names[path], 'original_sha256': sha(raw), 'size': len(raw), 'reason': str(error)})
                continue
            total += len(retained)
            if total > MAX_TOTAL:
                raise ValueError("per-job evidence exceeds archive resource budget")
            refs = []
            for offset in range(0, max(1, len(retained)), PART):
                data = retained[offset:offset + PART]
                digest = sha(data)
                name = "parts/" + digest
                (staging / name).write_bytes(data)
                item = {"name": name, "sha256": digest, "size": len(data)}
                if digest in part_index:
                    index = part_index[digest]
                else:
                    if current and (current_bytes + len(data) > PART or len(current) >= 256):
                        chunks.append(current)
                        current, current_bytes = [], 0
                    if len(chunks) >= 64:
                        raise ValueError("per-job evidence exceeds chunk bound")
                    index = len(chunks)
                    current.append(item)
                    current_bytes += len(data)
                    part_index[digest] = index
                refs.append({"name": name, "offset": offset, "size": len(data), "sha256": digest, "chunk_index": index})
            originals.append({"name": names[path], "sha256": sha(retained), "size": len(retained), "original_sha256": sha(raw), "redacted": retained != raw, "parts": refs})
        # Even a job that failed before generating any report has an explicit
        # encrypted partial-outcome chunk. Cancellation reconciliation records
        # jobs that could not reach this finalizer separately.
        if current:
            chunks.append(current)
        if not chunks:
            chunks = [[]]
        recipient_path = staging / "recipient.txt"
        if not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
            raise ValueError("pinned age recipient unavailable")
        recipient_path.write_text(recipient + "\n")
        for index, items in enumerate(chunks):
            manifest = {"schema": 1, "repository": repository, "workflow": workflow, "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "revision": revision, "candidate_id": f"run-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}", "complete": False, "files": items, "details": {"kind": "job-chunk", "job": job, "chunk_index": index, "chunk_count": len(chunks), "github_sha": os.environ.get("GITHUB_SHA"), "checkout_revision": revision, "status": status, "missing": missing, "original_files": originals, "omitted_files": omitted, "diagnostic_policy": "redacted-text-only/v1", "dast": "deferred-owner-decision"}}
            payload = crypto.pack(manifest, staging)
            (output / f"chunk-{index:04d}.age").write_bytes(crypto.age_encrypt(payload, recipient_path))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    for flag in ("output", "recipient", "job", "status", "revision", "workflow"):
        parser.add_argument("--" + flag, required=True)
    parser.add_argument("--runner-results")
    parser.add_argument("--source-root", help="Separate source checkout used only for exact revision binding")
    parser.add_argument("--path", action="append", default=[])
    args = parser.parse_args()
    os.umask(0o077)
    try:
        encrypt_job(args.root, args.output, args.recipient, args.job, args.status, args.path, args.revision, args.workflow, args.runner_results, args.source_root)
    except Exception:
        # Provider errors, report text and signed URLs must never enter logs.
        parser.exit(1, "private job evidence encryption failed; reconciliation required\n")


if __name__ == "__main__":
    main()
