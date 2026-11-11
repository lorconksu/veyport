#!/usr/bin/env python3
"""Run the allowlisted Sonar consumer closure from an immutable main checkout."""
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

PROGRAMS = {'context': 'sonar_context.py', 'wait': 'sonar_bridge.py',
            'capture': 'sonar_job_evidence.py', 'encrypt': 'ci_evidence.py'}
CLOSURE = ('sonar_control.py', 'sonar_bridge.py', 'sonar_job_evidence.py', 'source_sast.py',
           'sonar_context.py', 'risk_acceptance.py', 'scan_contract.py', 'metadata.py',
           'ci_evidence.py', 'ci_evidence_crypto.py')


def require(ok):
    if not ok:
        raise ValueError('immutable Sonar control/source boundary rejected')


def main():
    require(sys.flags.isolated and sys.flags.no_site and len(sys.argv) >= 2 and sys.argv[1] in PROGRAMS)
    require(os.environ.get('GITHUB_REPOSITORY') == 'lorconksu/veyport'
            and os.environ.get('SONAR_CREDENTIAL_MODE') == 'bridge')
    pin, revision = os.environ.get('SONAR_BRIDGE_TOOLING_REVISION', ''), os.environ.get('EXPECTED_SOURCE_SHA', '')
    require(re.fullmatch(r'[0-9a-f]{40}', pin) and re.fullmatch(r'[0-9a-f]{40}', revision))
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve()
    trusted, candidate = workspace / 'trusted-control', workspace / 'candidate-source'
    require(all(path.is_dir() and not path.is_symlink() for path in (trusted, candidate)))
    require(Path(__file__).resolve().parents[2] == trusted)
    os.environ.update(PATH='/usr/bin:/bin', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    require(subprocess.check_output(['git', '-C', str(trusted), 'rev-parse', 'HEAD'], text=True).strip() == pin)
    require(subprocess.check_output(['git', '-C', str(candidate), 'rev-parse', 'HEAD'], text=True).strip() == revision)
    for name in CLOSURE:
        path = trusted
        for part in ('scripts', 'release', name):
            path = path / part
            require(not path.is_symlink())
        require(stat.S_ISREG(path.stat().st_mode))
    # -I -S removed cwd, PYTHONPATH and site hooks. Add only the pinned release
    # directory; __file__-relative imports cannot resolve through candidate data.
    release = trusted / 'scripts/release'
    sys.path.insert(0, str(release))
    command = sys.argv[1]
    program = PROGRAMS[command]
    sys.argv = [str(release / program)] + (['wait'] if command == 'wait' else []) + sys.argv[2:]
    os.umask(0o077)
    os.chdir(candidate)
    runpy.run_path(str(release / program), run_name='__main__')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        raise SystemExit('Trusted Sonar consumer failed closed') from None
