#!/usr/bin/env python3
"""Install or verify only the dedicated candidate bridge isolation rules."""
import argparse
import subprocess
import sys

BRIDGE = 'br-vey-cand'
CHAIN = 'VEYPORT-CAND'
RULES = [['-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], ['-j', 'DROP']]


def run(args, check=True):
    result = subprocess.run(['iptables', '-w', '5'] + args, capture_output=True, text=True, timeout=10)
    if check and result.returncode:
        raise RuntimeError('candidate firewall operation failed')
    return result


def verify():
    lines = run(['-S', CHAIN]).stdout.splitlines()
    # iptables normalizes the conntrack state ordering.
    expected = ['-N ' + CHAIN, '-A ' + CHAIN + ' -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', '-A ' + CHAIN + ' -j DROP']
    if lines != expected:
        raise RuntimeError('candidate firewall chain differs from required policy')
    for chain, match in [('INPUT', ['-i', BRIDGE]), ('DOCKER-USER', ['-i', BRIDGE, '!', '-o', BRIDGE])]:
        rules = [line for line in run(['-S', chain]).stdout.splitlines() if line.startswith('-A ')]
        expected_first = '-A ' + chain + ' ' + ' '.join(match + ['-j', CHAIN])
        if not rules or rules[0] != expected_first:
            raise RuntimeError('candidate firewall hook is not first in chain')


def install():
    existing = run(['-S', CHAIN], check=False)
    if existing.returncode:
        run(['-N', CHAIN])
        for rule in RULES:
            run(['-A', CHAIN] + rule)
    for chain, match in [('INPUT', ['-i', BRIDGE]), ('DOCKER-USER', ['-i', BRIDGE, '!', '-o', BRIDGE])]:
        rule = match + ['-j', CHAIN]
        if run(['-C', chain] + rule, check=False).returncode:
            run(['-I', chain, '1'] + rule)
    verify()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('install', 'verify'))
    args = parser.parse_args()
    try:
        {'install': install, 'verify': verify}[args.command]()
        print('candidate bridge isolation rules verified')
    except (RuntimeError, OSError, subprocess.SubprocessError):
        sys.exit('candidate bridge isolation is not verified')
