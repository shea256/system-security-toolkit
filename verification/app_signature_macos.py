#!/usr/bin/env python3
"""Verify an existing app's signature, expected identity and Gatekeeper assessment."""
import argparse
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    parser.add_argument('--team-id', required=True, help='expected publisher ID from an independently trusted source')
    parser.add_argument('--bundle-id', required=True, help='expected application identifier')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('macOS only.')
    if not re.fullmatch(r'[A-Z0-9]{10}', args.team_id) or not re.fullmatch(r'[A-Za-z0-9.-]+', args.bundle_id):
        parser.error('Invalid team or bundle identifier.')
    app = args.app.resolve(strict=True)
    if app.suffix != '.app' or not app.is_dir():
        parser.error('Expected an existing .app directory.')
    requirement = ('=anchor apple generic and identifier "' + args.bundle_id +
                   '" and certificate leaf[subject.OU] = "' + args.team_id +
                   '" and certificate 1[field.1.2.840.113635.100.6.2.6] exists'
                   ' and certificate leaf[field.1.2.840.113635.100.6.1.13] exists')
    checks = {
        'integrity': ['/usr/bin/codesign', '--verify', '--deep', '--strict', '--verbose=2', str(app)],
        'publisher': ['/usr/bin/codesign', '--verify', '--strict', '-R', requirement, str(app)],
        'gatekeeper': ['/usr/sbin/spctl', '--assess', '--type', 'execute', '--verbose=2', str(app)],
    }
    results = {}
    for name, command in checks.items():
        try:
            p = subprocess.run(command, capture_output=True, text=True, timeout=60)
            results[name] = {'exit': p.returncode, 'stdout': p.stdout[:2000], 'stderr': p.stderr[:2000]}
        except (OSError, subprocess.TimeoutExpired) as error:
            results[name] = {'error': str(error)}
    with (app / 'Contents/Info.plist').open('rb') as handle:
        info = plistlib.load(handle)
    results['reported_version'] = info.get('CFBundleShortVersionString')
    results['note'] = 'A valid signature does not prove the app or embedded runtime is free of vulnerabilities. Gatekeeper may contact Apple.'
    print(json.dumps(results, indent=2))
    return 0 if all(results[name].get('exit') == 0 for name in checks) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        sys.exit('Stopped: ' + str(error))
