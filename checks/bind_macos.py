#!/usr/bin/env python3
"""Read-only, partial BIND server inventory. Does not scan containers or VMs."""
import json
from pathlib import Path
import plistlib
import subprocess
import sys


def command(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=15)
        return {'exit': p.returncode, 'stdout': p.stdout[:4000], 'stderr': p.stderr[:1000]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'error': str(error)}


def inventory():
    result = {'scope': 'Standard macOS/Homebrew/MacPorts paths and processes. No containers, VMs, remote hosts or exhaustive disk search.',
              'binaries': [], 'package_paths': [], 'launch_items': [], 'inspection_errors': []}
    for root in ('/usr/sbin', '/usr/local/sbin', '/opt/homebrew/sbin', '/opt/local/sbin'):
        for name in ('named', 'rndc'):
            path = Path(root) / name
            if path.exists():
                result['binaries'].append(str(path))
    for root in ('/opt/homebrew/Cellar', '/usr/local/Cellar', '/opt/local/var/macports/software'):
        path = Path(root)
        if path.is_dir():
            try:
                result['package_paths'].extend(str(p) for p in path.iterdir() if p.name == 'bind' or p.name.startswith(('bind9', 'bind@')))
            except OSError as error:
                result['inspection_errors'].append(str(error))
    for root in ('/Library/LaunchDaemons', '/Library/LaunchAgents', '/System/Library/LaunchDaemons',
                 str(Path.home() / 'Library/LaunchAgents')):
        for path in Path(root).glob('*.plist'):
            try:
                data = plistlib.loads(path.read_bytes())
                args = [data.get('Program', '')] + data.get('ProgramArguments', [])
                if any(isinstance(a, str) and Path(a).name in ('named', 'rndc') for a in args):
                    result['launch_items'].append(str(path))
            except (OSError, ValueError, plistlib.InvalidFileException) as error:
                result['inspection_errors'].append(str(path) + ': ' + str(error))
    result['named_process'] = command(['/usr/bin/pgrep', '-x', 'named'])
    result['visible_port_53'] = command(['/usr/sbin/lsof', '-nP', '-iUDP:53', '-iTCP:53'])
    result['dig_client'] = command(['/usr/bin/dig', '-v'])
    result['note'] = 'dig is a client, not proof of a running named server. Unprivileged lsof visibility may be incomplete. No vulnerability verdict is inferred from version strings.'
    return result


if __name__ == '__main__':
    if sys.platform != 'darwin':
        sys.exit('This inventory supports macOS only.')
    print(json.dumps(inventory(), indent=2))
