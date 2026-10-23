#!/usr/bin/env python3
"""Opt-in network probes of macOS curl/Git; never downloads or executes code."""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile

ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C', 'LC_ALL': 'C',
       'HOME': '/var/empty', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
       'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/usr/bin/false'}
HOSTS = ('dv-g3b', 'dv-g3b-aaa', 'dv-g3b-noct', 'dv-g3b-aaa-noct')


def run(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, env=ENV,
                                cwd=tempfile.gettempdir(), timeout=25)
        return {'exit': result.returncode, 'stdout': result.stdout[:3000], 'stderr': result.stderr[:3000]}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'error': str(error)}


def classify(result, tool, control=False):
    code = result.get('exit')
    if control:
        return 'control_ok' if code == 0 else 'inconclusive'
    stderr = result.get('stderr', '').lower()
    issuer_error = any(s in stderr for s in ('unable to get local issuer certificate',
                                            'certificate revoked', 'certificate has been revoked'))
    if issuer_error and code == (60 if tool == 'curl' else 128):
        return 'rejected'
    if tool == 'curl' and code == 0 and result.get('stdout', '').strip().isdigit() and int(result['stdout']) >= 100:
        return 'accepted'
    if tool == 'git' and code == 128 and 'info/refs not valid' in stderr:
        return 'accepted'
    # DNS failures, timeouts, expired certs and hostname errors do not prove mitigation.
    return 'inconclusive'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--network', action='store_true', help='contact researcher test hosts and GitHub over HTTPS')
    args = parser.parse_args()
    if sys.platform != 'darwin':
        parser.error('This verifier tests Apple-provided tools on macOS only.')
    if not args.network:
        parser.error('Add --network to allow the documented network probes.')
    jobs = {}
    curl = ['/usr/bin/curl', '--disable', '--head', '--silent', '--show-error', '--output', '/dev/null',
            '--write-out', '%{http_code}', '--connect-timeout', '8', '--max-time', '18', '--proto', '=https']
    git = ['/usr/bin/git', '-c', 'credential.helper=', '-c', 'core.askPass=', '-c', 'http.extraHeader=',
           '-c', 'http.sslVerify=true', '-c', 'http.followRedirects=false', '-c', 'http.lowSpeedLimit=1',
           '-c', 'http.lowSpeedTime=15', 'ls-remote']
    jobs['curl_control'] = curl + ['https://github.com/']
    jobs['git_control'] = git + ['https://github.com/openai/codex.git', 'HEAD']
    for host in HOSTS:
        url = 'https://' + host + '-emudhra.we-have-a-problem.com/'
        jobs['curl_' + host] = curl + [url]
        jobs['git_' + host] = git + [url, 'HEAD']
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = {name: pool.submit(run, command) for name, command in jobs.items()}
        results = {name: future.result() for name, future in futures.items()}
    for name, result in results.items():
        result['status'] = classify(result, name.split('_')[0], name.endswith('_control'))
    print(json.dumps(results, indent=2))
    if any(r['status'] == 'accepted' for r in results.values()):
        return 1
    if any(r['status'] == 'inconclusive' for r in results.values()):
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
