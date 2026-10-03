#!/usr/bin/env python3
"""Deploy an owned binary and test official Mac recovery via authorized SSH.

SSH is only the test/deployment transport. The installed optimizer talks directly
to the assistant over Tailscale and never reads these SSH credentials.
This harness disables source-session capture. Test the complete dynamic search
from a native Mac terminal with sudo -v, as documented in macos-source-sessions.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--identity', required=True)
    parser.add_argument('--known-hosts', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--peer', required=True)
    parser.add_argument('--budget', default='120s')
    parser.add_argument('--hold', default='20s')
    parser.add_argument('--count', default='6')
    parser.add_argument('--rebinds', default='2')
    parser.add_argument('--transfer-timeout', type=int, default=900)
    args = parser.parse_args()
    os.umask(0o077)
    run = Path(args.output_dir)
    run.mkdir(parents=True, mode=0o700, exist_ok=False)
    base = Path(__file__).resolve().parents[1]
    options = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o',
               'ConnectTimeout=45', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=3', '-o', 'StrictHostKeyChecking=yes', '-o',
               'UserKnownHostsFile=' + args.known_hosts, '-i', args.identity]
    ssh = ['ssh', '-T'] + options + [args.host]

    def remote(name, command, timeout=30):
        started = time.time()
        # SSH can forward a Linux-only locale that crashes macOS's Perl shasum.
        wrapped = 'env LC_ALL=C LC_CTYPE=C LANG=C /bin/bash -e -o pipefail -c ' + shlex.quote(command)
        result = subprocess.run(ssh + [wrapped], capture_output=True, text=True, timeout=timeout)
        (run / name).write_text(result.stdout)
        (run / (name + '.stderr')).write_text(result.stderr)
        (run / (name + '.meta.json')).write_text(json.dumps({
            'exit_code': result.returncode, 'duration_seconds': time.time() - started,
        }, indent=2))
        return result

    system = remote('mac-system.txt', 'printf "%s\\n" "$HOME"; uname -m; sw_vers -productVersion; defaults read /Applications/Tailscale.app/Contents/Info CFBundleIdentifier')
    if system.returncode:
        raise RuntimeError('Mac access failed; no remote file changes')
    lines = system.stdout.splitlines()
    home, arch = lines[:2]
    if not home.startswith('/Users/') or arch not in ('arm64', 'x86_64'):
        raise RuntimeError('Unexpected Mac home or architecture')
    name = 'ts-direct-darwin-' + ('arm64' if arch == 'arm64' else 'amd64')
    binary = base / 'dist' / name
    manifest = json.loads((base / 'dist/manifest.json').read_text())
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != next(item['sha256'] for item in manifest['files'] if item['name'] == name):
        raise RuntimeError('Local artifact checksum mismatch')
    stamp = run.name
    remote_bin = home + '/bin/ts-direct'
    upload = home + '/bin/.ts-direct-upload-' + str(os.getpid())
    reports = home + '/.local/state/ts-direct/runs/' + stamp
    setup = remote('mac-setup.txt', 'umask 077; mkdir -p ' + shlex.quote(home + '/bin') + ' ' + shlex.quote(reports))
    if setup.returncode:
        raise RuntimeError('Mac directory preparation failed')
    try:
        transfer = subprocess.run(['scp', '-q', '-C'] + options + [str(binary), args.host + ':' + upload], capture_output=True, text=True, timeout=args.transfer_timeout)
        (run / 'mac-transfer.stderr').write_text(transfer.stderr)
        if transfer.returncode:
            raise RuntimeError('Artifact transfer failed')
        check = remote('mac-upload-sha256.txt', 'shasum -a 256 ' + shlex.quote(upload))
        if check.returncode:
            raise RuntimeError('Remote checksum command failed; see its preserved stderr')
        if not check.stdout.split() or check.stdout.split()[0] != digest:
            raise RuntimeError('Remote artifact checksum mismatch')
        install = ('if test -e ' + shlex.quote(remote_bin) + '; then cp -p ' +
                   shlex.quote(remote_bin) + ' ' + shlex.quote(remote_bin + '.backup-' + stamp) + '; fi; chmod 700 ' +
                   shlex.quote(upload) + ' && mv ' + shlex.quote(upload) + ' ' + shlex.quote(remote_bin))
        if remote('mac-install.txt', install).returncode:
            raise RuntimeError('Mac installation failed')
        result = remote('mac-status-before.json', shlex.join([remote_bin, 'status', '--peer', args.peer, '--json']))
        if result.returncode:
            raise RuntimeError('Installed binary cannot access LocalAPI')
        prefs = '/Applications/Tailscale.app/Contents/MacOS/Tailscale debug prefs | shasum -a 256'
        if remote('mac-preferences-before.sha256', prefs).returncode:
            raise RuntimeError('Native preferences digest collection failed')
        print('Mac optimizer started; native client and verified artifact are ready.', flush=True)
        command = [remote_bin, 'optimize', '--peer', args.peer, '--once', '--budget', args.budget,
                   '--hold', args.hold, '--count', args.count, '--rebinds', args.rebinds,
                   '--source-sessions', '0',
                   '--json', '--output', reports + '/optimize.json']
        result = remote('mac-optimize.json', shlex.join(command), timeout=210)
        report = json.loads(result.stdout)
        (run / 'deployment.json').write_text(json.dumps({
            'binary': remote_bin, 'sha256': digest, 'release': manifest['release'],
            'mac_report': reports + '/optimize.json', 'optimization_exit_code': result.returncode,
        }, indent=2))
        print(json.dumps({k: report.get(k) for k in ('outcome', 'direct_verified', 'optimized', 'application_verified', 'error')}, ensure_ascii=False), flush=True)
        for trial in report.get('trials', []):
            local = (trial.get('local') or {}).get('summary') or {}
            remote_side = ((trial.get('remote') or {}).get('report') or {}).get('summary') or {}
            print(trial['name'], 'Mac:', (local.get('last_probe_path') or {}).get('type'),
                  'server:', (remote_side.get('last_probe_path') or {}).get('type'), flush=True)
        remote('mac-status-after.json', shlex.join([remote_bin, 'status', '--peer', args.peer, '--json']))
        remote('mac-preferences-after.sha256', prefs)
        return result.returncode
    finally:
        remote('mac-upload-cleanup.txt', 'rm -f ' + shlex.quote(upload))


if __name__ == '__main__':
    raise SystemExit(main())
