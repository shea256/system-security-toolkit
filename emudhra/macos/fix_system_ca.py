#!/usr/bin/env python3
"""Offline, explicit mitigation for macOS's PEM trust bundle. Python 3.9+."""

import argparse
import contextlib
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid

TARGET = Path('/private/etc/ssl/cert.pem')
OPENSSL = '/usr/bin/openssl'
MIN_CERTS = 100
MAX_BYTES = 4 * 1024 * 1024
PEM = re.compile(rb'-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----', re.S)
# SHA-256 of DER SubjectPublicKeyInfo, NOT certificate fingerprints.
# Provenance and the broader effects of removing these roots: README.md.
BLOCKED = {
    'bd153ed7b0434f6886b17bce8bbe84ed340c7132d702a8f4fa318f756ecbd6f3': 'AAA Certificate Services',
    '8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782': 'emSign ECC Root CA - G3',
    'c619e4780ed8e0abeda24ad732567de4383a7ea941338f6d1a7d1b49ac792fe9': 'emSign Root TLS CA - G3',
}
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C'}


def openssl(args, data):
    result = subprocess.run([OPENSSL] + args, input=data, capture_output=True,
                            env=ENV, timeout=10, check=True)
    return result.stdout


def fingerprint(cert):
    public = openssl(['x509', '-pubkey', '-noout'], cert)
    der = openssl(['pkey', '-pubin', '-outform', 'der'], public)
    return hashlib.sha256(der).hexdigest()


def filtered(data):
    """Validate every certificate; remove only the explicit public keys above."""
    certs = PEM.findall(data)
    if not MIN_CERTS <= len(certs) <= 1000:
        raise ValueError('Unexpected certificate count; refusing to modify bundle.')
    if data.count(b'-----BEGIN CERTIFICATE-----') != len(certs) or data.count(b'-----END CERTIFICATE-----') != len(certs):
        raise ValueError('Incomplete or malformed PEM bundle.')
    # Ignore normal text annotations, but never silently discard another PEM object.
    if b'-----BEGIN ' in PEM.sub(b'', data) or b'-----END ' in PEM.sub(b'', data):
        raise ValueError('Unexpected PEM object in bundle.')
    keys = {}
    kept, removed = [], []
    for cert in certs:
        if cert not in keys:
            keys[cert] = fingerprint(cert)
        key = keys[cert]
        if key in BLOCKED:
            removed.append({'spki_sha256': key, 'name': BLOCKED[key]})
        else:
            kept.append(cert)
    if len(kept) < MIN_CERTS:
        raise ValueError('Too few certificates would remain; refusing modification.')
    # Idempotence preserves an already-mitigated bundle byte-for-byte.
    return (b'\n'.join(kept) + b'\n' if removed else data), removed, len(certs)


def secure_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Expected a regular file with one hard link: ' + str(path))
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('File must be root-owned and not group/world writable: ' + str(path))
        data = handle.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError('File exceeds size limit.')
    return data, info


def check_parents(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted parent directory: ' + str(parent))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            info.st_mode, info.st_mtime_ns, info.st_size, getattr(info, 'st_flags', 0))


def unchanged(path, data, info):
    current, current_info = secure_read(path)
    if current != data or identity(current_info) != identity(info):
        raise ValueError('Bundle changed during operation; stopped.')


@contextlib.contextmanager
def locked(target):
    path = target.with_name('.system-security-toolkit-ca.lock')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('Unsafe lock file; stopped.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def replace_with_backup(target, original, info, updated):
    """Caller holds lock. Preserve content on failure before atomic replacement."""
    unchanged(target, original, info)
    if getattr(info, 'st_flags', 0):
        raise ValueError('Unexpected file flags; refusing replacement.')
    backup = target.with_name(target.name + '.sst-backup-' + uuid.uuid4().hex)
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(original)
        handle.flush()
        os.fsync(handle.fileno())
    print('Backup:', backup, flush=True)
    fd, temporary = tempfile.mkstemp(prefix='.sst-ca-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(updated)
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            handle.flush()
            os.fsync(handle.fileno())
        unchanged(target, original, info)
        os.replace(temporary, target)
        parent_fd = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return backup


def restore_data(target, backup, current):
    if backup.parent != target.parent or not re.fullmatch(re.escape(target.name) + r'\.sst-backup-[0-9a-f]{32}', backup.name):
        raise ValueError('Restore requires a backup created by this tool beside cert.pem.')
    original, _ = secure_read(backup)
    expected, removed, _ = filtered(original)
    if not removed or expected != current:
        raise ValueError('Current bundle is not the filtered version of this backup. Refusing to overwrite other changes.')
    return original


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true', help='back up and replace the macOS system PEM bundle')
    mode.add_argument('--restore', type=Path, metavar='BACKUP', help='restore an exact prior bundle (reintroduces affected trust)')
    parser.add_argument('--acknowledge-restored-trust', action='store_true', help='required with --restore')
    args = parser.parse_args(argv)
    if sys.platform != 'darwin':
        parser.error('This tool supports macOS only.')
    if args.acknowledge_restored_trust and not args.restore:
        parser.error('--acknowledge-restored-trust requires --restore.')
    if args.restore and not args.acknowledge_restored_trust:
        parser.error('Restore reintroduces affected trust; add --acknowledge-restored-trust.')
    if (args.apply or args.restore) and os.geteuid() != 0:
        parser.error('Apply and restore require sudo. Dry-run does not.')
    check_parents(TARGET)
    context = locked(TARGET) if args.apply or args.restore else contextlib.nullcontext()
    with context:
        original, info = secure_read(TARGET)
        if args.restore:
            updated = restore_data(TARGET, args.restore.absolute(), original)
            replace_with_backup(TARGET, original, info, updated)
            print('Restored. Affected trust has been reintroduced. Reassess before using network tools.')
            return 0
        updated, removed, count = filtered(original)
        print('Certificates:', count, 'Retained:', count - len(removed), 'Affected:', len(removed))
        for item in removed:
            print(item['name'], 'SPKI SHA256:', item['spki_sha256'])
        if not removed:
            print('No listed root keys found. This does not assess other trust stores.')
            return 0
        if not args.apply:
            print('Dry run only. Use --apply after review. No files changed.')
            return 1
        replace_with_backup(TARGET, original, info, updated)
        print('Applied. Now run verify_tls.py. Recheck after OS updates.')
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print('Stopped:', error, file=sys.stderr)
        sys.exit(2)
