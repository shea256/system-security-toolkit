"""Root integration tests for a disposable GitHub macOS runner, never a live bundle."""
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ca', ROOT/'emudhra/macos/fix_system_ca.py')
ca = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ca)
LIVE_TARGET = ca.TARGET


class PrivilegedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.live_hash = hashlib.sha256(LIVE_TARGET.read_bytes()).hexdigest()
        cls.root = tempfile.TemporaryDirectory(prefix='sst-integration-', dir='/private/var/root')
        fixture = Path(cls.root.name)
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(fixture/'key.pem'), '-out', str(fixture/'cert.pem'),
                        '-days', '1', '-subj', '/CN=Toolkit disposable test'],
                       capture_output=True, check=True)
        cls.bundle = (fixture/'cert.pem').read_bytes() * 100
        cls.bundle += b''.join(p.read_bytes() for p in sorted((ROOT/'tests/fixtures').glob('*.pem')))

    @classmethod
    def tearDownClass(cls):
        cls.root.cleanup()
        if hashlib.sha256(LIVE_TARGET.read_bytes()).hexdigest() != cls.live_hash:
            raise AssertionError('The runner system trust bundle changed during tests.')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.root.name)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.target = self.directory/'cert.pem'
        self.target.write_bytes(self.bundle)
        self.target.chmod(0o644)
        # Redirect only the target constant; all file/privilege/locking checks remain real.
        self.redirect = patch.object(ca, 'TARGET', self.target)
        self.redirect.start()
        self.addCleanup(self.redirect.stop)

    def test_dry_run_apply_idempotence_and_restore(self):
        self.assertEqual(ca.main([]), 1)
        self.assertEqual(self.target.read_bytes(), self.bundle)
        self.assertEqual(list(self.directory.glob('cert.pem.sst-backup-*')), [])
        self.assertEqual(ca.main(['--apply']), 0)
        self.assertEqual(len(ca.PEM.findall(self.target.read_bytes())), 100)
        info = self.target.stat()
        self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o777), (0, os.getegid(), 0o644))
        backups = list(self.directory.glob('cert.pem.sst-backup-*'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.bundle)
        self.assertEqual(backups[0].stat().st_uid, 0)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(ca.main(['--apply']), 0)
        self.assertEqual(list(self.directory.glob('cert.pem.sst-backup-*')), backups)
        self.assertEqual(ca.main(['--restore', str(backups[0]), '--acknowledge-restored-trust']), 0)
        self.assertEqual(self.target.read_bytes(), self.bundle)

    def test_refuses_restore_over_subsequent_changes(self):
        ca.main(['--apply'])
        backup = next(self.directory.glob('cert.pem.sst-backup-*'))
        self.target.write_bytes(self.target.read_bytes() + b'\n# subsequent update\n')
        before = self.target.read_bytes()
        with self.assertRaises(ValueError):
            ca.main(['--restore', str(backup), '--acknowledge-restored-trust'])
        self.assertEqual(self.target.read_bytes(), before)

    def test_refuses_symlink_target_and_lock(self):
        real = self.directory/'real.pem'
        self.target.rename(real)
        self.target.symlink_to(real)
        with self.assertRaises(OSError):
            ca.main(['--apply'])
        self.assertEqual(real.read_bytes(), self.bundle)
        self.target.unlink()
        real.rename(self.target)
        lock = self.directory/'.system-security-toolkit-ca.lock'
        lock.unlink()
        lock.symlink_to(self.target)
        with self.assertRaises(OSError):
            ca.main(['--apply'])
        self.assertEqual(self.target.read_bytes(), self.bundle)

    def test_refuses_untrusted_ownership_and_parent_permissions(self):
        os.chown(self.target, 501, -1)
        with self.assertRaises(ValueError):
            ca.main(['--apply'])
        os.chown(self.target, 0, -1)
        self.directory.chmod(0o777)
        with self.assertRaises(ValueError):
            ca.main(['--apply'])
        self.directory.chmod(0o700)
        self.assertEqual(self.target.read_bytes(), self.bundle)

    def test_exclusive_lock_prevents_another_apply(self):
        with ca.locked(self.target):
            with self.assertRaises(BlockingIOError):
                ca.main(['--apply'])
        self.assertEqual(self.target.read_bytes(), self.bundle)


if __name__ == '__main__':
    if (sys.platform != 'darwin' or os.geteuid() != 0 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        sys.exit('Run only as root in the disposable GitHub-hosted macOS CI job.')
    unittest.main(verbosity=2)
