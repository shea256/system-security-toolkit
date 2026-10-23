import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ca = load('ca', 'emudhra/macos/fix_system_ca.py')
tls = load('tls', 'emudhra/macos/verify_tls.py')


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root/'key.pem'), '-out', str(root/'cert.pem'),
                        '-days', '1', '-subj', '/CN=Toolkit unit test'], capture_output=True, check=True)
        cls.good = (root/'cert.pem').read_bytes()
        cls.bad = b''.join(p.read_bytes() for p in sorted((ROOT/'tests/fixtures').glob('*.pem')))
        cls.bundle = cls.good * 100 + cls.bad

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_public_keys_match_pinned_fingerprints(self):
        fixtures = list((ROOT/'tests/fixtures').glob('*.pem'))
        self.assertEqual(len(fixtures), 3)
        for p in fixtures:
            self.assertEqual(ca.fingerprint(p.read_bytes()), p.stem)
            self.assertIn(p.stem, ca.BLOCKED)

    def test_removes_only_listed_keys_and_is_idempotent(self):
        result, removed, count = ca.filtered(self.bundle)
        self.assertEqual(count, 103)
        self.assertEqual(len(removed), 3)
        self.assertEqual(ca.PEM.findall(result), ca.PEM.findall(self.good) * 100)
        self.assertEqual(ca.filtered(result), (result, [], 100))

    def test_preserves_clean_bundle_bytes(self):
        data = b'# annotation\n' + self.good * 100
        self.assertEqual(ca.filtered(data)[0], data)

    def test_fails_closed_for_truncation_invalid_cert_and_small_bundle(self):
        for data in (self.good, self.bundle + b'-----BEGIN CERTIFICATE-----',
                     self.bundle + b'-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----',
                     self.bundle + b'-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----'):
            with self.subTest(data_size=len(data)):
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    ca.filtered(data)

    def test_dry_run_never_writes_and_reports_remaining_trust(self):
        with patch.object(ca.sys, 'platform', 'darwin'), patch.object(ca, 'check_parents'), \
             patch.object(ca, 'secure_read', return_value=(self.bundle, None)), \
             patch.object(ca, 'replace_with_backup') as replace:
            self.assertEqual(ca.main([]), 1)
            replace.assert_not_called()

    def test_apply_noop_does_not_replace_clean_bundle(self):
        import contextlib
        with patch.object(ca.sys, 'platform', 'darwin'), patch.object(ca.os, 'geteuid', return_value=0), \
             patch.object(ca, 'check_parents'), patch.object(ca, 'locked', return_value=contextlib.nullcontext()), \
             patch.object(ca, 'secure_read', return_value=(self.good * 100, None)), \
             patch.object(ca, 'replace_with_backup') as replace:
            self.assertEqual(ca.main(['--apply']), 0)
            replace.assert_not_called()

    def test_linux_and_nonroot_apply_refused(self):
        with patch.object(ca.sys, 'platform', 'linux'):
            with self.assertRaises(SystemExit):
                ca.main(['--apply'])
        with patch.object(ca.sys, 'platform', 'darwin'), patch.object(ca.os, 'geteuid', return_value=501):
            with self.assertRaises(SystemExit):
                ca.main(['--apply'])

    def test_restore_requires_explicit_acknowledgement(self):
        with patch.object(ca.sys, 'platform', 'darwin'):
            with self.assertRaises(SystemExit):
                ca.main(['--restore', '/tmp/anything'])

    def test_restore_requires_exact_filtered_backup(self):
        target = Path('/private/etc/ssl/cert.pem')
        backup = target.with_name('cert.pem.sst-backup-' + 'a' * 32)
        clean = ca.filtered(self.bundle)[0]
        with patch.object(ca, 'secure_read', return_value=(self.bundle, None)):
            self.assertEqual(ca.restore_data(target, backup, clean), self.bundle)
            with self.assertRaises(ValueError):
                ca.restore_data(target, backup, clean + b'\n')
            with self.assertRaises(ValueError):
                ca.restore_data(target, Path('/tmp/' + backup.name), clean)

    def test_secure_read_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/'target'
            p.write_bytes(self.bundle)
            link = Path(temp)/'link'
            link.symlink_to(p)
            with self.assertRaises(OSError):
                ca.secure_read(link)

    def test_secure_read_refuses_writable_and_hardlinked_files(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/'target'
            p.write_bytes(self.bundle)
            p.chmod(0o666)
            with self.assertRaises(ValueError):
                ca.secure_read(p)
            p.chmod(0o644)
            os.link(p, Path(temp)/'hardlink')
            with self.assertRaises(ValueError):
                ca.secure_read(p)

    def test_atomic_replace_backup_metadata_and_change_detection(self):
        # Only this fixture reader bypasses root ownership, allowing unprivileged tests.
        def read_fixture(p):
            return p.read_bytes(), p.stat()
        with tempfile.TemporaryDirectory() as temp, patch.object(ca, 'secure_read', side_effect=read_fixture):
            p = Path(temp)/'cert.pem'
            p.write_bytes(self.bundle)
            p.chmod(0o644)
            info = p.stat()
            clean = ca.filtered(self.bundle)[0]
            backup = ca.replace_with_backup(p, self.bundle, info, clean)
            self.assertEqual(backup.read_bytes(), self.bundle)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
            self.assertEqual(p.read_bytes(), clean)
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o644)
            with self.assertRaises(ValueError):
                ca.replace_with_backup(p, self.bundle, info, clean)
            restored = ca.restore_data(p, backup, clean)
            ca.replace_with_backup(p, clean, p.stat(), restored)
            self.assertEqual(p.read_bytes(), self.bundle)

    def test_failed_replace_preserves_original(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/'cert.pem'
            p.write_bytes(self.bundle)
            with patch.object(ca, 'secure_read', side_effect=lambda path: (path.read_bytes(), path.stat())), \
                 patch.object(ca.os, 'replace', side_effect=OSError('simulated failure')):
                with self.assertRaises(OSError):
                    ca.replace_with_backup(p, self.bundle, p.stat(), ca.filtered(self.bundle)[0])
            self.assertEqual(p.read_bytes(), self.bundle)
            self.assertEqual(list(Path(temp).glob('.sst-ca-*')), [])


class ProbeTests(unittest.TestCase):
    def test_network_failure_is_not_a_pass(self):
        for result in ({'exit': 6}, {'exit': 28}, {'error': 'timeout'},
                       {'exit': 60, 'stderr': 'certificate has expired'},
                       {'exit': 60, 'stderr': 'hostname mismatch'}):
            self.assertEqual(tls.classify(result, 'curl'), 'inconclusive')

    def test_acceptance_and_issuer_rejection(self):
        self.assertEqual(tls.classify({'exit': 0, 'stdout': '200'}, 'curl'), 'accepted')
        self.assertEqual(tls.classify({'exit': 60, 'stderr': 'unable to get local issuer certificate'}, 'curl'), 'rejected')
        self.assertEqual(tls.classify({'exit': 128, 'stderr': 'info/refs not valid'}, 'git'), 'accepted')
        self.assertEqual(tls.classify({'exit': 128, 'stderr': 'unable to get local issuer certificate'}, 'git'), 'rejected')


if __name__ == '__main__':
    unittest.main()
