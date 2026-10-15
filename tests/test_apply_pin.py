"""Regression gates for upgrading an existing checkout and refusing anchor drift."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('pin', Path(__file__).parents[1] / 'patches/apply-pin.py')
pin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pin)


class PatchUpgradeTests(unittest.TestCase):
    def test_pristine_and_v1_upgrade_are_idempotent(self):
        for original in (pin.T2_OLD, pin.T2_V1):
            with self.subTest(original=original[:30]), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                target = root / pin.T2_REL
                target.parent.mkdir(parents=True)
                target.write_text('before\n' + original + '\nafter\n')
                self.assertEqual(pin.patch_outbound(root), 'APPLIED')
                expected = 'before\n' + pin.T2_NEW + '\nafter\n'
                self.assertEqual(target.read_text(), expected)
                self.assertEqual(pin.patch_outbound(root), 'ALREADY')
                self.assertEqual(target.read_text(), expected)

    def test_partial_marker_and_unknown_v1_refused_without_writes(self):
        for original in (pin.MARKER, pin.T2_V1.replace('tls.insecure = false;', 'tls.insecure = true;'),
                         pin.T2_OLD + '\n' + pin.T2_OLD):
            with self.subTest(original=original[:30]), tempfile.TemporaryDirectory() as work:
                root = Path(work)
                target = root / pin.T2_REL
                target.parent.mkdir(parents=True)
                target.write_text(original)
                self.assertTrue(pin.patch_outbound(root).startswith('FAILED'))
                self.assertEqual(target.read_text(), original)

    def test_hy2_anchor_upgrade_idempotency_and_drift(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            target = root / pin.T4_REL
            target.parent.mkdir(parents=True)
            target.write_text(pin.T4_OLD)
            self.assertEqual(pin.patch_hy2(root), 'APPLIED')
            self.assertEqual(pin.patch_hy2(root), 'ALREADY')
            target.write_text(pin.T4_NEW.replace('isPublicKeyPin = false', 'isPublicKeyPin = true'))
            before = target.read_bytes()
            self.assertTrue(pin.patch_hy2(root).startswith('FAILED'))
            self.assertEqual(target.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
