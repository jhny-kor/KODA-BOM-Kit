#!/usr/bin/env python3
"""Check source hashing without reading generated inventory or whole files."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SourceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.script = self.root / 'scripts/source-identity.py'
        self.script.parent.mkdir()
        shutil.copyfile(ROOT / 'scripts/source-identity.py', self.script)
        (self.root / 'source.txt').write_bytes(b'content\n' * 200000)

    def identity(self, reject_whole_file_reads=False):
        runner = '''import pathlib, runpy, sys
if sys.argv[2] == 'guard':
    def forbidden(*args, **kwargs):
        raise AssertionError('source hashing must stream file contents')
    pathlib.Path.read_bytes = forbidden
runpy.run_path(sys.argv[1], run_name='__main__')
'''
        result = subprocess.run(
            [sys.executable, '-c', runner, str(self.script),
             'guard' if reject_whole_file_reads else 'normal'],
            capture_output=True, text=True, check=True, timeout=10)
        return result.stdout.strip()

    def test_streaming_preserves_existing_hash_format(self):
        expected = hashlib.sha256()
        for path in sorted(self.root.rglob('*')):
            if path.is_file():
                expected.update(path.relative_to(self.root).as_posix().encode() + b'\0')
                expected.update(path.read_bytes())
                expected.update(b'\0')
        self.assertEqual(self.identity(reject_whole_file_reads=True),
                         'src' + expected.hexdigest()[:12])

    def test_generated_inventory_and_runtime_do_not_change_identity(self):
        before = self.identity()
        for directory in ('SBOM', '.omc', 'reports', 'dist'):
            path = self.root / directory / 'nested/output.json'
            path.parent.mkdir(parents=True)
            path.write_text('generated data')
        self.assertEqual(self.identity(), before)
        (self.root / 'source.txt').write_text('changed source')
        self.assertNotEqual(self.identity(), before)


if __name__ == '__main__':
    unittest.main()
