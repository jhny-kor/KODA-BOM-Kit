#!/usr/bin/env python3
"""Check release tool selection and verifier startup without a target or Docker."""
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
QA_ENTRY_POINTS = (
    'scripts/finalize-release.py',
    'tests/check_binary.py',
    'tests/integration.py',
    'tests/docker_integration.py',
    'tests/directory_integration.py',
    'tests/livepatch_integration.py',
)


class ReleaseGuards(unittest.TestCase):
    def run_command(self, args, env=None):
        return subprocess.run(args, cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)

    def test_optimized_python_cannot_start_release_qa(self):
        for script in QA_ENTRY_POINTS:
            args = [str(ROOT / script), '--help']
            with self.subTest(script=script):
                normal_env = {name: value for name, value in os.environ.items() if name != 'PYTHONOPTIMIZE'}
                normal = self.run_command([sys.executable, *args], normal_env)
                self.assertEqual(normal.returncode, 0, normal.stderr)
                for flags, env in ((['-O'], normal_env), ([], {**normal_env, 'PYTHONOPTIMIZE': '1'})):
                    optimized = self.run_command([sys.executable, *flags, *args], env)
                    self.assertNotEqual(optimized.returncode, 0)
                    self.assertFalse(optimized.stdout)
                    self.assertIn('Python optimization', optimized.stderr)

    def test_alternate_go_requires_matching_trusted_digest(self):
        # The ordinary Python executable stands in for an unrelated absolute tool.
        cmd = [str(ROOT / 'scripts/build-release.sh')]
        env = {**os.environ, 'GO_BIN': sys.executable}
        for args, message in (
            ([], 'require a matching --go'),
            (['--go', sys.executable], 'require --go-sha256'),
            (['--go', sys.executable, '--go-sha256', '0' * 64], 'does not match'),
        ):
            with self.subTest(args=args):
                failed = self.run_command([*cmd, *args], env)
                self.assertEqual(failed.returncode, 2, failed.stderr)
                self.assertFalse(failed.stdout)
                self.assertIn(message, failed.stderr)


if __name__ == '__main__':
    unittest.main()
