#!/usr/bin/env python3
"""Black-box helper argument boundaries with local synthetic clients/collector."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def exercise():
    source = Path(__file__).resolve().parents[1] / 'scripts/collect-livepatch-status.sh'
    with tempfile.TemporaryDirectory(prefix='koda-helper-options-qa-') as tmp:
        work = Path(tmp)
        release = work / 'release'
        release.mkdir()
        helper = release / source.name
        shutil.copy2(source, helper)
        helper.chmod(0o755)
        collector = release / 'koda-sbom'
        collector.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
with open(os.environ['QA_CALLS'], 'a') as stream:
    stream.write(json.dumps({'kind': 'collector', 'args': sys.argv[1:]})+'\\n')
if sys.argv[1] == 'validate-scan-options':
    # Synthetic pure-validator responses exercise helper ordering, not Go's
    # duration/glob parsing; the real binary gets separate integration tests.
    if any(value in ('not-a-duration', '9223372036854775808', '[') for value in sys.argv[2:]):
        sys.exit(2)
elif sys.argv[1] == 'doctor':
    print('{"supported":true}')
elif sys.argv[1] == 'livepatch-evidence':
    target = pathlib.Path(sys.argv[sys.argv.index('--output')+1])
    target.write_text('{}')
elif sys.argv[1] != 'scan':
    sys.exit(2)
''')
        collector.chmod(0o755)
        mocks = work / 'mocks'
        mocks.mkdir()
        for name in ('canonical-livepatch', 'ksplice', 'uptrack-show', 'uptrack-uname'):
            client = mocks / name
            client.write_text('''#!/bin/sh
printf 'client\\n' >> "$QA_CLIENT_CALLS"
printf 'synthetic installed client status\\n'
''')
            client.chmod(0o755)
        timeout = mocks / 'timeout'
        timeout.write_text('''#!/usr/bin/env python3
import json, os, sys
if sys.argv[2] == '10s':
    # The real helper deliberately caps this query's file size to one block.
    with open(os.environ['QA_CALLS']+'.effective', 'w') as stream:
        json.dump({'kind': 'timeout', 'args': sys.argv[1:3]}, stream)
else:
    with open(os.environ['QA_CALLS'], 'a') as stream:
        stream.write(json.dumps({'kind': 'timeout', 'args': sys.argv[1:]})+'\\n')
os.execv(sys.argv[3], sys.argv[3:])
''')
        timeout.chmod(0o755)
        rawtmp = work / 'rawtmp'
        rawtmp.mkdir()

        def invoke(label, options):
            calls = work / (label + '-calls.jsonl')
            clients = work / (label + '-clients.txt')
            output = work / (label + '-output')
            env = dict(os.environ, PATH=str(mocks)+os.pathsep+os.environ.get('PATH', ''),
                       TMPDIR=str(rawtmp), QA_CALLS=str(calls), QA_CLIENT_CALLS=str(clients))
            result = subprocess.run([str(helper), str(output), *options], env=env,
                                    capture_output=True, text=True, timeout=20)
            return result, calls, clients, output

        options = ['--timeout', '0', '--max-files', '0', '--exclude', '/qa/**',
                   '--exclude', '/path with spaces/**', '--timeout=10m', '--timeout=0']
        result, calls, clients, output = invoke('valid', options)
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        history = [json.loads(line) for line in calls.read_text().splitlines()]
        assert history[0] == {'kind': 'collector', 'args': ['validate-scan-options', *options]}, history
        scan = [call['args'] for call in history if call['kind'] == 'collector' and call['args'][0] == 'scan']
        assert len(scan) == 1 and scan[0][-len(options):] == options, scan
        assert scan[0][1:3] == ['--output-dir', str(output)], scan
        timeouts = [call['args'] for call in history if call['kind'] == 'timeout']
        timeouts.append(json.loads(Path(str(calls)+'.effective').read_text())['args'])
        assert len(timeouts) == 4, timeouts
        assert all(args[:2] == ['--kill-after=5s', '30s'] for args in timeouts[:3]), timeouts
        assert timeouts[-1][:2] == ['--kill-after=5s', '10s'], timeouts
        assert len(clients.read_text().splitlines()) == 4
        assert not list(rawtmp.iterdir()), 'raw client files were retained'

        invalid = [
            ['--unknown'], ['--timeout'], ['--max-files'], ['--exclude'],
            ['--timeout='], ['--max-files='], ['--exclude='],
            ['--timeout', '--max-files', '0'], ['--max-files', '-1'],
            ['--timeout=-1s'], ['--output-dir', '/elsewhere'], ['--output-dir=/elsewhere'],
            ['--target', '/opt/app'], ['--target=/'], ['--image-archive', 'image.tar'],
            ['--no-context'], ['--livepatch-evidence', 'foreign.json'],
            ['--format', 'spdx'], ['--', '--timeout', '0'], ['unexpected-position'],
        ]
        for index, args in enumerate(invalid):
            result, calls, clients, output = invoke('invalid-'+str(index), args)
            assert result.returncode == 2, (args, result.returncode, result.stdout, result.stderr)
            assert not output.exists(), ('invalid arguments created output', args)
            assert not calls.exists() and not clients.exists(), ('invalid arguments executed a collector/client', args)
        invalid_values = [
            ['--timeout', 'not-a-duration'],
            ['--max-files', '9223372036854775808'],
            ['--exclude', '['],
        ]
        for index, args in enumerate(invalid_values):
            result, calls, clients, output = invoke('invalid-value-'+str(index), args)
            assert result.returncode == 2, (args, result.returncode, result.stdout, result.stderr)
            assert not output.exists() and not clients.exists(), ('invalid values caused output/client side effects', args)
            history = [json.loads(line) for line in calls.read_text().splitlines()]
            assert history == [{'kind': 'collector', 'args': ['validate-scan-options', *args]}], history
        return {'passed': True, 'scope': 'Synthetic helper argument forwarding and preflight only',
                'safeArgumentsPreserved': options, 'rejectedArgumentCases': len(invalid),
                'rejectedSemanticValueCases': len(invalid_values),
                'invalidArgumentsHaveNoOutputOrClientSideEffects': True,
                'invalidValuesInvokeOnlyPureValidation': True,
                'clientQueryTimeoutsUnchanged': True}


if __name__ == '__main__':
    print(json.dumps(exercise(), indent=2))
