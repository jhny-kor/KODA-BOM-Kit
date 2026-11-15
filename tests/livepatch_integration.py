#!/usr/bin/env python3
"""Exercise the optional helper with synthetic clients, never vendor patches."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from validate_outputs import validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, type=Path)
    args = parser.parse_args()
    stage = args.stage.resolve()
    with tempfile.TemporaryDirectory(prefix='koda-livepatch-helper-qa-') as tmp:
        work = Path(tmp)
        work.chmod(0o755)
        mocks = work / 'mocks'
        mocks.mkdir()
        scripts = {
            'canonical-livepatch': '''#!/bin/sh
set -eu
kernel=$(uname -r)
checked=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '{"Last-Check":"%s","Token":"CANARY_NEVER_EXPORT_CLIENT_SECRET","Status":[{"Kernel":"%s","Running":true,"Livepatch":{"CheckState":"checked","State":"applied","Version":"1","Fixes":[{"Name":"CVE-2026-98432","Patched":true},{"Name":"CVE-2026-12345","Patched":false}]}}]}\\n' "$checked" "$kernel"
''',
            'ksplice': '''#!/bin/sh
printf 'Ksplice kernel updates:\\nInstalled updates:\\n[abc123] CVE-2026-98432: Synthetic fix.\\n[def456] Known exploit detection for CVE-2019-9213.\\n\\nAvailable updates:\\n[bad999] CVE-2026-99999: Not installed.\\n'
''',
            'uptrack-show': '''#!/bin/sh
printf 'Installed updates:\\n[up1234] CVE-2026-98432: Synthetic fix.\\n'
''',
            'uptrack-uname': '#!/bin/sh\nuname -r\n',
        }
        for name, content in scripts.items():
            path = mocks / name
            path.write_text(content.replace('#!/bin/sh\n', '#!/bin/sh\nprintf "client\\n" >> /qa/client-calls\n', 1))
            path.chmod(0o755)
        output = work / 'output'
        output.mkdir()
        rawtmp = work / 'rawtmp'
        rawtmp.mkdir()
        command = [
            'docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--cpus', '2', '--memory', '1536m', '--tmpfs', '/tmp:rw,size=512m',
            '--mount', f'type=bind,src={stage},dst=/release,readonly',
            '--mount', f'type=bind,src={work},dst=/qa',
            '--env', 'PATH=/qa/mocks:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            '--env', 'TMPDIR=/qa/rawtmp', 'debian:bookworm-slim',
            '/release/collect-livepatch-status.sh', '/qa/output',
            '--timeout', '0', '--max-files', '0', '--exclude', '/qa/**',
        ]
        invalid_values = [
            ['--timeout', 'not-a-duration'],
            ['--max-files', '9223372036854775808'],
            ['--exclude', '['],
        ]
        helper_prefix = command[:command.index('/release/collect-livepatch-status.sh')+1]
        for index, options in enumerate(invalid_values):
            bad_output = work / ('invalid-output-'+str(index))
            invalid = subprocess.run([*helper_prefix, '/qa/'+bad_output.name, *options],
                                     capture_output=True, text=True, timeout=30)
            assert invalid.returncode == 2, (options, invalid.returncode, invalid.stdout, invalid.stderr)
            assert not bad_output.exists(), ('invalid value created output/evidence', options)
            assert not (work / 'client-calls').exists(), ('invalid value executed a client', options)
            assert not list(rawtmp.iterdir()), 'invalid value created raw client files'
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        assert result.returncode in (0, 3), (result.returncode, result.stdout, result.stderr)
        directories = [p for p in output.iterdir() if p.name.startswith('koda-sbom-')]
        assert len(directories) == 1
        scan = directories[0]
        standard = validate(scan)
        context = json.loads((scan / 'context.json').read_text())
        collection = json.loads((scan / 'collection.json').read_text())
        limits = collection['limits']
        assert limits['timeoutSeconds'] == 0 and limits['maxFiles'] == 0, limits
        assert collection['filesystemFileCount'] >= 0, collection
        imported = {x['provider']: x for x in context['livepatch'] if x['evidenceKind'] == 'imported-client-status'}
        assert set(imported) == {'canonical-livepatch', 'ksplice', 'uptrack'}
        for provider, status in imported.items():
            assert status['status'] == 'observed', (provider, status)
            assert any(p['state'] == 'reported-applied' and 'CVE-2026-98432' in p.get('cves', []) for p in status['patches']), status
            assert not any('CVE-2026-99999' in p.get('cves', []) or 'CVE-2019-9213' in p.get('cves', []) for p in status['patches']), status
        all_json = '\n'.join(p.read_text() for p in output.rglob('*.json'))
        assert 'CANARY_NEVER_EXPORT_CLIENT_SECRET' not in all_json
        assert not list(rawtmp.iterdir()), 'Helper left raw client status files behind'
        print(json.dumps({
            'passed': True, 'scope': 'Synthetic installed clients and real Linux helper/collector execution; no genuine vendor patch applied',
            'binarySha256': hashlib.sha256((stage / 'koda-sbom').read_bytes()).hexdigest(),
            'providers': sorted(imported), 'scanExitCode': result.returncode,
            'schemas': standard, 'rawClientFilesRemoved': True, 'secretCanaryAbsent': True,
            'availableUpdatesAndExploitDetectionNotClassifiedAsCVEPatches': True,
            'collectionLimits': limits, 'filesystemFileCount': collection['filesystemFileCount'],
            'unlimitedScanOptionsForwarded': True,
            'semanticInvalidValueCasesHaveNoOutputOrClientSideEffects': len(invalid_values),
        }, indent=2))


if __name__ == '__main__':
    main()
