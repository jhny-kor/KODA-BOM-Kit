#!/usr/bin/env python3
"""Prove the directory launcher confines a real Linux SBOM to its chosen tree."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import zipfile

from fixtures import make_tree
from validate_outputs import require_unoptimized, validate


def exercise(stage):
    require_unoptimized()
    stage = stage.resolve(strict=True)
    binary = stage / 'koda-bom'
    helper = stage / 'scan-directory.sh'
    assert binary.is_file() and helper.is_file()
    reports = []
    with tempfile.TemporaryDirectory(prefix='koda-directory-qa-') as temporary:
        work = Path(temporary)
        work.chmod(0o777)
        target = make_tree(work / 'application with spaces')
        outside = work / 'outside'
        metadata = outside / 'lib/python3.11/site-packages/directory_sibling_canary-99.0.dist-info/METADATA'
        metadata.parent.mkdir(parents=True)
        metadata.write_text('Metadata-Version: 2.1\nName: directory-sibling-canary\nVersion: 99.0\n')
        (target / 'outside-link').symlink_to('/work/outside', target_is_directory=True)
        (work / 'root alias').symlink_to('/', target_is_directory=True)
        default_work = work / 'default run'
        default_work.mkdir(mode=0o777)
        default_work.chmod(0o777)

        def invoke(arguments, expected=(0, 3), cwd='/work'):
            command = [
                'docker', 'run', '--rm', '--platform', 'linux/amd64', '--network', 'none',
                '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--user', '65534:65534', '--cpus', '2', '--memory', '1536m',
                '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
                '--mount', f'type=bind,src={stage},dst=/release files,readonly',
                '--mount', f'type=bind,src={work},dst=/work',
                '--mount', f'type=bind,src={target},dst=/work/application with spaces,readonly',
                '--mount', f'type=bind,src={outside},dst=/work/outside,readonly',
                '--workdir', cwd, 'debian:bookworm-slim',
                '/release files/scan-directory.sh', *arguments,
            ]
            started = time.monotonic()
            process = subprocess.run(command, capture_output=True, text=True, timeout=180)
            assert process.returncode in expected, (process.returncode, process.stdout, process.stderr)
            return process, round(time.monotonic() - started, 3)

        def scan(arguments, output_parent, cwd='/work'):
            before = set(output_parent.iterdir()) if output_parent.exists() else set()
            process, elapsed = invoke(arguments, cwd=cwd)
            created = set(output_parent.iterdir()) - before
            assert len(created) == 1, (created, process.stdout, process.stderr)
            result = created.pop()
            schemas = validate(result)
            cdx = json.loads((result / 'sbom.cdx.json').read_text())
            names = {component['name'] for component in cdx['components']}
            assert {'fixture-python', 'fixture-node', 'openssl'}.issubset(names), sorted(names)
            for name in ('inventory.syft.json', 'sbom.cdx.json', 'sbom.spdx.json'):
                assert 'directory-sibling-canary' not in (result / name).read_text(), name
            context = json.loads((result / 'context.json').read_text())
            assert context['mode'] == context['status'] == 'disabled', context
            for field in ('runningKernel', 'kernelFlavor', 'loadedModules', 'processLinks', 'livepatch'):
                assert not context.get(field), (field, context)
            collection = json.loads((result / 'collection.json').read_text())
            assert collection['limits']['maxFiles'] == collection['limits']['timeoutSeconds'] == 0
            assert collection['filesystemFileCount'] > 0
            assert any(issue.get('path') == 'outside-link' and 'scope' in issue['message']
                       for issue in collection['issues']), collection['issues']
            reports.append({'exitCode': process.returncode, 'seconds': elapsed,
                            'schemas': schemas, 'packageCount': collection['packageCount'],
                            'limits': collection['limits'], 'context': 'disabled',
                            'outsideAndSymlinkCanaryAbsent': True})
            return result, collection

        scan(['/work/application with spaces', '/work/results with spaces',
              '--timeout', '0', '--max-files', '0'], work / 'results with spaces')
        scan(['../application with spaces', '--timeout=0', '--max-files=0'],
             default_work / 'sbom-output', cwd='/work/default run')

        # Each excluded tree contains identities observable by the normal scan.
        # The similar sibling would also be excluded if [old] were treated as a glob.
        for directory, name, version in [
            ('opt/retired/deeper', 'fixture-excluded-relative', '1.2.3'),
            ('opt/backup [old]/deeper', 'fixture-excluded-literal', '2.3.4'),
            ('opt/backup o/deeper', 'fixture-retained-sibling', '3.4.5'),
            ('opt/generated-cache/deeper', 'fixture-excluded-glob', '4.5.6'),
        ]:
            package = target / directory / 'package.json'
            package.parent.mkdir(parents=True)
            package.write_text(json.dumps({'name': name, 'version': version}))
        with zipfile.ZipFile(target / 'opt/retired/deeper/app.war', 'w') as archive:
            archive.writestr('assets/jquery.min.js', '/*! jQuery v3.1.1 | jquery.com */')
        (target / 'opt/backup [old]/deeper/jquery.min.js').write_text('/*! jQuery v2.2.4 | jquery.com */')
        (target / 'opt/backup o/deeper/jquery.min.js').write_text('/*! jQuery v3.7.1 | jquery.com */')
        (target / 'opt/retired alias [link]').symlink_to('retired', target_is_directory=True)
        retained = ('pkg:npm/fixture-retained-sibling@3.4.5', 'pkg:npm/jquery@3.7.1')
        removed = (
            'pkg:npm/fixture-excluded-relative@1.2.3',
            'pkg:npm/fixture-excluded-literal@2.3.4',
            'pkg:npm/fixture-excluded-glob@4.5.6',
            'pkg:npm/jquery@3.1.1', 'pkg:npm/jquery@2.2.4',
        )
        formats = ('inventory.syft.json', 'sbom.cdx.json', 'sbom.spdx.json')
        baseline, baseline_collection = scan([
            '/work/application with spaces', '/work/exclusion-baseline',
            '--timeout=0', '--max-files=0',
        ], work / 'exclusion-baseline')
        for filename in formats:
            raw = (baseline / filename).read_text()
            assert all(purl in raw for purl in retained + removed), filename
        filtered, filtered_collection = scan([
            '../application with spaces', '/work/exclusion-filtered',
            '--timeout=0', '--max-files=0', '--exclude-dir', './opt/retired/',
            '--exclude-dir=/work/application with spaces/opt/backup [old]',
            '--exclude', '**/generated-*',
        ], work / 'exclusion-filtered', cwd='/work/default run')
        for filename in formats:
            raw = (filtered / filename).read_text()
            assert all(purl in raw for purl in retained), filename
            assert all(purl not in raw for purl in removed), filename
            assert 'retired alias [link]' not in raw, filename
        assert set(filtered_collection['excludedDirectories']) == {'opt/retired', 'opt/backup [old]'}
        assert baseline_collection['filesystemFileCount'] - filtered_collection['filesystemFileCount'] == 5

        invalid_options = [
            ['--target', '/'], ['--target=/'], ['--image-archive', '/work/anything.tar'],
            ['--no-context=false'], ['--output-dir', '/work/override'],
            ['--livepatch-evidence', '/work/report.json'], ['--format', 'spdx'],
            ['--timeout', 'not-a-duration'], ['--max-files', '-1'],
            ['--max-files', '9223372036854775808'], ['--exclude', '['],
            ['--exclude-dir'], ['--exclude-dir='], ['--exclude-dir', '/work/outside'],
            ['--exclude-dir', '/work/application with spaces'], ['--exclude-dir', '.'],
            ['--exclude-dir', '../outside'], ['--exclude-dir', 'opt/missing'],
            ['--exclude-dir', 'opt/app/requirements.txt'], ['--exclude-dir', 'outside-link'],
            ['--exclude-dir', 'opt/retired alias [link]'],
        ]
        for index, options in enumerate(invalid_options):
            output = work / f'invalid-option-{index}'
            invoke(['/work/application with spaces', '/work/' + output.name, *options], (2,))
            assert not output.exists(), options
        invalid_targets = ['/', '/work/root alias', '/work/missing',
                           '/work/application with spaces/opt/app/requirements.txt']
        for index, invalid in enumerate(invalid_targets):
            output = work / f'invalid-target-{index}'
            invoke([invalid, '/work/' + output.name], (2,))
            assert not output.exists(), invalid
        (work / 'application [literal]' / 'cache').mkdir(parents=True)
        invoke(['/work/application [literal]', '/work/invalid-exclusion-root',
                '--exclude-dir', 'cache'], (2,))
        assert not (work / 'invalid-exclusion-root').exists()
    return {
        'passed': True,
        'scope': 'Real Linux amd64 binary and directory launcher; isolated synthetic directory inputs',
        'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'helperSHA256': hashlib.sha256(helper.read_bytes()).hexdigest(),
        'network': 'none', 'rootfs': 'read-only', 'user': '65534:65534',
        'scans': reports, 'invalidOptionCases': len(invalid_options),
        'invalidTargetCases': len(invalid_targets),
        'hostContextNotCollected': True,
        'literalDirectoryAndGlobExclusion': {'passed': True, 'excludedPURLs': list(removed)},
    }


if __name__ == '__main__':
    require_unoptimized()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, type=Path)
    arguments = parser.parse_args()
    print(json.dumps(exercise(arguments.stage), ensure_ascii=False, indent=2))
