#!/usr/bin/env python3
"""Exercise default CLI BOM products in an isolated, offline Linux container."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from bomset_integration import checksum, edges, entities, read_document, verify_references, write_document
from domain_bom_integration import CANARY, create_fixtures, properties, verify_formulation
from validate_outputs import require, require_unoptimized, validate


PROFILES = {'sbom', 'hbom', 'cbom', 'obom', 'saasbom', 'aibom', 'mbom'}


def check_sources(merged, sources):
    combined = entities(merged)
    for source in sources:
        require(edges(source) <= edges(merged), 'source relationships lost in default merge')
        for ref, item in entities(source).items():
            require(ref in combined, ('source entity lost', ref))
            for key, value in item.items():
                if key == 'properties':
                    require(all(prop in combined[ref].get(key, []) for prop in value), 'source properties lost')
                else:
                    require(combined[ref].get(key) == value, ('source entity changed', ref, key))


def exercise(binary, platform, image):
    require_unoptimized()
    binary = Path(binary).resolve(strict=True)
    report = []
    with tempfile.TemporaryDirectory(prefix='koda-default-bom-qa-') as temporary:
        work = Path(temporary)

        def call(arguments, output, expected=(0, 3)):
            before = set(output.iterdir()) if output.exists() else set()
            translated = [str(arg).replace(str(work), '/work') for arg in arguments]
            command = ['docker', 'run', '--rm', '--platform', platform, '--pull', 'never',
                       '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges', '--cpus', '2', '--memory', '2g',
                       '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m',
                       '-v', str(binary) + ':/koda-bom:ro', '-v', str(work) + ':/work',
                       '--workdir', '/work', image, '/koda-bom', *translated]
            result = subprocess.run(command, capture_output=True, text=True, timeout=240)
            require(result.returncode in expected, (result.returncode, result.stdout, result.stderr))
            created = set(output.iterdir()) - before if output.exists() else set()
            require(len(created) == 1, ('expected one result directory', created, result.stdout, result.stderr))
            directory = created.pop()
            require(directory.is_dir(), 'result is not a directory')
            printed = result.stdout.strip().replace('/work', str(work))
            if not Path(printed).is_absolute():
                printed = str(work / printed)
            require(Path(printed).resolve() == directory.resolve(), ('CLI output path mismatch', printed, directory))
            validate(directory)
            return directory

        def check_products(directory, expected_profiles, dual=False):
            validate(directory / 'boms')
            manifest = read_document(directory / 'boms/bom-set.json')
            require({v['specVersion'] for v in manifest['versions']} == ({'1.6', '1.7'} if dual else {'1.6'}),
                    'unexpected manifest versions')
            require(not any(directory.rglob('mlbom.cdx*.json')), 'legacy AI-BOM filename emitted')
            for version in manifest['versions']:
                require({p['kind'] for p in version['profiles']} == expected_profiles, 'incorrect profile set')
                suffix = '.cdx-1.7.json' if version['specVersion'] == '1.7' else '.cdx.json'
                require(all(p['filename'] == p['kind'] + suffix for p in version['profiles']),
                        'manifest profile filenames differ from the exported BOMs')
            suffixes = ['.cdx.json', '.cdx-1.7.json'] if dual else ['.cdx.json']
            for suffix in suffixes:
                require((directory / ('bom' + suffix)).is_file(), 'default merged BOM missing')
                verify_references(read_document(directory / ('bom' + suffix)))
                for profile in expected_profiles:
                    path = directory / 'boms' / (profile + suffix)
                    require(path.is_file(), ('missing individual profile', profile, suffix))
                    verify_references(read_document(path))
            return suffixes

        def remerge(directory, suffixes):
            output = work / 'remerged'
            arguments = ['bom-merge', '--set', directory / 'boms', '--output-dir', output]
            if len(suffixes) == 2:
                arguments.append('--cyclonedx-17')
            merged = call(arguments, output, expected=(0,))
            for suffix in suffixes:
                name = 'bom' + suffix
                require(checksum(directory / name) == checksum(merged / name),
                        ('default merged output differs from later merge', name))

        # This invocation intentionally has no flags or subcommand. Its root is
        # the container filesystem; no host root or Docker socket is mounted.
        bare = call([], work / 'bom-output')
        suffixes = check_products(bare, PROFILES)
        require((bare / 'sbom.spdx.json').is_file(), 'default SPDX source missing')
        require((bare / 'sbom.cdx.json').is_file(), 'default CycloneDX source missing')
        require(not list(bare.rglob('*.cdx-1.7.json')), '1.7 must require explicit selection')
        require(read_document(bare / 'context.json')['mode'] == 'live-host', 'bare invocation did not scan live root')
        for profile in ('saasbom', 'aibom', 'mbom'):
            document = read_document(bare / 'boms' / (profile + '.cdx.json'))
            require(properties(document['metadata'])['koda:domain:status'] == 'no-evidence',
                    ('missing explicit no-evidence status', profile))
            require(not document.get('components') and not document.get('services') and not document.get('formulation'),
                    ('invented domain evidence', profile))
            require(any(row['aggregate'] == 'unknown' for row in document['compositions']), 'absence claimed complete')
        check_sources(read_document(bare / 'bom.cdx.json'),
                      [read_document(bare / name) for name in ('sbom.cdx.json', 'obom.cdx.json')])
        remerge(bare, suffixes)
        report.append({'case': 'bare live-root invocation, seven profiles, empty evidence and identical remerge'})

        fixture = work / 'fixture'
        fixture.mkdir()
        write_document(fixture / 'package.json', {'name': 'tiny-default-fixture', 'version': '1.2.3'})
        output = work / 'fixture-output'
        base = ['scan', '--target', fixture, '--no-context', '--output-dir', output]
        optout = call([*base, '--separate-boms=false'], output)
        require((optout / 'sbom.cdx.json').is_file() and (optout / 'sbom.spdx.json').is_file(), 'opt-out lost source formats')
        require(not (optout / 'boms').exists() and not (optout / 'bom.cdx.json').exists(), 'opt-out still emitted products')
        spdx = call([*base, '--format', 'spdx'], output)
        require((spdx / 'sbom.spdx.json').is_file(), 'SPDX-only output missing')
        require(not list(spdx.rglob('*.cdx*.json')) and not (spdx / 'boms').exists(), 'SPDX-only emitted CycloneDX')
        report.append({'case': 'explicit separate-BOM opt-out and SPDX-only compatibility'})

        evidence = work / 'evidence'
        evidence.mkdir()
        fixtures = create_fixtures(evidence)
        # Omit the scan subcommand as a regression for the public shorthand.
        enriched = call([*base[1:], '--cyclonedx-17',
                         '--saas-evidence', fixtures['services'], '--saas-evidence', fixtures['api'],
                         '--model-evidence', fixtures['model'], '--model-artifact', fixtures['weights'],
                         '--provenance', fixtures['provenance'], '--provenance-artifact', fixtures['artifact']], output)
        suffixes = check_products(enriched, PROFILES - {'obom'}, dual=True)
        for suffix in suffixes:
            for prefix in ('sbom', 'saasbom', 'aibom', 'mbom'):
                require((enriched / (prefix + suffix)).is_file(), 'original source document missing')
            saas = read_document(enriched / 'boms' / ('saasbom' + suffix))
            require({'frontend', 'backend', 'declared API'} <= {s['name'] for s in saas['services']}, 'service evidence lost')
            model_doc = read_document(enriched / 'boms' / ('aibom' + suffix))
            model = next(c for c in model_doc['components'] if c['name'] == 'fixture model')
            require(model['hashes'] == [{'alg': 'SHA-256', 'content': checksum(fixtures['weights'])}], 'model hash lost')
            require(model.get('modelCard'), 'model card lost')
            mbom = read_document(enriched / 'boms' / ('mbom' + suffix))
            merged = read_document(enriched / ('bom' + suffix))
            require(mbom.get('formulation') and mbom['formulation'] == merged.get('formulation'), 'manufacturing formulation lost')
            verify_formulation(merged)
            check_sources(merged, [read_document(enriched / ('sbom' + suffix))])
            combined = entities(merged)
            for prefix in ('saasbom', 'aibom', 'mbom'):
                source = read_document(enriched / (prefix + suffix))
                for ref, item in entities(source).items():
                    require(combined.get(ref) == item, ('domain source entity changed', prefix, ref))
            require(CANARY not in json.dumps(merged), 'private fixture data leaked')
        remerge(enriched, suffixes)
        report.append({'case': 'shorthand dual-version scan, retained sources, populated SaaS/AI/MBOM and formulation roundtrip'})
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--docker-platform', choices=('linux/arm64', 'linux/amd64'), default='linux/arm64')
    parser.add_argument('--image', default='alpine:3.21')
    arguments = parser.parse_args()
    print(json.dumps({'passed': True, 'binarySHA256': checksum(arguments.binary),
                      'cases': exercise(arguments.binary, arguments.docker_platform, arguments.image)}, indent=2))
