#!/usr/bin/env python3
"""Package a tested release, binding all VM and QA evidence to its exact binary."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, data):
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\n')


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', required=True, type=Path)
    parser.add_argument('--evidence-dir', required=True, type=Path)
    parser.add_argument('--oracle-work', required=True, type=Path)
    parser.add_argument('--ubuntu-work', required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    stage = args.stage.resolve(strict=True)
    assert stage.parent == repo / 'dist' and stage.is_dir() and not stage.is_symlink()
    evidence = args.evidence_dir.resolve(strict=True)
    evidence.relative_to(repo / 'dist' / 'evidence')
    release = read(stage / 'release.json')
    binary = stage / 'koda-sbom'
    binary_sha = digest(binary)
    identity = subprocess.check_output(['python3', str(repo / 'scripts/source-identity.py')], text=True).strip()
    assert identity == release['revision'], 'Source changed after release build'
    qa = read(evidence / 'candidate-verification.json')
    assert qa['passed'] and qa['binarySHA256'] == binary_sha
    for filename in ['binary-inspection.json', 'fixture-integration.json', 'go-verification.json', 'guest-syscall-verification.json', 'livepatch-integration.json', 'directory-integration.json']:
        item = read(evidence / filename)
        assert item['passed'], filename
        if 'binarySha256' in item:
            assert item['binarySha256'] == binary_sha, filename
        if 'sha256' in item:
            assert item['sha256'] == binary_sha, filename

    oracle = module('oracle_verify_release', repo / 'tests/oracle-vm/validate.py')
    ubuntu = module('ubuntu_verify_release', repo / 'tests/ubuntu-vm/validate.py')
    vm_reports = []
    provenance = {}
    for family, work, boots, validator in [
        ('oracle82', args.oracle_work.resolve(), read(args.oracle_work / 'latest-boots.json'), oracle.validate_vm),
        ('ubuntu24041', args.ubuntu_work.resolve(), [read(args.ubuntu_work / 'latest-boot.json')], ubuntu.validate_vm),
    ]:
        inputs = read(work / 'input-provenance.json')
        assert inputs['files']['koda-sbom']['sha256'] == binary_sha
        for filename, info in inputs['files'].items():
            assert digest(work / filename) == info['sha256'], filename
        provenance[family] = inputs
        assert len(boots) == (2 if family == 'oracle82' else 1)
        for boot in boots:
            directory = Path(boot['directory']).resolve(strict=True)
            directory.relative_to(work)
            kwargs = {'binary': binary}
            if family == 'oracle82':
                kwargs['expected_kernel'] = boot['expectedKernel']
            validation = validator(directory / 'results', **kwargs)
            assert validation['passed'], validation['failedChecks']
            assert validation['collectorSHA256'] == binary_sha
            write(directory / 'validation.json', validation)
            qemu = boot['qemuCommand']
            assert qemu[qemu.index('-nic') + 1] == 'none'
            assert qemu[qemu.index('-accel') + 1] == 'tcg,thread=single'
            baseline = read(directory / 'results/baseline.json')
            result = directory / 'results' / baseline['resultDirectories'][0]
            context = read(result / 'context.json')
            collection = read(result / 'collection.json')
            assert context.get('livepatch'), 'Final binary must collect passive livepatch sources'
            assert collection['limits']['maxFiles'] == 0 and collection['limits']['timeoutSeconds'] == 0
            assert collection['filesystemFileCount'] > 0
            copied = evidence / 'system-vms' / (family + '-' + boot['expectedKernel'])
            copied.mkdir(parents=True, exist_ok=False)
            for filename in ['command.json', 'boot-report.json', 'validation.json', 'serial.log', 'results.tar.gz']:
                shutil.copy2(directory / filename, copied / filename)
            shutil.copy2(directory / 'results/baseline.json', copied / 'baseline.json')
            vm_reports.append({
                'family': family, 'verification': validation,
                'qemuCommand': qemu, 'bootAndScanSeconds': boot['seconds'],
                'scanDurationSeconds': baseline['scanDurationSeconds'],
                'scanPeakRssKiB': baseline['scanPeakRssKiB'],
                'livepatchObservation': context['livepatch'],
                'collectionLimits': collection['limits'],
                'filesystemFileCount': collection['filesystemFileCount'],
                'explicitPartialCollectionIssues': collection['issues'],
                'evidenceSHA256': {p.name: digest(p) for p in copied.iterdir() if p.is_file()},
            })
    assert {v['verification']['runningKernel'] for v in vm_reports} == {
        '4.18.0-193.el8.x86_64', '5.4.17-2011.1.2.el8uek.x86_64', '6.8.0-47-generic'}
    report = {
        'schema': 'koda-sbom-verified-delivery-v2', 'passed': True,
        'verifiedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'release': release, 'binarySHA256': binary_sha, 'candidateBinaryQA': qa,
        'systemVMs': vm_reports, 'inputProvenance': provenance,
        'livepatchSoftwareVerification': read(evidence / 'livepatch-integration.json'),
        'directoryScanVerification': read(evidence / 'directory-integration.json'),
        'limits': [
            'Actual x86_64 guest kernels under QEMU system TCG on ARM64; physical company servers and hardware not tested.',
            'Custom initramfs boot; full systemd, GRUB, UEFI/Secure Boot, package configuration and SELinux enforcing not tested.',
            'Partial collection exit 3 and individual missing observations remain explicit; this is not complete host coverage.',
            'Real licensed Ksplice/Canonical client installation and genuine vendor kernel patch application were not performed.',
            'Vendor report parsers/helper are tested with synthetic clients; passive sysfs is observed in real VMs without vendor patches.',
            'Imported client state is not authenticated, an atomic snapshot or a CVE vulnerability/remediation verdict.',
            'Collector syscall verification excludes optional installed-client helper behavior and background daemons.',
            'Tracker context/patch import and automatic CVE analysis are outside this release verification.',
        ],
    }
    write(stage / 'VERIFICATION.json', report)
    (stage / '반입후실행.ko.txt').write_text(
        'KODA SBOM Linux ' + release['release'] + '\n\n'
        'sha256sum -c SHA256SUMS\n./koda-sbom doctor\n'
        '특정 디렉터리와 그 하위만 수집 (아래 경로를 실제 대상 폴더로 변경):\n'
        'sudo ./scan-directory.sh /opt/application /var/tmp/koda-sbom-results --max-files 0 --timeout 0\n\n'
        '호스트 전체를 수집:\n'
        'sudo ./koda-sbom scan --output-dir /var/tmp/koda-sbom-results\n\n'
        '파일 개수·수집 시간 제한을 해제하려면:\n'
        'sudo ./koda-sbom scan --max-files 0 --timeout 0 --output-dir /var/tmp/koda-sbom-results\n\n'
        'Ksplice·Livepatch 클라이언트 상세 상태와 함께 수집:\n'
        'sudo ./collect-livepatch-status.sh /var/tmp/koda-sbom-results --max-files 0 --timeout 0\n\n'
        '종료 코드 0=완전 수집, 3=부분 수집, 2=실패. 결과 폴더 전체를 보관합니다.\n'
        'Ubuntu 24.04.1 6.8.0-47 및 Oracle 8.2 RHCK/UEK 실제 커널 VM으로 최종 바이너리 검증.\n'
        '구독 클라이언트의 실제 패치 적용 시험과 CVE 판정은 수행하지 않았습니다.\n'
        '실행 파일 SHA-256: ' + binary_sha + '\n상세 사용법 README.md, docs/폐쇄망_실행_결과확인_안내.ko.txt, 검증 VERIFICATION.json\n')
    checks = {p.relative_to(stage).as_posix(): digest(p) for p in sorted(stage.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'}
    (stage / 'SHA256SUMS').write_text(''.join(f'{sha}  {name}\n' for name, sha in checks.items()))
    final = stage.with_name(stage.name + '-verified')
    archive = Path(str(final) + '.tar.gz')
    assert not final.exists() and not archive.exists()
    stamp = int(datetime.datetime.fromisoformat(release['builtAt'].replace('Z', '+00:00')).timestamp())
    def normalize(info):
        info.uid = info.gid = 0
        info.uname = info.gname = 'root'
        info.mtime = stamp
        info.pax_headers = {}
        info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
        return info
    with tarfile.open(archive, 'w:gz') as bundle:
        bundle.add(stage, arcname=final.name, filter=normalize)
    with tarfile.open(archive, 'r:gz') as bundle:
        for name, sha in checks.items():
            member = bundle.getmember(final.name + '/' + name)
            assert member.isfile() and member.uid == member.gid == 0
            with bundle.extractfile(member) as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == sha, name
    delivery = {'archive': archive.name, 'archiveSHA256': digest(archive), 'archiveBytes': archive.stat().st_size,
                'verifiedFileCount': len(checks), 'binarySHA256': binary_sha, 'verificationReportSHA256': checks['VERIFICATION.json']}
    Path(str(archive) + '.sha256').write_text(delivery['archiveSHA256'] + '  ' + archive.name + '\n')
    write(Path(str(archive) + '.verification.json'), dict(report, delivery=delivery))
    write(evidence / 'final-verification.json', dict(report, delivery=delivery))
    assert subprocess.check_output(['python3', str(repo / 'scripts/source-identity.py')], text=True).strip() == identity
    print(json.dumps(delivery, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
