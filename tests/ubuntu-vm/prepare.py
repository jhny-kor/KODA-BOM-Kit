#!/usr/bin/env python3
"""Authenticate an Ubuntu 24.04.1 rootfs and historical kernel; prepare a test-only initramfs."""
import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
BASE_NAME = 'ubuntu-base-24.04.1-base-amd64.tar.gz'
BASE_URL = 'https://ftpmirror.your.org/pub/ubuntu/cdimage/ubuntu-base/releases/24.04/release/'
BASE_SHA = '5b0ffb1e31d4b85f5a2214f105d1377ba616c453b38ff46c278dc6472b21e2d8'
CD_KEY = '843938DF228D22F7B3742BC0D94AA3F0EFE21092'
SNAPSHOT = 'https://snapshot.ubuntu.com/ubuntu/20241018T000000Z/'
KERNEL = '6.8.0-47-generic'
VERSION = '6.8.0-47.47'
TOOL_IMAGE = 'local/koda-sbom-oracle-vm:20261029'


def run(args, **kw):
    return subprocess.run(args, check=True, **kw)


def digest(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def fetch(url, path):
    if not path.exists():
        part = path.with_suffix(path.suffix + '.part')
        with urlopen(url, timeout=120) as src, part.open('wb') as out:
            shutil.copyfileobj(src, out)
        part.replace(path)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work-dir', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--go', required=True)
    a = p.parse_args()
    work = a.work_dir.resolve(); work.mkdir(parents=True, exist_ok=True)
    inputs = work / 'inputs'; inputs.mkdir(exist_ok=True)
    gnupg = work / 'gnupg'; gnupg.mkdir(mode=0o700, exist_ok=True)
    urls = {
        'base.SHA256SUMS': BASE_URL + 'SHA256SUMS',
        'base.SHA256SUMS.gpg': BASE_URL + 'SHA256SUMS.gpg',
        'cdimage-key.asc': 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x' + CD_KEY,
        BASE_NAME: BASE_URL + BASE_NAME,
        'InRelease': SNAPSHOT + 'dists/noble-updates/InRelease',
        'Packages.xz': SNAPSHOT + 'dists/noble-updates/main/binary-amd64/Packages.xz',
    }
    for name, url in urls.items():
        fetch(url, inputs / name)
    key_info = run(['gpg', '--homedir', str(gnupg), '--batch', '--with-colons', '--import-options', 'show-only', '--import', str(inputs/'cdimage-key.asc')], capture_output=True, text=True)
    fingerprints = [line.split(':')[9] for line in key_info.stdout.splitlines() if line.startswith('fpr:')]
    assert fingerprints == [CD_KEY], fingerprints
    run(['gpg', '--batch', '--yes', '--dearmor', '--output', str(inputs/'cdimage-key.gpg'), str(inputs/'cdimage-key.asc')])
    signature = run(['gpgv', '--homedir', str(gnupg), '--keyring', str(inputs/'cdimage-key.gpg'), str(inputs/'base.SHA256SUMS.gpg'), str(inputs/'base.SHA256SUMS')], capture_output=True)
    (work/'base-signature.log').write_bytes(signature.stdout + signature.stderr)
    checksum = next(line.split()[0] for line in (inputs/'base.SHA256SUMS').read_text().splitlines() if line.split()[-1].lstrip('*') == BASE_NAME)
    assert checksum == BASE_SHA == digest(inputs/BASE_NAME)
    # The archive keyring is itself authenticated by the CD-image signature above.
    with tarfile.open(inputs/BASE_NAME) as tf:
        key = next(m for m in tf if m.name.lstrip('./') == 'usr/share/keyrings/ubuntu-archive-keyring.gpg')
        (inputs/'ubuntu-archive-keyring.gpg').write_bytes(tf.extractfile(key).read())
    release = run(['gpgv', '--homedir', str(gnupg), '--keyring', str(inputs/'ubuntu-archive-keyring.gpg'), '--output', '-', str(inputs/'InRelease')], capture_output=True)
    (inputs/'Release').write_bytes(release.stdout)
    (work/'snapshot-signature.log').write_bytes(release.stderr)
    expected = [line.split() for line in release.stdout.decode().splitlines() if line.strip().endswith('main/binary-amd64/Packages.xz') and len(line.split()[0]) == 64]
    assert len(expected) == 1
    assert digest(inputs/'Packages.xz') == expected[0][0] and (inputs/'Packages.xz').stat().st_size == int(expected[0][1])
    packages = []
    for stanza in lzma.decompress((inputs/'Packages.xz').read_bytes()).decode().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in stanza.splitlines() if line and not line.startswith(' ') and ': ' in line)
        if fields.get('Package') in ['linux-image-'+KERNEL, 'linux-modules-'+KERNEL]:
            assert fields['Version'] == VERSION and fields['Architecture'] == 'amd64'
            dest = inputs / Path(fields['Filename']).name
            url = SNAPSHOT + fields['Filename']; urls[dest.name] = url
            fetch(url, dest)
            assert dest.stat().st_size == int(fields['Size']) and digest(dest) == fields['SHA256']
            packages.append(fields)
    assert len(packages) == 2
    (inputs/'kernel-package-records.json').write_text(json.dumps(packages, indent=2)+'\n')
    root_tar = work/'ubuntu24041-rootfs.tar'
    image = 'local/koda-sbom-ubuntu-base:24.04.1-authenticated'
    if root_tar.exists() and (work/'input-provenance.json').exists():
        previous = json.loads((work/'input-provenance.json').read_text())
        assert previous.get('files', {}).get(root_tar.name, {}).get('sha256') == digest(root_tar), 'Cached Ubuntu rootfs changed since authenticated preparation'
    if not root_tar.exists():
        run(['docker', 'import', '--platform', 'linux/amd64', str(inputs/BASE_NAME), image], stdout=subprocess.DEVNULL)
        # Real dpkg unpack updates its database, with original package scripts and
        # metadata. This is intentionally not a configured full Ubuntu installation.
        command = "dpkg --force-depends --unpack /inputs/*.deb && dpkg-query -W -f='${Package} ${Version} ${Architecture} ${Status}\\n' linux-image-6.8.0-47-generic linux-modules-6.8.0-47-generic"
        cid = subprocess.check_output(['docker','create','--platform','linux/amd64','--network','none','--mount',f'type=bind,src={inputs},dst=/inputs,readonly',image,'/bin/sh','-ec',command], text=True).strip()
        try:
            result = run(['docker','start','-a',cid], capture_output=True)
            (work/'dpkg-unpack.log').write_bytes(result.stdout+result.stderr)
            state = json.loads(subprocess.check_output(['docker','inspect',cid], text=True))[0]['State']
            assert state['ExitCode'] == 0, (state, result.stdout, result.stderr)
            run(['docker','export','--output',str(root_tar),cid])
        finally:
            run(['docker','rm',cid], stdout=subprocess.DEVNULL)
    with tarfile.open(root_tar) as tf:
        status = next(m for m in tf if m.name.lstrip('./') == 'var/lib/dpkg/status')
        kernel_db = []
        for stanza in tf.extractfile(status).read().decode().split('\n\n'):
            fields = dict(line.split(': ', 1) for line in stanza.splitlines() if line and not line.startswith(' ') and ': ' in line)
            if fields.get('Package') in ['linux-image-'+KERNEL, 'linux-modules-'+KERNEL]:
                assert fields.get('Version') == VERSION and fields.get('Status') == 'install ok unpacked', fields
                kernel_db.append({k: fields[k] for k in ['Package','Version','Architecture','Source','Status']})
        assert len(kernel_db) == 2
    (work/'rootfs-kernel-dpkg-baseline.json').write_text(json.dumps(kernel_db, indent=2)+'\n')
    shutil.copy2(a.binary.resolve(), work/'koda-sbom')
    env = dict(os.environ, CGO_ENABLED='0', GOOS='linux', GOARCH='amd64', GOAMD64='v1', GOTOOLCHAIN='local')
    run([a.go,'build','-trimpath','-ldflags','-s -w','-o',str(work/'init'),str(HERE/'init.go')], env=env)
    assembly = r'''set -euo pipefail
mkdir -p /tmp/rootfs
tar --no-same-owner --delay-directory-restore --exclude='dev/*' --exclude='proc/*' --exclude='sys/*' -xf /work/ubuntu24041-rootfs.tar -C /tmp/rootfs
cp /work/init /tmp/rootfs/init
cp /work/koda-sbom /tmp/rootfs/koda-sbom
mkdir -p /tmp/rootfs/proc /tmp/rootfs/sys /tmp/rootfs/dev /tmp/rootfs/tmp /tmp/rootfs/results /tmp/rootfs/vm-test/modules/6.8.0-47-generic
cp /tmp/rootfs/boot/vmlinuz-6.8.0-47-generic /work/vmlinuz-6.8.0-47-generic
python3 - <<'PYMODULE'
from pathlib import Path
import ctypes,ctypes.util,lzma
paths=list(Path('/tmp/rootfs/usr/lib/modules/6.8.0-47-generic').rglob('dummy.ko*'))
assert len(paths)==1,paths
p=paths[0];data=p.read_bytes()
if p.suffix=='.zst':
 lib=ctypes.CDLL(ctypes.util.find_library('zstd'))
 lib.ZSTD_getFrameContentSize.argtypes=[ctypes.c_void_p,ctypes.c_size_t];lib.ZSTD_getFrameContentSize.restype=ctypes.c_ulonglong
 size=lib.ZSTD_getFrameContentSize(data,len(data));assert size<16<<20,size
 out=ctypes.create_string_buffer(size);lib.ZSTD_decompress.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t];lib.ZSTD_decompress.restype=ctypes.c_size_t
 result=lib.ZSTD_decompress(out,size,data,len(data));assert result==size,(result,size);data=out.raw
elif p.suffix=='.xz':data=lzma.decompress(data)
Path('/tmp/rootfs/vm-test/modules/6.8.0-47-generic/dummy.ko').write_bytes(data)
PYMODULE
cd /tmp/rootfs
find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --owner=0:0 2>/work/cpio.log | gzip -1 > /work/ubuntu24041-initramfs.cpio.gz
'''
    run(['docker','run','--rm','--platform','linux/arm64','--network','none','--read-only','--cap-drop','ALL','--cap-add','DAC_OVERRIDE','--cap-add','FOWNER','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,size=2g','--mount',f'type=bind,src={work},dst=/work',TOOL_IMAGE,'/bin/bash','-ec',assembly])
    provenance = {'schema':'koda-sbom-ubuntu-vm-inputs-v1','os':'Ubuntu Base 24.04.1 amd64','kernelRelease':KERNEL,'rootfsSource':BASE_URL+BASE_NAME,'rootfsMirrorSignatureFingerprint':CD_KEY,'kernelSnapshot':SNAPSHOT,'packageRecords':packages,'urls':urls,'files':{},'imageIDs':{},'limitations':['Ubuntu Base plus dpkg-unpacked authentic kernel packages; not a configured full server installation.','Direct custom-initramfs boot; GRUB, UEFI, Secure Boot, systemd and physical-server integration not tested.','No installed proprietary Ksplice or Canonical Livepatch service or livepatch entitlement; no real vendor patch is installed by this harness.']}
    for file in [inputs/BASE_NAME,inputs/'InRelease',inputs/'Packages.xz',inputs/'ubuntu-archive-keyring.gpg',root_tar,work/'koda-sbom',work/'init',work/('vmlinuz-'+KERNEL),work/'ubuntu24041-initramfs.cpio.gz']:
        provenance['files'][str(file.relative_to(work))]={'sha256':digest(file),'bytes':file.stat().st_size}
    for name in [TOOL_IMAGE,image]:
        provenance['imageIDs'][name]=subprocess.check_output(['docker','image','inspect','--format','{{.Id}}',name],text=True).strip()
    (work/'input-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    print(json.dumps({'workDirectory':str(work),'kernel':KERNEL,'binarySHA256':digest(work/'koda-sbom'),'initramfsBytes':(work/'ubuntu24041-initramfs.cpio.gz').stat().st_size}))

if __name__ == '__main__':
    main()
