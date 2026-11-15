#!/usr/bin/env python3
"""Prepare a disposable, signed-Oracle-RPM initramfs for real x86 kernel boot tests.
Requires Docker, build-host Python and Go. Never touches KODA/Tracker services/data.
"""
import argparse, base64, hashlib, json, os, shutil, subprocess
from pathlib import Path
from urllib.request import urlopen

def run(args, **kw):
    return subprocess.run(args, check=True, **kw)

def key_fingerprint(armored):
    body=base64.b64decode(''.join(line for line in armored.splitlines() if line and not line.startswith(('-', '=')) and ':' not in line),validate=True)
    offset=0
    while offset<len(body):
        head=body[offset];offset+=1
        assert head&128,'Invalid OpenPGP packet'
        if head&64:
            tag=head&63;n=body[offset];offset+=1
            if n<192:length=n
            elif n<224:length=((n-192)<<8)+body[offset]+192;offset+=1
            elif n==255:length=int.from_bytes(body[offset:offset+4],'big');offset+=4
            else:raise ValueError('Partial OpenPGP packets not accepted')
        else:
            tag=(head>>2)&15;kind=head&3
            assert kind!=3,'Indeterminate packet not accepted'
            count=(1,2,4)[kind];length=int.from_bytes(body[offset:offset+count],'big');offset+=count
        packet=body[offset:offset+length];offset+=length
        assert len(packet)==length,'Truncated OpenPGP packet'
        if tag==6:
            assert packet[0]==4 and length<65536,'Expected OpenPGP v4 key'
            return hashlib.sha1(b'\x99'+length.to_bytes(2,'big')+packet).hexdigest().upper()
    raise ValueError('No primary public key')

def main():
    p=argparse.ArgumentParser();p.add_argument('--work-dir',type=Path,required=True)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--go',required=True)
    a=p.parse_args();base=Path(__file__).resolve().parent
    work=a.work_dir.resolve();work.mkdir(parents=True,exist_ok=True)
    rpms=work/'rpms';rpms.mkdir(exist_ok=True)
    manifest=json.loads((base/'kernels.json').read_text())
    for pkg in manifest['packages']:
        dest=rpms/pkg['url'].rsplit('/',1)[-1]
        if not dest.exists():
            with urlopen(pkg['url'],timeout=120) as src,dest.with_suffix('.part').open('wb') as f:shutil.copyfileobj(src,f)
            dest.with_suffix('.part').replace(dest)
        assert dest.stat().st_size==pkg['sizeBytes'],dest
        assert hashlib.sha256(dest.read_bytes()).hexdigest()==pkg['sha256'],dest
    key=rpms/'RPM-GPG-KEY-oracle-ol8'
    if not key.exists():
        with urlopen(manifest['signingKey']['url'],timeout=30) as src:key.write_bytes(src.read())
    assert key_fingerprint(key.read_text())==manifest['signingKey']['fingerprint'],'Oracle key fingerprint mismatch'
    root_tar=work/'oracle82-rootfs.tar'
    if not root_tar.exists():
        cmd='rpm --import /rpms/RPM-GPG-KEY-oracle-ol8 && rpm -Kv /rpms/*.rpm && rpm -ivh --nodeps --noscripts --notriggers /rpms/*.rpm && rpm -qa --qf "%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\\n"'
        cid=subprocess.check_output(['docker','create','--platform','linux/amd64','--network','none','--mount',f'type=bind,src={rpms},dst=/rpms,readonly','oraclelinux:8.2','/bin/bash','-ec',cmd],text=True).strip()
        try:
            r=run(['docker','start','-a',cid],capture_output=True,text=True)
            state=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]['State']
            (work/'rpm-signature-install.log').write_text(r.stdout+r.stderr)
            assert state['ExitCode']==0,(state,r.stdout,r.stderr)
            assert r.stdout.count('V3 RSA/SHA256 Signature, key ID ad986da3: OK')==8,r.stdout
            run(['docker','export','--output',str(root_tar),cid])
        finally:run(['docker','rm',cid],stdout=subprocess.DEVNULL)
    shutil.copy2(a.binary.resolve(),work/'koda-sbom')
    env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='amd64',GOAMD64='v1',GOTOOLCHAIN='local')
    run([a.go,'build','-trimpath','-ldflags','-s -w','-o',str(work/'init'),str(base/'init.go')],env=env)
    script='''set -euo pipefail
mkdir -p /tmp/rootfs
tar --no-same-owner --delay-directory-restore --exclude='dev/*' --exclude='proc/*' --exclude='sys/*' -xf /work/oracle82-rootfs.tar -C /tmp/rootfs
cp /work/init /tmp/rootfs/init
cp /work/koda-sbom /tmp/rootfs/koda-sbom
mkdir -p /tmp/rootfs/proc /tmp/rootfs/sys /tmp/rootfs/dev /tmp/rootfs/tmp /tmp/rootfs/results /tmp/rootfs/vm-test/modules
for release in 4.18.0-193.el8.x86_64 5.4.17-2011.1.2.el8uek.x86_64; do
 mkdir -p "/tmp/rootfs/vm-test/modules/$release"
 loop="$(find "/tmp/rootfs/usr/lib/modules/$release" -name loop.ko.xz -print -quit)"
 if test -n "$loop"; then xz -dc "$loop" > "/tmp/rootfs/vm-test/modules/$release/loop.ko"; fi
 image="/tmp/rootfs/boot/vmlinuz-$release"
 if ! test -f "$image"; then image="/tmp/rootfs/usr/lib/modules/$release/vmlinuz"; fi
 cp "$image" "/work/vmlinuz-$release"
done
cd /tmp/rootfs
find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --owner=0:0 2>/work/cpio.log | gzip -1 > /work/oracle82-initramfs.cpio.gz
'''
    run(['docker','run','--rm','--platform','linux/arm64','--network','none','--read-only','--cap-drop','ALL','--cap-add','DAC_OVERRIDE','--cap-add','FOWNER','--security-opt','no-new-privileges','--tmpfs','/tmp:rw,size=2g','--mount',f'type=bind,src={work},dst=/work','local/koda-sbom-oracle-vm:20261029','/bin/bash','-ec',script])
    provenance={'schema':'koda-sbom-oracle-vm-inputs-v1','kernelRPMs':manifest['packages'],'oracleKeyFingerprint':key_fingerprint(key.read_text()),'files':{},'imageIDs':{}}
    for name in ['oracle82-rootfs.tar','oracle82-initramfs.cpio.gz','init','koda-sbom','vmlinuz-4.18.0-193.el8.x86_64','vmlinuz-5.4.17-2011.1.2.el8uek.x86_64','rpm-signature-install.log']:
        f=work/name
        with f.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
        provenance['files'][name]={'bytes':f.stat().st_size,'sha256':digest}
    for image in ['oraclelinux:8.2','local/koda-sbom-oracle-vm:20261029']:
        provenance['imageIDs'][image]=subprocess.check_output(['docker','image','inspect',image,'--format','{{.Id}}'],text=True).strip()
    (work/'input-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
    print(json.dumps({'workDirectory':str(work),'initramfs':str(work/'oracle82-initramfs.cpio.gz'),'binarySHA256':hashlib.sha256((work/'koda-sbom').read_bytes()).hexdigest()},indent=2))
if __name__=='__main__':main()
