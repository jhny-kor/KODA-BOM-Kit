#!/usr/bin/env python3
"""Boot actual Oracle x86_64 kernels under QEMU system TCG, no guest NIC/disk."""
import argparse,base64,gzip,hashlib,io,json,subprocess,tarfile,tempfile,time
from pathlib import Path

KERNELS={'rhck':'4.18.0-193.el8.x86_64','uek':'5.4.17-2011.1.2.el8uek.x86_64'}
def extract(log,dest):
    raw=log.read_bytes();begin=b'KODA_VM_RESULT_BEGIN\r\n';end=b'KODA_VM_RESULT_END'
    if begin not in raw:begin=b'KODA_VM_RESULT_BEGIN\n'
    assert begin in raw and end in raw,'VM did not export a completed result; inspect serial.log'
    encoded=raw.split(begin,1)[1].split(end,1)[0]
    packed=base64.b64decode(b''.join(encoded.split()),validate=True)
    (dest/'results.tar.gz').write_bytes(packed)
    with tarfile.open(fileobj=io.BytesIO(packed),mode='r:gz') as archive:
        size=0;count=0
        for entry in archive:
            p=Path(entry.name);size+=entry.size;count+=1
            assert entry.isfile() and not p.is_absolute() and '..' not in p.parts
            assert size<=256<<20 and count<=10000
            target=dest/'results'/p;target.parent.mkdir(parents=True,exist_ok=True)
            with archive.extractfile(entry) as src,target.open('xb') as out:
                while b:=src.read(1<<20):out.write(b)
    return json.loads((dest/'results/baseline.json').read_text())
def main():
    p=argparse.ArgumentParser();p.add_argument('--work-dir',required=True,type=Path)
    p.add_argument('--flavor',choices=['rhck','uek','both'],default='both');p.add_argument('--timeout',type=int,default=1200)
    a=p.parse_args();work=a.work_dir.resolve();(work/'runs').mkdir(exist_ok=True)
    reports=[]
    for flavor in (KERNELS if a.flavor=='both' else [a.flavor]):
        release=KERNELS[flavor];dest=Path(tempfile.mkdtemp(prefix=flavor+'-',dir=work/'runs'))
        cidfile=dest/'container.id';log=dest/'serial.log'
        qemu=['qemu-system-x86_64','-machine','pc','-accel','tcg,thread=single','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot','-kernel','/work/vmlinuz-'+release,'-initrd','/work/oracle82-initramfs.cpio.gz','-append','console=ttyS0,115200 rdinit=/init panic=-1 random.trust_cpu=on loglevel=3']
        command=['docker','run','--rm','--cidfile',str(cidfile),'--platform','linux/arm64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','6g','--cpus','4','--tmpfs','/tmp:rw,size=64m','--mount',f'type=bind,src={work},dst=/work,readonly','local/koda-sbom-oracle-vm:20261029',*qemu]
        (dest/'command.json').write_text(json.dumps(command,indent=2)+'\n')
        print(json.dumps({'event':'boot','flavor':flavor,'kernel':release,'directory':str(dest)}),flush=True)
        start=time.monotonic()
        try:
            with log.open('wb') as output:r=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,timeout=a.timeout)
            assert r.returncode==0,f'QEMU exited {r.returncode}; inspect {log}'
        finally:
            if cidfile.exists():subprocess.run(['docker','rm','-f',cidfile.read_text().strip()],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        baseline=extract(log,dest)
        assert baseline['unameRelease']==release,baseline
        assert baseline['scanExitCode'] in (0,3),baseline
        report={'flavor':flavor,'expectedKernel':release,'directory':str(dest),'seconds':round(time.monotonic()-start,3),'baseline':baseline,'qemuCommand':qemu}
        (dest/'boot-report.json').write_text(json.dumps(report,indent=2)+'\n');reports.append(report)
        print(json.dumps({'event':'completed','flavor':flavor,'kernel':baseline['unameRelease'],'scanExitCode':baseline['scanExitCode'],'moduleLoadState':baseline['moduleLoadState'],'seconds':report['seconds'],'directory':str(dest)}),flush=True)
    (work/'latest-boots.json').write_text(json.dumps(reports,indent=2)+'\n')
if __name__=='__main__':main()
