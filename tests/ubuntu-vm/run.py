#!/usr/bin/env python3
"""Boot the authenticated Ubuntu 6.8.0-47 kernel with no NIC or virtual disk."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time

HERE=Path(__file__).resolve().parent
KERNEL='6.8.0-47-generic'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--work-dir',required=True,type=Path)
    p.add_argument('--timeout',type=int,default=1200)
    a=p.parse_args();work=a.work_dir.resolve();(work/'runs').mkdir(exist_ok=True)
    spec=importlib.util.spec_from_file_location('oracle_result_export',HERE.parent/'oracle-vm/run.py')
    shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)
    dest=Path(tempfile.mkdtemp(prefix='ubuntu-',dir=work/'runs'))
    cidfile=dest/'container.id';log=dest/'serial.log'
    qemu=['qemu-system-x86_64','-machine','pc','-accel','tcg,thread=single','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-serial','stdio','-no-reboot','-kernel','/work/vmlinuz-'+KERNEL,'-initrd','/work/ubuntu24041-initramfs.cpio.gz','-append','console=ttyS0,115200 rdinit=/init panic=-1 random.trust_cpu=on loglevel=3']
    command=['docker','run','--rm','--cidfile',str(cidfile),'--platform','linux/arm64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','6g','--cpus','4','--tmpfs','/tmp:rw,size=64m','--mount',f'type=bind,src={work},dst=/work,readonly','local/koda-sbom-oracle-vm:20261029',*qemu]
    (dest/'command.json').write_text(json.dumps(command,indent=2)+'\n')
    print(json.dumps({'event':'boot','kernel':KERNEL,'directory':str(dest)}),flush=True)
    start=time.monotonic()
    try:
        with log.open('wb') as output:r=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,timeout=a.timeout)
        assert r.returncode==0,f'QEMU exited {r.returncode}; inspect {log}'
    finally:
        if cidfile.exists():subprocess.run(['docker','rm','-f',cidfile.read_text().strip()],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    baseline=shared.extract(log,dest)
    assert baseline['unameRelease']==KERNEL and baseline['scanExitCode'] in (0,3),baseline
    report={'expectedKernel':KERNEL,'directory':str(dest),'seconds':round(time.monotonic()-start,3),'baseline':baseline,'qemuCommand':qemu}
    (dest/'boot-report.json').write_text(json.dumps(report,indent=2)+'\n')
    (work/'latest-boot.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'event':'completed','kernel':KERNEL,'scanExitCode':baseline['scanExitCode'],'moduleLoadState':baseline['moduleLoadState'],'seconds':report['seconds'],'directory':str(dest)}),flush=True)

if __name__=='__main__':main()
