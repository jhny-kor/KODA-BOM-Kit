#!/usr/bin/env python3
"""Compare an independently booted Ubuntu guest baseline with collector outputs."""
import argparse
import importlib.util
import json
from pathlib import Path
from urllib.parse import parse_qs

HERE=Path(__file__).resolve().parent
KERNEL='6.8.0-47-generic'
VERSION='6.8.0-47.47'
spec=importlib.util.spec_from_file_location('oracle_validation_shared',HERE.parent/'oracle-vm/validate.py')
shared=importlib.util.module_from_spec(spec);spec.loader.exec_module(shared)


def validate_vm(directory, *, binary=None, binary_sha256=None):
    if not __debug__:
        raise shared.VerificationError('Run without Python -O')
    root=Path(directory).resolve(strict=True)
    baseline=shared.load_json(root,'baseline.json')
    if binary is not None:
        actual=shared.digest_file(Path(binary))
        if binary_sha256 is not None and binary_sha256!=actual:
            raise shared.VerificationError('Requested binary and SHA disagree')
        binary_sha256=actual
    if binary_sha256 is not None and not shared.SHA256.fullmatch(binary_sha256):
        raise shared.VerificationError('Invalid binary SHA-256')
    checks=[]
    def check(name,passed,detail=None):
        result={'name':name,'passed':bool(passed)}
        if detail is not None:result['detail']=detail
        checks.append(result)
    check('ubuntu_baseline_schema',baseline.get('schema')=='koda-sbom-ubuntu-vm-baseline-v1')
    check('exact_actual_kernel',baseline.get('unameRelease')==KERNEL and baseline.get('procRelease')==KERNEL)
    check('amd64_guest',baseline.get('unameMachine')=='x86_64')
    distro=baseline.get('osRelease') or {}
    check('ubuntu_24041_userspace',distro.get('ID')=='ubuntu' and distro.get('VERSION_ID')=='24.04' and '24.04.1' in distro.get('PRETTY_NAME',''),distro)
    check('guest_completed',baseline.get('scanTimedOut') is False and not baseline.get('exportError') and baseline.get('issues')==[])
    code=baseline.get('scanExitCode')
    check('scan_completed_or_explicit_partial',code in (0,3),{'exitCode':code})
    check('guest_collector_sha_present',bool(shared.SHA256.fullmatch(baseline.get('binarySha256',''))))
    if binary_sha256 is not None:check('final_binary_digest',baseline.get('binarySha256')==binary_sha256)
    result_dirs=baseline.get('resultDirectories')
    if not isinstance(result_dirs,list) or len(result_dirs)!=1 or not shared.RESULT_NAME.fullmatch(result_dirs[0]):
        raise shared.VerificationError('Expected one exported scan directory')
    name=result_dirs[0]
    result=(root/name).resolve(strict=True);result.relative_to(root)
    check('single_scan',sorted(p.name for p in root.iterdir() if p.is_dir() and p.name.startswith('koda-sbom-'))==[name])
    for filename in shared.REQUIRED|{'SHA256SUMS'}:shared.confined(root,name+'/'+filename)
    try:
        validated=shared.standard_validator()(result)
        check('official_schemas_and_checksums',True,validated)
    except Exception as exc:check('official_schemas_and_checksums',False,str(exc)[:1000])
    context=shared.load_json(root,name+'/context.json')
    collection=shared.load_json(root,name+'/collection.json')
    inventory=shared.load_json(root,name+'/inventory.syft.json')
    cdx=shared.load_json(root,name+'/sbom.cdx.json');spdx=shared.load_json(root,name+'/sbom.spdx.json')
    check('live_context_actual_kernel',context.get('mode')=='live-host' and context.get('runningKernel')==KERNEL)
    check('context_completed_or_explicit_partial',context.get('status') in ('completed','partial'))
    check('exit_and_collection_status_consistent',(code==0 and collection.get('status')=='completed') or (code==3 and collection.get('status')=='partial'))
    distro=inventory.get('distro') or {}
    check('ubuntu_inventory',distro.get('id')=='ubuntu' and distro.get('versionID')=='24.04',distro)
    check('standard_versions',cdx.get('specVersion')=='1.6' and spdx.get('spdxVersion')=='SPDX-2.3')
    baseline_modules=baseline.get('loadedModulesAfter');observed=context.get('loadedModules')
    check('current_loaded_modules',isinstance(baseline_modules,list) and isinstance(observed,list) and set(baseline_modules)==set(observed))
    check('real_dummy_module_loaded',baseline.get('moduleLoadState') in ('loaded','already-loaded') and 'dummy' in (baseline_modules or []) and 'dummy' in (observed or []),{'state':baseline.get('moduleLoadState'),'error':baseline.get('moduleLoadError')})
    check('module_matches_running_kernel',baseline.get('modulePath')==f'/vm-test/modules/{KERNEL}/dummy.ko' and bool(shared.SHA256.fullmatch(baseline.get('moduleSha256',''))))
    artifacts=shared.as_objects(inventory.get('artifacts'))
    check('inventory_count',len(artifacts)>0 and collection.get('packageCount')==len(artifacts))
    cdx_purls,spdx_purls=shared.standard_purls(cdx,spdx)
    package_summary=[]
    for expected,source in [('linux-image-'+KERNEL,'linux-signed'),('linux-modules-'+KERNEL,'linux')]:
        packages=[p for p in artifacts if p.get('type')=='deb' and p.get('name')==expected and p.get('version')==VERSION]
        check('dpkg_exact_'+expected,bool(packages))
        valid=[]
        for package in packages:
            m=package.get('metadata') or {};purl=package.get('purl','');q=parse_qs(purl.partition('?')[2])
            if m.get('package')==expected and m.get('version')==VERSION and m.get('source')==source and m.get('architecture')=='amd64' and q.get('arch')==['amd64'] and q.get('distro')==['ubuntu-24.04'] and purl in cdx_purls and purl in spdx_purls:valid.append(package)
        check('dpkg_source_and_both_standard_purls_'+expected,bool(valid))
        if valid:package_summary.append({'name':expected,'version':VERSION,'source':source,'purl':valid[0]['purl'],'architecture':'amd64'})
    kernels=[p for p in artifacts if p.get('type')=='linux-kernel' and p.get('version')==KERNEL]
    modules=[p for p in artifacts if p.get('type')=='linux-kernel-module' and (p.get('metadata') or {}).get('kernelVersion')==KERNEL]
    check('installed_kernel_image',bool(kernels))
    check('installed_module_identity',bool(modules))
    check('module_vermagic',any((p.get('metadata') or {}).get('versionMagic','').split(' ',1)[0]==KERNEL for p in modules))
    return {'schema':'koda-sbom-ubuntu-vm-verification-v1','passed':all(c['passed'] for c in checks),'evidenceKind':'independent-guest-baseline-vs-live-host-collector','runningKernel':KERNEL,'osRelease':baseline.get('osRelease'),'collectorSHA256':baseline.get('binarySha256'),'requestedBinaryChecked':binary_sha256 is not None,'scanExitCode':code,'collectionStatus':collection.get('status'),'contextStatus':context.get('status'),'moduleLoadState':baseline.get('moduleLoadState'),'installedKernelDEBs':package_summary,'installedModuleCount':len(modules),'packageCount':len(artifacts),'checks':checks,'failedChecks':[c for c in checks if not c['passed']],'limitations':['Real Ubuntu kernel under QEMU system TCG on ARM64; physical-server performance and hardware not tested.','Authenticated Ubuntu Base 24.04.1 with original dpkg-unpacked kernel DEBs; full package configuration, GRUB, UEFI/Secure Boot and systemd boot not tested.','No real Canonical Livepatch/Ksplice update entitlement or vendor patch installation; software parsing and passive live-state observation require separate evidence.']}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);p.add_argument('--binary',type=Path);p.add_argument('--binary-sha256');p.add_argument('--report',type=Path)
    a=p.parse_args();report=validate_vm(a.directory,binary=a.binary,binary_sha256=a.binary_sha256)
    raw=json.dumps(report,indent=2)+'\n'
    if a.report:
        with a.report.open('x') as f:f.write(raw)
    print(raw);return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
