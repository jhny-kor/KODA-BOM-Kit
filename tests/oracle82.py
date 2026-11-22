#!/usr/bin/env python3
"""Oracle 8.2 user-space/RPM test. This does not validate a native Oracle kernel."""
import argparse,json,subprocess,tempfile,time
from pathlib import Path
from validate_outputs import require_unoptimized, validate

require_unoptimized()
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--output',type=Path);a=p.parse_args()
output=(a.output or Path(tempfile.mkdtemp(prefix='koda-sbom-oracle82-'))).resolve();output.mkdir(parents=True,exist_ok=True)
image='oraclelinux:8.2';binary=a.binary.resolve()
assert subprocess.check_output(['docker','image','inspect','--platform','linux/amd64',image,'--format','{{.Architecture}}'],text=True).strip()=='amd64'
command=['docker','run','--rm','--platform','linux/amd64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--cpus','2','--memory','1536m','--tmpfs','/tmp:rw,nosuid,nodev,size=512m','--mount',f'type=bind,src={binary},dst=/koda-bom,readonly','--mount',f'type=bind,src={output},dst=/results',image,'/koda-bom','scan','--target','/','--no-context','--output-dir','/results']
before=set(output.glob('koda-sbom-*'));start=time.monotonic();proc=subprocess.run(command,capture_output=True,text=True,timeout=300)
assert proc.returncode in (0,3),(proc.returncode,proc.stdout,proc.stderr)
results=list(set(output.glob('koda-sbom-*'))-before);assert len(results)==1,results
result=results[0];checks=validate(result);collection=json.loads((result/'collection.json').read_text());distribution=collection.get('distribution') or {}
assert (distribution.get('id') or distribution.get('ID'))=='ol',distribution
assert str(distribution.get('versionID') or distribution.get('versionId') or distribution.get('VersionID') or distribution.get('version') or distribution.get('Version'))=='8.2',distribution
assert collection.get('packageTypes',{}).get('rpm',0)>20,collection.get('packageTypes')
context=json.loads((result/'context.json').read_text());assert not context.get('runningKernel')
report={'passed':True,'kind':'Oracle Linux 8.2 container userspace and RPM DB; not actual RHCK/UEK kernel','image':image,'imageIdentity':subprocess.check_output(['docker','image','inspect','--platform','linux/amd64',image,'--format','{{.Id}}'],text=True).strip(),'seconds':round(time.monotonic()-start,3),'exitCode':proc.returncode,'collectionStatus':collection['status'],'packageTypes':collection['packageTypes'],'distribution':distribution,'validation':checks,'resultDirectory':str(result)}
(output/'oracle82-verification.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n');print(json.dumps(report,ensure_ascii=False,indent=2))
