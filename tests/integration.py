#!/usr/bin/env python3
"""Black-box CLI regression suite; Python runs only on the build host."""
import argparse,hashlib,io,json,os,subprocess,tarfile,tempfile,time
from pathlib import Path
from fixtures import make_tree,make_oci
from validate_outputs import require, require_unoptimized, validate


def exercise(binary,runner=None):
 require_unoptimized()
 report=[]
 with tempfile.TemporaryDirectory(prefix='koda-sbom-qa-') as temp:
  work=Path(temp);work.chmod(0o755);fixture=make_tree(work/'fixture');output=work/'output';output.mkdir();output.chmod(0o777)
  def invoke(args,expected=(0,3)):
   command=[str(binary),*args] if runner is None else runner(work,args)
   start=time.monotonic();p=subprocess.run(command,capture_output=True,text=True,timeout=180)
   require(p.returncode in expected, (command,p.returncode,p.stdout,p.stderr))
   return p,time.monotonic()-start
  def scan(args,expected=(0,3)):
   before=set(output.iterdir());p,elapsed=invoke(args,expected)
   after=set(output.iterdir());created=[d for d in after-before if d.is_dir()]
   require(len(created)==1, (created,p.stdout,p.stderr))
   result=created[0];validation=validate(result)
   texts='\n'.join(f.read_text(errors='replace') for f in result.glob('*.json'))
   require('CANARY_NEVER_EXPORT_SECRET' not in texts, 'private fixture text was exported')
   report.append({'command':args,'exitCode':p.returncode,'seconds':round(elapsed,3),'validation':validation})
   return result
  path=lambda p:str(p) if runner is None else '/work/'+str(Path(p).relative_to(work))
  evidence=work/'assets-fixture.json'
  evidence.write_text(json.dumps({
   'schema':'koda-assets-1','observedAt':'2026-11-18T01:00:00Z',
   'assets':[
    {'id':'controller','kind':'device','name':'Fixture controller','model':'Model-A'},
    {'id':'controller-fw','parentId':'controller','kind':'firmware','name':'Fixture controller firmware','version':'1.2'},
   ],
  }))
  a=scan(['scan','--target',path(fixture),'--no-context','--asset-evidence',path(evidence),
          '--cyclonedx-17','--output-dir',path(output)])
  require((a/'sbom.cdx-1.7.json').is_file(), 'dual output did not produce CycloneDX 1.7')
  cdx=json.loads((a/'sbom.cdx.json').read_text());names={p['name'] for p in cdx['components']}
  for wanted in ('openssl','openssh-server','fixture-python','fixture-node'):
   require(wanted in names, (wanted,sorted(names)))
  require(any(x['type']=='device' and x['name']=='Fixture controller' for x in cdx['components']),
          'device evidence missing from the combined inventory')
  require(any(x['type']=='firmware' and x['version']=='1.2' and x['name']=='Fixture controller firmware'
              for x in cdx['components']), 'firmware version missing from the combined inventory')
  require('fixture-uninstalled-only' not in names, 'uninstalled Python component was collected')
  require('fixture-uninstalled-node' not in names, 'uninstalled Node component was collected')
  context=json.loads((a/'context.json').read_text())
  require(not context.get('runningKernel'), 'directory scan reported a running kernel')
  summary=json.loads((a/'collection.json').read_text())
  require(summary['limits']['maxFiles']==1000000 and summary['limits']['timeoutSeconds']==1800, summary['limits'])
  require(summary['filesystemFileCount']>0, summary)
  unlimited=scan(['scan','--target',path(fixture),'--timeout','0','--max-files','0','--no-context','--output-dir',path(output)])
  summary=json.loads((unlimited/'collection.json').read_text())
  require(summary['limits']['maxFiles']==0 and summary['limits']['timeoutSeconds']==0, summary['limits'])
  require(summary['filesystemFileCount']>0, summary)
  before=set(output.iterdir())
  failed,elapsed=invoke(['scan','--target',path(fixture),'--max-files','1','--no-context','--output-dir',path(output)],(2,))
  created=set(output.iterdir())-before
  require(len(created)==1, (created,failed.stdout,failed.stderr))
  failed_dir=created.pop();summary=json.loads((failed_dir/'collection.json').read_text())
  require(summary['status']=='failed' and summary['filesystemFileCount']==1, summary)
  limit_issues=[issue for issue in summary['issues'] if issue.get('code')=='file_limit_exceeded']
  require(len(limit_issues)==1 and limit_issues[0]['limit']==1 and limit_issues[0]['observed']==2, limit_issues)
  require('file_limit_exceeded' in failed.stderr and 'limit=1' in failed.stderr and 'observed=2' in failed.stderr, failed.stderr)
  require(not (failed_dir/'sbom.cdx.json').exists() and not (failed_dir/'sbom.spdx.json').exists(), 'failed preflight claimed a success SBOM')
  report.append({'fileLimit':1,'observed':2,'exitCode':failed.returncode,'seconds':round(elapsed,3),'passed':True})
  negative_options=[['--max-files','-1'],['--max-files=-1'],['--timeout','-1s'],['--timeout=-1s']]
  for options in negative_options:
   before=set(output.iterdir())
   invoke(['scan','--target',path(fixture),*options,'--no-context','--output-dir',path(output)],(2,))
   require(set(output.iterdir())==before, ('negative limit created output',options))
  b=scan(['scan','--target',path(fixture),'--format','spdx','--no-context','--output-dir',path(output)])
  require(not (b/'sbom.cdx.json').exists(), 'SPDX-only scan produced CycloneDX')
  require((a/'sbom.cdx.json').exists(), 'previous run overwritten')
  archive=make_oci(fixture,work/'image.tar')
  c=scan(['scan','--image-archive',path(archive),'--output-dir',path(output)])
  context=json.loads((c/'context.json').read_text())
  require(not context.get('runningKernel') and not context.get('processLinks'), 'image scan included live host context')
  invoke(['scan','--target',path(work/'missing'),'--output-dir',path(output)],(2,))
  invoke(['scan','--target',path(fixture),'--format','invalid','--output-dir',path(output)],(2,))
  invoke(['scan','--target',path(fixture),'--image-archive',path(archive),'--output-dir',path(output)],(2,))
  malicious=work/'path-escape.tar'
  with tarfile.open(malicious,'w') as tar:
   entry=tarfile.TarInfo('../CANARY_ESCAPE');entry.size=1;tar.addfile(entry,io.BytesIO(b'x'))
  invoke(['scan','--image-archive',path(malicious),'--output-dir',path(output)],(2,))
  require(not (work.parent/'CANARY_ESCAPE').exists(), 'archive wrote outside the working directory')
  # A denied metadata file must be disclosed, not silently turned into zero
  # packages. This runs as an unprivileged uid in Docker mode.
  blocked=fixture/'opt/blocked/private.dist-info/METADATA';blocked.parent.mkdir(parents=True);blocked.write_text('Name: restricted-fixture\nVersion: 1.0\n');blocked.chmod(0)
  try:
   partial=scan(['scan','--target',path(fixture),'--no-context','--output-dir',path(output)],(3,))
   summary=json.loads((partial/'collection.json').read_text())
   require(summary['status']=='partial' and summary.get('issues'), 'denied metadata was not reported as partial')
  finally:blocked.chmod(0o644)
  for timeout in ('1ns','10ms'):
   if timeout=='10ms':
    large=fixture/'opt/large';large.mkdir()
    for index in range(4000):(large/f'file-{index:05}.txt').write_text('fixture')
   before=set(output.iterdir());p,elapsed=invoke(['scan','--target',path(fixture),'--timeout',timeout,'--no-context','--output-dir',path(output)],(2,))
   require(elapsed<15, ('cancellation did not return promptly',elapsed))
   for result in set(output.iterdir())-before:
    if result.is_dir() and (result/'collection.json').exists():
     require(json.loads((result/'collection.json').read_text())['status']=='failed', 'timed out scan did not record failure')
   report.append({'timeout':timeout,'exitCode':p.returncode,'seconds':round(elapsed,3),'passed':True})
  report.append({'negativeCases':4+len(negative_options),'permissionCase':'partial','unlimitedScan':'passed','fileLimitDiagnostics':'passed','passed':True})
 return report

if __name__=='__main__':
 require_unoptimized()
 p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);a=p.parse_args()
 binary=a.binary.resolve()
 report={'passed':True,'binarySHA256':hashlib.sha256(binary.read_bytes()).hexdigest(),'results':exercise(binary)}
 print(json.dumps(report,indent=2))
