#!/usr/bin/env python3
"""Copy license texts for modules actually linked into the selected Go target.

No SPDX identifier is inferred from a module name. Missing texts are reported and
--strict prevents producing an apparently complete release.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
parser=argparse.ArgumentParser();parser.add_argument('--go',default='go');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--strict',action='store_true');args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
proc=subprocess.run([args.go,'list','-deps','-json','./cmd/koda-sbom'],cwd=root,env={**os.environ,'CGO_ENABLED':'0','GOOS':'linux','GOARCH':'amd64','GOAMD64':'v1','GOTOOLCHAIN':'local'},capture_output=True,text=True,check=True)
decoder=json.JSONDecoder();stream=proc.stdout;modules={}
while stream.strip():
 stream=stream.lstrip();obj,end=decoder.raw_decode(stream);stream=stream[end:];module=obj.get('Module')
 if module and not module.get('Main'):
  module=module.get('Replace',module);modules[(module['Path'],module.get('Version',''))]=module
args.output.mkdir(parents=True,exist_ok=False)
records=[];missing=[]
for (name,version),module in sorted(modules.items()):
 directory=Path(module.get('Dir','/nonexistent'));files=[]
 if directory.is_dir():
  files=[p for p in directory.iterdir() if p.is_file() and re.match(r'(?i)^(license|licence|copying|notice|copyright)([.\-_].*)?$',p.name)]
 # A nested Go module may inherit the repository-level license in its cached
 # parent. Include only ancestors inside GOMODCACHE, never arbitrary host files.
 if not any(re.match(r'(?i)^(license|licence|copying)',p.name) for p in files):
  cache=Path(subprocess.check_output([args.go,'env','GOMODCACHE'],text=True).strip())
  for parent in directory.parents:
   if parent==cache or cache not in parent.parents:break
   found=[p for p in parent.iterdir() if p.is_file() and re.match(r'(?i)^(license|licence|copying)([.\-_].*)?$',p.name)]
   if found:files+=found;break
 folder=args.output/(name.replace('/','_')+'@'+version)
 folder.mkdir();copied=[]
 for p in sorted(set(files)):
  dest=folder/p.name
  shutil.copyfile(p,dest);copied.append({'file':str(dest.relative_to(args.output)),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
 has_license=any(re.match(r'(?i)^(license|licence|copying)',Path(f['file']).name) for f in copied)
 if not has_license:missing.append(name+'@'+version)
 records.append({'module':name,'version':version,'status':'included' if has_license else 'missing','texts':copied})
goroot=Path(subprocess.check_output([args.go,'env','GOROOT'],text=True).strip())
if (goroot/'LICENSE').is_file():shutil.copyfile(goroot/'LICENSE',args.output/'GO-LICENSE')
(args.output/'inventory.json').write_text(json.dumps({'modules':records,'missing':missing},ensure_ascii=False,indent=2)+'\n')
print(f'License inventory: {len(records)} modules, {len(missing)} missing',file=sys.stderr)
for name in missing:print('Missing license: '+name,file=sys.stderr)
if args.strict and missing:raise SystemExit(2)
