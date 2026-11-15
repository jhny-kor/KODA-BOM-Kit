#!/usr/bin/env python3
"""Validate only a supplied Linux amd64 binary in an isolated target container."""
import argparse,json,subprocess
from pathlib import Path
from integration import exercise

p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);p.add_argument('--image',default='debian:bookworm-slim');p.add_argument('--pull',action='store_true');a=p.parse_args();binary=a.binary.resolve()
if a.pull:subprocess.run(['docker','pull','--platform','linux/amd64',a.image],check=True)
arch=subprocess.check_output(['docker','image','inspect','--platform','linux/amd64',a.image,'--format','{{.Architecture}}'],text=True).strip()
assert arch=='amd64',f'{a.image} is {arch}; use --pull to fetch linux/amd64 first'

def runner(work,args):
 return ['docker','run','--rm','--platform','linux/amd64','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','65534:65534','--cpus','2','--memory','1536m','--tmpfs','/tmp:rw,nosuid,nodev,size=512m',
  '--mount',f'type=bind,src={binary},dst=/koda-sbom,readonly',
  '--mount',f'type=bind,src={work},dst=/work',
  '--mount',f'type=bind,src={work/"fixture"},dst=/work/fixture,readonly',a.image,'/koda-sbom',*args]
print(json.dumps({'passed':True,'image':a.image,'architecture':arch,'network':'none','rootfs':'read-only','user':'65534:65534','results':exercise(binary,runner)},indent=2))
