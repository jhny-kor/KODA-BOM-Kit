#!/usr/bin/env python3
"""Identity without fabricating a Git revision in an uncommitted project."""
import hashlib
import os
import subprocess
from pathlib import Path
root=Path(__file__).resolve().parents[1]
try:
 top=Path(subprocess.check_output(['git','-C',str(root),'rev-parse','--show-toplevel'],stderr=subprocess.DEVNULL,text=True).strip())
 if top==root:
  revision=subprocess.check_output(['git','-C',str(root),'rev-parse','--short=12','HEAD'],stderr=subprocess.DEVNULL,text=True).strip()
  dirty=bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain','--untracked-files=normal'],text=True).strip())
  if not dirty:
   print(revision);raise SystemExit
  prefix=revision+'-dirty-'
 else: prefix=''
except (OSError,subprocess.CalledProcessError):prefix=''
h=hashlib.sha256()
excluded = {'.git', 'dist', 'reports', '.omx', '.codex', '.ruff_cache', '__pycache__', '.DS_Store'}
files = []
for base, directories, names in os.walk(root):
 directories[:] = [name for name in directories if name not in excluded]
 files.extend(Path(base) / name for name in names if name not in excluded)
for p in sorted(files):
 if p.is_symlink() or not p.is_file():continue
 h.update(p.relative_to(root).as_posix().encode()+b'\0'); h.update(p.read_bytes());h.update(b'\0')
print(prefix+'src'+h.hexdigest()[:12])
