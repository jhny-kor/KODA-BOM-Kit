#!/usr/bin/env python3
"""Inspect ELF headers without executing the supplied artifact."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('binary',type=Path);a=p.parse_args();data=a.binary.read_bytes()
assert data[:4]==b'\x7fELF','not ELF'
assert data[4]==2 and data[5]==1,'not ELF64 little endian'
assert struct.unpack_from('<H',data,18)[0]==62,'not x86_64'
phoff=struct.unpack_from('<Q',data,32)[0];entry_size=struct.unpack_from('<H',data,54)[0];entry_count=struct.unpack_from('<H',data,56)[0]
assert entry_size>=56 and phoff+entry_count*entry_size<=len(data),'invalid ELF program headers'
types=[struct.unpack_from('<I',data,phoff+i*entry_size)[0] for i in range(entry_count)]
assert 3 not in types,'PT_INTERP: target would require a dynamic loader'
assert 2 not in types,'PT_DYNAMIC: investigate shared library dependencies'
print(json.dumps({'passed':True,'name':a.binary.name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'format':'ELF64 Linux x86_64','PT_INTERP':False,'PT_DYNAMIC':False}))
