#!/usr/bin/env python3
"""Offline schema + identity + integrity verification on the build host."""
import argparse,hashlib,json,warnings
from pathlib import Path
import jsonschema

SCHEMAS=Path(__file__).resolve().parent/'schemas'

def validate(directory):
 directory=Path(directory)
 store={}
 for p in SCHEMAS.glob('*.json'):
  schema=json.loads(p.read_text());store[p.name]=schema
  if '$id' in schema:store[schema['$id']]=schema
  store['http://cyclonedx.org/schema/'+p.name]=schema
 for filename,schemafile in [('sbom.cdx.json','bom-1.6.schema.json'),('sbom.spdx.json','spdx-2.3.schema.json')]:
  path=directory/filename
  if not path.exists():continue
  schema=json.loads((SCHEMAS/schemafile).read_text())
  # RefResolver is deliberately backed only by local schemas. HTTP handlers
  # fail rather than fetching missing references from the validation host.
  def offline(uri):raise ValueError('Schema reference not vendored: '+uri)
  with warnings.catch_warnings():
   warnings.simplefilter('ignore',DeprecationWarning)
   resolver=jsonschema.RefResolver.from_schema(schema,store=store,handlers={'http':offline,'https':offline})
  cls=jsonschema.validators.validator_for(schema)
  cls(schema,resolver=resolver).validate(json.loads(path.read_text()))
 lines=(directory/'SHA256SUMS').read_text().splitlines()
 for line in lines:
  expected,name=line.split('  ',1);path=directory/name
  if path.resolve().parent!=directory.resolve():raise AssertionError('unsafe checksum filename')
  assert hashlib.sha256(path.read_bytes()).hexdigest()==expected,name
 if (directory/'sbom.cdx.json').exists() and (directory/'sbom.spdx.json').exists():
  cdx=json.loads((directory/'sbom.cdx.json').read_text());spdx=json.loads((directory/'sbom.spdx.json').read_text())
  c={p['purl'] for p in cdx.get('components',[]) if p.get('purl')}
  s={r['referenceLocator'] for p in spdx.get('packages',[]) for r in p.get('externalRefs',[]) if r.get('referenceType')=='purl'}
  # Namespaces (npm scopes/Maven groups) are represented differently in the
  # standards; compare the canonical identities instead of display names.
  assert c.issubset(s),('format identity mismatch',sorted(c-s))
 return {'schemas':'passed','checksums':len(lines)}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('directory');a=p.parse_args();print(json.dumps(validate(a.directory)))
