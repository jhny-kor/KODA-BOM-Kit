#!/usr/bin/env python3
"""Offline schema + identity + integrity verification on the build host."""
import argparse,hashlib,json,warnings
from pathlib import Path
import jsonschema

SCHEMAS=Path(__file__).resolve().parent/'schemas'

def require(condition, detail):
 if not condition:
  raise AssertionError(detail)

def require_unoptimized():
 if not __debug__:
  raise SystemExit('Run release QA without Python optimization (-O or PYTHONOPTIMIZE)')

def validate_cyclonedx_parity(legacy,companion):
 require(legacy['specVersion']=='1.6' and companion['specVersion']=='1.7', 'incorrect dual-output versions')
 def components(document):
  result={}
  def visit(items):
   for component in items:
    ref=component['bom-ref']
    require(ref not in result, ('duplicate component reference',ref))
    # Compare identity, remediation versions, evidence and asset properties.
    result[ref]={key:component.get(key) for key in ('type','name','group','version','purl','cpe','hashes','properties','evidence')}
    # A newer SPDX ID is retained as license.name by the 1.6 writer.
    # Its identity must still match the native license.id in 1.7.
    licenses=[]
    for choice in component.get('licenses',[]):
     choice=dict(choice)
     if 'license' in choice:
      license=dict(choice['license'])
      identity=license.pop('id',None)
      if identity is None:identity=license.pop('name',None)
      license['identity']=identity;choice['license']=license
     licenses.append(choice)
    result[ref]['licenses']=licenses
    visit(component.get('components',[]))
  visit(document.get('components',[]))
  return result
 require(components(legacy)==components(companion), 'CycloneDX component identity/evidence mismatch')
 def graph(document):
  return sorted((item['ref'],tuple(sorted(item.get('dependsOn',[]))),tuple(sorted(item.get('provides',[])))) for item in document.get('dependencies',[]))
 require(graph(legacy)==graph(companion), 'CycloneDX dependency graph mismatch')
 def coverage(document):
  return [p for p in document.get('metadata',{}).get('properties',[]) if p['name']=='koda:collection:coverage:v1']
 require(coverage(legacy)==coverage(companion), 'CycloneDX collection coverage mismatch')
 require(legacy.get('compositions')==companion.get('compositions'), 'CycloneDX completeness mismatch')

def validate(directory):
 directory=Path(directory)
 documents={}
 for filename,schemafile in [('sbom.cdx.json','bom-1.6.schema.json'),('sbom.cdx-1.7.json','cyclonedx-1.7/bom-1.7.schema.json'),('sbom.spdx.json','spdx-2.3.schema.json')]:
  path=directory/filename
  if not path.exists():continue
  schema_path=SCHEMAS/schemafile
  # SPDX and cryptography definitions are release-specific. Never resolve a
  # 1.6 license reference using the newer 1.7 SPDX enumeration.
  store={}
  for p in schema_path.parent.glob('*.json'):
   schema=json.loads(p.read_text());store[p.name]=schema
   if '$id' in schema:store[schema['$id']]=schema
   store['http://cyclonedx.org/schema/'+p.name]=schema
   store['https://cyclonedx.org/schema/'+p.name]=schema
  schema=json.loads(schema_path.read_text())
  # RefResolver is deliberately backed only by local schemas. HTTP handlers
  # fail rather than fetching missing references from the validation host.
  def offline(uri):raise ValueError('Schema reference not vendored: '+uri)
  with warnings.catch_warnings():
   warnings.simplefilter('ignore',DeprecationWarning)
   resolver=jsonschema.RefResolver.from_schema(schema,store=store,handlers={'http':offline,'https':offline})
  cls=jsonschema.validators.validator_for(schema)
  documents[filename]=json.loads(path.read_text())
  cls(schema,resolver=resolver).validate(documents[filename])
 if 'sbom.cdx-1.7.json' in documents:
  require('sbom.cdx.json' in documents, '1.7 companion requires 1.6 output')
  validate_cyclonedx_parity(documents['sbom.cdx.json'],documents['sbom.cdx-1.7.json'])
 lines=(directory/'SHA256SUMS').read_text().splitlines()
 names=set()
 for line in lines:
  expected,name=line.split('  ',1);path=directory/name
  if path.resolve().parent!=directory.resolve():raise AssertionError('unsafe checksum filename')
  require(name not in names, ('duplicate checksum',name))
  names.add(name)
  require(hashlib.sha256(path.read_bytes()).hexdigest()==expected, name)
 require(set(documents).issubset(names), ('missing output checksums',sorted(set(documents)-names)))
 if (directory/'sbom.cdx.json').exists() and (directory/'sbom.spdx.json').exists():
  cdx=json.loads((directory/'sbom.cdx.json').read_text());spdx=json.loads((directory/'sbom.spdx.json').read_text())
  c={p['purl'] for p in cdx.get('components',[]) if p.get('purl')}
  s={r['referenceLocator'] for p in spdx.get('packages',[]) for r in p.get('externalRefs',[]) if r.get('referenceType')=='purl'}
  # Namespaces (npm scopes/Maven groups) are represented differently in the
  # standards; compare the canonical identities instead of display names.
  require(c.issubset(s), ('format identity mismatch',sorted(c-s)))
 return {'schemas':'passed','checksums':len(lines)}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('directory');a=p.parse_args();print(json.dumps(validate(a.directory)))
