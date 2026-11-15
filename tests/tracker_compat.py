#!/usr/bin/env python3
"""Build-host-only compatibility check; uses a fresh Tracker DB and no workers."""
import argparse, hashlib, json, os, secrets, sys, tempfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--tracker-root',type=Path,required=True);p.add_argument('--results',type=Path,required=True);a=p.parse_args()
with tempfile.TemporaryDirectory(prefix='koda-sbom-tracker-compat-') as temporary:
 root=Path(temporary);password=secrets.token_urlsafe(24)
 os.environ.update(TRACKER_ENVIRONMENT='test',TRACKER_DATABASE_URL='sqlite:///'+str(root/'isolated.sqlite'),TRACKER_ARTIFACT_DIR=str(root/'artifacts'),TRACKER_BOOTSTRAP_ADMIN_USERNAME='sbom-compat-admin',TRACKER_BOOTSTRAP_ADMIN_PASSWORD=password,TRACKER_SECURE_COOKIES='false',TRACKER_OFFLINE_MODE='true')
 sys.path.insert(0,str(a.tracker_root.resolve()/'apps/api'))
 from cryptography.fernet import Fernet
 os.environ['TRACKER_LDAP_ENCRYPTION_KEY']=Fernet.generate_key().decode()
 from fastapi.testclient import TestClient
 from koda_tracker.main import app
 from koda_tracker.sbom import parse_sbom
 result=[]
 with TestClient(app) as client:
  login=client.post('/api/v1/auth/login',json={'username':'sbom-compat-admin','password':password});assert login.status_code==200,login.text
  headers={'X-CSRF-Token':login.json()['csrfToken']}
  service=client.post('/api/v1/services',json={'slug':'native-fixture','name':'Native SBOM compatibility fixture'},headers=headers);assert service.status_code==201,service.text
  environment=client.get('/api/v1/environments').json()[0]['id']
  for name,media in [('sbom.cdx.json','application/vnd.cyclonedx+json'),('sbom.spdx.json','application/spdx+json')]:
   raw=(a.results/name).read_bytes();normalized,_=parse_sbom(raw)
   response=client.post('/api/v1/sbom-runs',data={'serviceId':service.json()['id'],'environmentId':environment,'releaseVersion':name},files={'sbom':(name,raw,media)},headers=headers)
   assert response.status_code==202,response.text
   run_id=response.json()['runId'];artifact=client.get(f'/api/v1/sbom-runs/{run_id}/artifact');assert artifact.content==raw
   components=client.get(f'/api/v1/sbom-runs/{run_id}/components').json();assert components['total']==len(normalized['components'])
   expected={c['name'] for c in normalized['components']};assert {'openssl','fixture-python','fixture-node'}<=expected
   purls={c['name']:c.get('purl') for c in normalized['components']};assert purls['openssl'].startswith('pkg:deb/')
   result.append({'file':name,'uploadStatus':response.status_code,'componentCount':components['total'],'artifactSHA256':hashlib.sha256(raw).hexdigest(),'osPackagePURL':purls['openssl'],'dependencyEntries':len(normalized.get('dependencies',[]))})
 print(json.dumps({'passed':True,'isolatedDatabase':True,'workersStarted':False,'uploads':result,'limitations':['No CVE analysis performed','Context and patch sidecars are not automatically consumed by current Tracker','Distro backport matching requires separate downstream validation']},indent=2))
