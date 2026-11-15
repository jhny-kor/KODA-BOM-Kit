"""Build-host fixture factory; no dependency managers or target runtimes execute."""
import hashlib,io,json,tarfile,zipfile
from pathlib import Path


def make_tree(root):
 root=Path(root);root.mkdir(parents=True,exist_ok=True)
 def put(name,text):
  p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);return p
 put('etc/os-release','ID=debian\nVERSION_ID="12"\nNAME="Debian GNU/Linux"\nVERSION="12 (bookworm)"\n')
 put('var/lib/dpkg/status','Package: openssl\nStatus: install ok installed\nPriority: optional\nSection: utils\nInstalled-Size: 1024\nMaintainer: Fixture Maintainer\nArchitecture: amd64\nSource: openssl\nVersion: 3.0.11-1~deb12u2\nDescription: OpenSSL fixture package\n\nPackage: openssh-server\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:9.2p1-2+deb12u7\nDescription: SSH fixture package\n\n')
 put('opt/app/venv/lib/python3.11/site-packages/fixture_python-2.4.1.dist-info/METADATA','Metadata-Version: 2.1\nName: fixture-python\nVersion: 2.4.1\nLicense: MIT\nAuthor: CANARY_NEVER_EXPORT_SECRET\nAuthor-email: CANARY_NEVER_EXPORT_SECRET@example.invalid\nRequires-Dist: fixture-dependency (>=1.0)\n')
 put('opt/app/venv/lib/python3.11/site-packages/fixture_python-2.4.1.dist-info/RECORD','fixture_python/__init__.py,,\n')
 put('opt/app/node_modules/fixture-node/package.json',json.dumps({'name':'fixture-node','version':'3.2.1','license':'MIT','author':'CANARY_NEVER_EXPORT_SECRET','homepage':'https://user:CANARY_NEVER_EXPORT_SECRET@example.invalid/project?secret=CANARY_NEVER_EXPORT_SECRET','dependencies':{'@fixture/child':'1.8.0'}}))
 put('opt/app/node_modules/@fixture/child/package.json',json.dumps({'name':'@fixture/child','version':'1.8.0','license':'Apache-2.0'}))
 put('opt/php/vendor/composer/installed.json',json.dumps({'packages':[{'name':'fixture/php-library','version':'v4.2.0','version_normalized':'4.2.0.0','type':'library','license':['MIT'],'install-path':'../fixture/php-library'}],'dev':False,'dev-package-names':[]}))
 put('opt/php/vendor/fixture/php-library/composer.json',json.dumps({'name':'fixture/php-library','version':'4.2.0','license':'MIT'}))
 put('opt/jdk/release','IMPLEMENTOR="Fixture OpenJDK"\nJAVA_VERSION="17.0.12"\nJAVA_RUNTIME_VERSION="17.0.12+7"\nOS_ARCH="x86_64"\n')
 jar=root/'opt/tomcat/lib/catalina.jar';jar.parent.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(jar,'w',zipfile.ZIP_DEFLATED) as z:
  z.writestr('META-INF/MANIFEST.MF','Manifest-Version: 1.0\nImplementation-Title: Apache Tomcat\nImplementation-Version: 10.1.30\nSpecification-Vendor: Apache Software Foundation\nX-Internal-Password: CANARY_NEVER_EXPORT_SECRET\n\n')
  z.writestr('org/apache/catalina/util/ServerInfo.properties','server.info=Apache Tomcat/10.1.30\nserver.number=10.1.30.0\nserver.built=fixture\n')
  z.writestr('META-INF/maven/org.apache.tomcat/tomcat-catalina/pom.properties','groupId=org.apache.tomcat\nartifactId=tomcat-catalina\nversion=10.1.30\n')
 put('opt/tomcat/conf/server.xml','<Server><Service><Connector protocol="AJP/1.3" port="8009" secret="CANARY_NEVER_EXPORT_SECRET"/><Connector port="8443"><UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol"/></Connector></Service></Server>')
 put('etc/nginx/nginx.conf','http { server { location /assets { alias /srv/public; rewrite ^/old /new; } } }\n# CANARY_NEVER_EXPORT_SECRET\n')
 put('etc/php/8.2/fpm/php.ini','session.upload_progress.enabled=1\nsession.serialize_handler=php_serialize\n; CANARY_NEVER_EXPORT_SECRET\n')
 put('etc/httpd/conf.modules.d/10-h2.conf','LoadModule http2_module modules/mod_http2.so\n# CANARY_NEVER_EXPORT_SECRET\n')
 put('opt/app/.env','PASSWORD=CANARY_NEVER_EXPORT_SECRET\n')
 put('opt/app/requirements.txt','fixture-uninstalled-only==99.99.99\n')
 put('opt/app/package-lock.json',json.dumps({'name':'declared-only','lockfileVersion':3,'packages':{'node_modules/fixture-uninstalled-node':{'version':'99.0.0'}}}))
 return root


def make_oci(root,archive):
 root=Path(root);archive=Path(archive)
 layer=io.BytesIO()
 with tarfile.open(fileobj=layer,mode='w') as tar:
  for p in sorted(root.rglob('*')):
   tar.add(p,arcname=p.relative_to(root).as_posix(),recursive=False)
 layer=layer.getvalue();digest=lambda b:hashlib.sha256(b).hexdigest()
 config=json.dumps({'architecture':'amd64','os':'linux','config':{},'rootfs':{'type':'layers','diff_ids':['sha256:'+digest(layer)]},'history':[{'created_by':'fixture only'}]}).encode()
 manifest=json.dumps({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':'sha256:'+digest(config),'size':len(config)},'layers':[{'mediaType':'application/vnd.oci.image.layer.v1.tar','digest':'sha256:'+digest(layer),'size':len(layer)}]}).encode()
 index=json.dumps({'schemaVersion':2,'manifests':[{'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':'sha256:'+digest(manifest),'size':len(manifest),'annotations':{'org.opencontainers.image.ref.name':'fixture:1'}}]}).encode()
 with tarfile.open(archive,'w') as tar:
  def add(name,data):
   entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o644;tar.addfile(entry,io.BytesIO(data))
  add('oci-layout',b'{"imageLayoutVersion":"1.0.0"}');add('index.json',index)
  for data in (layer,config,manifest):add('blobs/sha256/'+digest(data),data)
 return archive
