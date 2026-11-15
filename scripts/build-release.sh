#!/usr/bin/env bash
# Build-host dependencies: Go 1.26.11+, Python 3.
set -euo pipefail
umask 022
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root_dir"
go_bin="${GO_BIN:-go}"
release_version="${VERSION:-0.1.5}"
release_stamp="${BUILD_TIMESTAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
built_at="${BUILD_AT:-${release_stamp:0:4}-${release_stamp:4:2}-${release_stamp:6:2}T${release_stamp:9:2}:${release_stamp:11:2}:${release_stamp:13:2}Z}"
if ! [[ "$release_version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || ! [[ "$release_stamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
  echo "Invalid VERSION or BUILD_TIMESTAMP" >&2
  exit 2
fi
python3 - "$release_stamp" "$built_at" <<'PY'
from datetime import datetime
from sys import argv
stamp = datetime.strptime(argv[1], '%Y%m%dT%H%M%SZ')
built = datetime.strptime(argv[2], '%Y-%m-%dT%H:%M:%SZ')
if stamp != built:
    raise SystemExit('BUILD_AT and BUILD_TIMESTAMP must identify the same UTC instant')
PY
revision="$(python3 scripts/source-identity.py)"
release_id="${release_version}-${release_stamp}-${revision}"
stage="$root_dir/dist/koda-sbom-linux-amd64-$release_id"
mkdir -p "$root_dir/dist"
# Keep generated license directories containing @version outside root Go wildcards.
if ! test -f "$root_dir/dist/go.mod"; then
  printf 'module koda.local/build-artifacts\n\ngo 1.26.8\n' > "$root_dir/dist/go.mod"
fi
if test -e "$stage" || test -e "$stage.tar.gz" || test -e "$stage.tar.gz.sha256"; then
  echo "Refusing to overwrite release: $stage" >&2
  exit 2
fi
mkdir "$stage"
trap 'test -n "${build_ok:-}" || rm -rf -- "$stage" "$stage.tar.gz" "$stage.tar.gz.sha256"' EXIT
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOTOOLCHAIN=local
"$go_bin" build -trimpath -ldflags "-s -w -X main.version=$release_version -X main.revision=$revision -X main.builtAt=$built_at" -o "$stage/koda-sbom" ./cmd/koda-sbom
cp README.md LICENSE THIRD_PARTY_NOTICES.md "$stage/"
cp scripts/collect-livepatch-status.sh "$stage/collect-livepatch-status.sh"
chmod 0755 "$stage/collect-livepatch-status.sh"
cp scripts/scan-directory.sh "$stage/scan-directory.sh"
chmod 0755 "$stage/scan-directory.sh"
cp scripts/collect-aix-evidence.sh "$stage/collect-aix-evidence.sh"
chmod 0755 "$stage/collect-aix-evidence.sh"
mkdir "$stage/scripts"
cp scripts/compare-sbom-inventory.py scripts/verify-tracker-inventory.py "$stage/scripts/"
cp -R docs "$stage/docs"
python3 scripts/license-inventory.py --go "$go_bin" --output "$stage/licenses" --strict
python3 - "$stage" "$release_id" "$built_at" "$revision" "$go_bin" <<'PY'
import hashlib,json,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1])
build=json.loads(subprocess.check_output([sys.argv[5],"version","-m","-json",str(root/'koda-sbom')]))
syft,=(dep["Version"] for dep in build["Deps"] if dep["Path"]=="github.com/anchore/syft")
info={"release":sys.argv[2],"builtAt":sys.argv[3],"revision":sys.argv[4],"architecture":"linux/amd64","goamd64":"v1","cgo":False,"syftVersion":syft,"goVersion":build["GoVersion"]}
(root/'release.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n')
lines=[]
for file in sorted(root.rglob('*')):
 if file.is_file() and file.name!='SHA256SUMS':
  lines.append(hashlib.sha256(file.read_bytes()).hexdigest()+'  '+file.relative_to(root).as_posix())
(root/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
PY
if test "$(python3 scripts/source-identity.py)" != "$revision"; then
  echo "Source changed during build; release was not packaged. Rebuild after source freeze." >&2
  exit 2
fi
python3 - "$stage" "$built_at" <<'PYARCHIVE'
import datetime,sys,tarfile
from pathlib import Path
root=Path(sys.argv[1]);stamp=int(datetime.datetime.fromisoformat(sys.argv[2].replace('Z','+00:00')).timestamp())
def clean(info):
 info.uid=0;info.gid=0;info.uname='root';info.gname='root';info.mtime=stamp
 info.pax_headers={}
 info.mode=0o755 if info.isdir() or info.mode&0o111 else 0o644
 return info
with tarfile.open(str(root)+'.tar.gz','w:gz') as archive:
 archive.add(root,arcname=root.name,filter=clean)
PYARCHIVE
python3 - "$stage.tar.gz" <<'PY'
import hashlib,sys
from pathlib import Path
p=Path(sys.argv[1]); p.with_name(p.name+'.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
PY
build_ok=1
printf '%s\n' "$stage.tar.gz"
