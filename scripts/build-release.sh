#!/bin/bash -p
# Build-host dependencies: Go 1.26.11+, Python 3.
set -euo pipefail
umask 022
trusted_path=/usr/local/go/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export PATH="$trusted_path"
unset CDPATH ENV GIT_CONFIG GIT_CONFIG_COUNT GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM
unset LD_LIBRARY_PATH LD_PRELOAD DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root_dir"
go_override=""
go_pin=""
if test "$#" -ge 2 && test "$1" = --go; then
  go_override="$2"
  shift 2
fi
if test "$#" -ne 0; then
  if test "$#" -ne 2 || test "$1" != --go-sha256 || ! [[ "$2" =~ ^[0-9a-f]{64}$ ]]; then
    echo 'Usage: build-release.sh [--go /trusted/bin/go] [--go-sha256 TRUSTED_SHA256]' >&2
    exit 2
  fi
  go_pin="$2"
fi
if test -n "${GO_BIN:-}" && test "$GO_BIN" != "$go_override"; then
  echo 'GO_BIN overrides require a matching --go toolchain path' >&2
  exit 2
fi
if test -n "$go_override" && test -z "$go_pin"; then
  echo 'Alternate Go toolchains require --go-sha256 from a trusted installation' >&2
  exit 2
fi
go_bin="${go_override:-$(command -v go || true)}"
if ! [[ "$go_bin" = /* ]] || ! test -x "$go_bin"; then
  echo 'Go executable not found. Use trusted system Go or --go with an absolute path and --go-sha256.' >&2
  exit 2
fi
python_bin="$(command -v python3)"
run_python() {
  env -i PATH="$trusted_path" LC_ALL=C TZ=UTC "$python_bin" -I "$@"
}
go_bin="$(run_python - "$go_bin" <<'PY'
from pathlib import Path
import sys

go = Path(sys.argv[1]).resolve(strict=True)
if not go.is_file():
    raise SystemExit('Expected a regular Go executable')
print(go)
PY
)"
go_sha256="$(run_python - "$go_bin" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], 'rb') as stream:
    for block in iter(lambda: stream.read(1 << 20), b''):
        digest.update(block)
print(digest.hexdigest())
PY
)"
if test -n "$go_pin" && test "$go_sha256" != "$go_pin"; then
  echo 'Go executable SHA-256 does not match --go-sha256' >&2
  exit 2
fi
# Use the account's cache location even when HOME was changed by a shell profile.
build_home="$(run_python -c 'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)')"
release_version="${VERSION:-0.1.7}"
release_stamp="${BUILD_TIMESTAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
built_at="${BUILD_AT:-${release_stamp:0:4}-${release_stamp:4:2}-${release_stamp:6:2}T${release_stamp:9:2}:${release_stamp:11:2}:${release_stamp:13:2}Z}"
if ! [[ "$release_version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || ! [[ "$release_stamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]; then
  echo "Invalid VERSION or BUILD_TIMESTAMP" >&2
  exit 2
fi
run_python - "$release_stamp" "$built_at" <<'PY'
from datetime import datetime
from sys import argv
stamp = datetime.strptime(argv[1], '%Y%m%dT%H%M%SZ')
built = datetime.strptime(argv[2], '%Y-%m-%dT%H:%M:%SZ')
if stamp != built:
    raise SystemExit('BUILD_AT and BUILD_TIMESTAMP must identify the same UTC instant')
PY
revision="$(run_python scripts/source-identity.py)"
release_id="${release_version}-${release_stamp}-${revision}"
stage="$root_dir/dist/koda-bom-linux-amd64-$release_id"
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
build_work=""
cleanup() {
  if test -n "$build_work"; then
    if test -d "$build_work/modules"; then
      find "$build_work/modules" -type d -exec chmod u+w {} +
    fi
    rm -rf -- "$build_work"
  fi
  test -n "${build_ok:-}" || rm -rf -- "$stage" "$stage.tar.gz" "$stage.tar.gz.sha256"
}
trap cleanup EXIT
build_work="$(mktemp -d "$root_dir/dist/.release-go.XXXXXXXX")"
mkdir "$build_work/cache" "$build_work/modules" "$build_work/tmp"
cached_proxy="$(run_python - "${GOMODCACHE:-$build_home/go/pkg/mod}" <<'PY'
from pathlib import Path
import sys

cache = Path(sys.argv[1])
if not cache.is_absolute():
    raise SystemExit('GOMODCACHE must be an absolute path')
print((cache / 'cache/download').as_uri())
PY
)"
module_proxy="$cached_proxy,${GOPROXY:-https://proxy.golang.org,direct}"
sum_database=sum.golang.org
if test "${GOPROXY:-}" = off; then
  sum_database=off
fi
go_environment=(
  "PATH=$trusted_path" "HOME=$build_home" LC_ALL=C TZ=UTC GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GO111MODULE=on
  GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local GOTELEMETRY=off GOAUTH=netrc
  "GOPATH=$build_home/go" "GOMODCACHE=$build_work/modules"
  "GOCACHE=$build_work/cache" "GOTMPDIR=$build_work/tmp" "TMPDIR=$build_work/tmp"
  "GOPROXY=$module_proxy" "GOSUMDB=$sum_database"
)
run_go() {
  env -i "${go_environment[@]}" "$go_bin" "$@"
}
run_go list -mod=readonly -deps ./cmd/koda-bom > /dev/null
run_go mod verify >&2
run_go list -mod=readonly -m -json all > "$build_work/modules.json"
if test "$(run_python scripts/source-identity.py)" != "$revision"; then
  echo 'Source changed during dependency verification. Rebuild after source freeze.' >&2
  exit 2
fi
build_flags="-s -w -X main.version=$release_version -X main.revision=$revision -X main.builtAt=$built_at"
run_go build -mod=readonly -trimpath -buildvcs=false -ldflags "$build_flags" -o "$stage/koda-bom" ./cmd/koda-bom
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
env -i "${go_environment[@]}" "$python_bin" -I scripts/license-inventory.py --go "$go_bin" --output "$stage/licenses" --strict
run_go version -m -json "$stage/koda-bom" > "$build_work/binary.json"
run_python - "$stage" "$release_id" "$built_at" "$revision" "$go_sha256" "$build_work" "$build_flags" "$sum_database" <<'PY'
import hashlib,json,sys
from pathlib import Path
root=Path(sys.argv[1])
work=Path(sys.argv[6])
build=json.loads((work/'binary.json').read_text())
syft,=(dep["Version"] for dep in build["Deps"] if dep["Path"]=="github.com/anchore/syft")
decoder=json.JSONDecoder()
modules=[]
remaining=(work/'modules.json').read_text()
while remaining.strip():
    remaining=remaining.lstrip()
    module,end=decoder.raw_decode(remaining)
    if module.get('Replace'):
        raise SystemExit('Release requires checksummed modules without replacements')
    modules.append({key:module[key] for key in ('Path','Version','Sum','GoModSum') if key in module})
    remaining=remaining[end:]
inputs={name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in ('go.mod','go.sum')}
provenance={
    'toolchainSHA256':sys.argv[5],
    'sourceInputsSHA256':inputs,
    'command':['go','build','-mod=readonly','-trimpath','-buildvcs=false','-ldflags',sys.argv[7],'-o','$STAGE/koda-bom','./cmd/koda-bom'],
    'environment':{'GOENV':'off','GOWORK':'off','GOFLAGS':'','GOTOOLCHAIN':'local','GOAUTH':'netrc','GOSUMDB':sys.argv[8]},
    'moduleGraph':modules,
}
info={"release":sys.argv[2],"builtAt":sys.argv[3],"revision":sys.argv[4],"architecture":"linux/amd64","goamd64":"v1","cgo":False,"syftVersion":syft,"goVersion":build["GoVersion"],"buildProvenance":provenance}
(root/'release.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n')
lines=[]
for file in sorted(root.rglob('*')):
 if file.is_file() and file.name!='SHA256SUMS':
  lines.append(hashlib.sha256(file.read_bytes()).hexdigest()+'  '+file.relative_to(root).as_posix())
(root/'SHA256SUMS').write_text('\n'.join(lines)+'\n')
PY
if test "$(run_python scripts/source-identity.py)" != "$revision"; then
  echo "Source changed during build; release was not packaged. Rebuild after source freeze." >&2
  exit 2
fi
run_python - "$stage" "$built_at" <<'PYARCHIVE'
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
run_python - "$stage.tar.gz" <<'PY'
import hashlib,sys
from pathlib import Path
p=Path(sys.argv[1]); p.with_name(p.name+'.sha256').write_text(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
PY
build_ok=1
printf '%s\n' "$stage.tar.gz"
