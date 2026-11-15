#!/usr/bin/env bash
# Debug image needs strace. Build it on the external build host first.
set -euo pipefail
if test "$#" -ne 3; then echo 'usage: trace-network.sh BINARY FIXTURE_DIRECTORY OUTPUT_DIRECTORY' >&2; exit 2; fi
binary="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
fixture="$(cd "$2" && pwd)"
mkdir -p "$3"
result_dir="$(cd "$3" && pwd)"
set +e
docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL \
 --cap-add SYS_PTRACE --security-opt seccomp=unconfined --security-opt no-new-privileges \
 --tmpfs /tmp:rw,nosuid,nodev,size=512m \
 --mount "type=bind,src=$binary,dst=/koda-sbom,readonly" \
 --mount "type=bind,src=$fixture,dst=/fixture,readonly" \
 --mount "type=bind,src=$result_dir,dst=/results" \
 local/koda-sbom-trace:20261029 \
 strace -f -e trace=network,execve -o /results/syscalls.log \
 /koda-sbom scan --target /fixture --no-context --output-dir /results/output
scan_status=$?
set -e
if test "$scan_status" -ne 0 && test "$scan_status" -ne 3; then exit "$scan_status"; fi
python3 - "$result_dir/syscalls.log" <<'PY'
import re,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text();network=[];execs=[]
if 'syscall_0x' in text:
 print('UNSUPPORTED: invalid syscall register decoding under emulation; rerun trace on native x86_64 Linux',file=sys.stderr);raise SystemExit(77)
for line in text.splitlines():
 if re.search(r'\b(socket|connect|sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|bind|listen|accept|accept4|getsockname|getpeername|socketpair)\(',line):network.append(line)
 if re.search(r'\bexecve\(',line):execs.append(line)
assert not network,'Network syscall attempts:\n'+'\n'.join(network)
assert len(execs)==1 and '"/koda-sbom"' in execs[0],'Unexpected external command execution:\n'+'\n'.join(execs)
print('PASS: network syscalls 0, only initial /koda-sbom execve')
PY
