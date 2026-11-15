#!/usr/bin/env bash
# ARM64 build-host fallback: records actual amd64 guest syscalls, not ptrace registers.
set -euo pipefail
if test "$#" -ne 3 && test "$#" -ne 4; then echo 'usage: trace-qemu.sh BINARY FIXTURE_DIRECTORY OUTPUT_DIRECTORY [live-host]' >&2; exit 2; fi
binary="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
fixture="$(cd "$2" && pwd)"
mkdir -p "$3"
result_dir="$(cd "$3" && pwd)"
scan_arguments=(scan --target /fixture --no-context --output-dir /results/output)
if test "${4:-}" = live-host; then
 scan_arguments=(scan --output-dir /results/output --exclude '/fixture/**' --exclude /koda-sbom)
elif test "$#" -eq 4; then
 echo 'Fourth argument must be live-host' >&2
 exit 2
fi
set +e
docker run --rm --platform linux/arm64 --network none --read-only --cap-drop ALL \
 --security-opt no-new-privileges --cpus 2 --memory 1536m \
 --tmpfs /tmp:rw,nosuid,nodev,size=512m \
 --mount "type=bind,src=$binary,dst=/koda-sbom,readonly" \
 --mount "type=bind,src=$fixture,dst=/fixture,readonly" \
 --mount "type=bind,src=$result_dir,dst=/results" \
 local/koda-sbom-qemu-trace:20261029 qemu-x86_64 -strace /koda-sbom \
 "${scan_arguments[@]}" \
 > "$result_dir/stdout.log" 2> "$result_dir/guest-syscalls.log"
scan_status=$?
set -e
if test "$scan_status" -ne 0 && test "$scan_status" -ne 3; then cat "$result_dir/stdout.log"; echo "Guest scan failed: $scan_status" >&2; exit "$scan_status"; fi
python3 - "$result_dir/guest-syscalls.log" "$binary" "$scan_status" <<'PY'
import hashlib,json,re,sys
from pathlib import Path
trace=Path(sys.argv[1]);text=trace.read_text()
network=[line for line in text.splitlines() if re.search(r'\b(socket|socketpair|connect|sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|bind|listen|accept|accept4|getsockname|getpeername)\(',line)]
execs=[line for line in text.splitlines() if re.search(r'\bexecve(at)?\(',line)]
assert len(text.splitlines())>100,'Empty or unexpectedly short trace'
assert not network,'Network attempts observed:\n'+'\n'.join(network)
assert not execs,'External command attempts observed:\n'+'\n'.join(execs)
report={'passed':True,'method':'amd64 binary guest syscall trace via explicit ARM64 qemu-x86_64; not native x86_64 kernel proof','binarySha256':hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest(),'scanExitCode':int(sys.argv[3]),'guestSyscallLines':len(text.splitlines()),'networkSyscallAttempts':0,'execveAttempts':0}
(trace.parent/'trace-verification.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
PY
