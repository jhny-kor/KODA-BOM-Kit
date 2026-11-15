#!/bin/sh
# Optional installed-client queries. The collector itself never starts clients.
# No install, refresh, upgrade, patch application or daemon configuration occurs.
set -eu
umask 077

usage_error() {
    echo "usage: $0 RESULT_PARENT_DIRECTORY [--timeout DURATION] [--max-files N] [--exclude GLOB]..." >&2
    exit 2
}

# Validate the complete option list before doctor, output creation or any client
# query. Function positional parameters are separate from the caller's "$@".
validate_scan_options() {
    [ "$#" -le 256 ] || usage_error
    while [ "$#" -gt 0 ]; do
        [ "${#1}" -le 4096 ] || usage_error
        case "$1" in
            --timeout|--max-files|--exclude)
                [ "$#" -ge 2 ] || usage_error
                option=$1
                value=$2
                shift 2
                ;;
            --timeout=*|--max-files=*|--exclude=*)
                option=${1%%=*}
                value=${1#*=}
                shift
                ;;
            *) usage_error ;;
        esac
        [ -n "$value" ] && [ "${#value}" -le 4096 ] || usage_error
        case "$value" in --*) usage_error ;; esac
        case "$option" in
            --max-files)
                case "$value" in *[!0-9]*) usage_error ;; esac
                ;;
            --timeout)
                case "$value" in -*) usage_error ;; esac
                ;;
        esac
    done
}

[ "$#" -ge 1 ] || usage_error
output_argument=$1
shift
validate_scan_options "$@"
helper_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$helper_dir/koda-sbom" ]; then
    collector="$helper_dir/koda-sbom"
else
    echo "Place this helper beside the release koda-sbom executable." >&2
    exit 2
fi
"$collector" validate-scan-options "$@"
"$collector" doctor
mkdir -p -- "$output_argument"
result_parent=$(CDPATH= cd -- "$output_argument" && pwd)
evidence_dir=$(mktemp -d "$result_parent/livepatch-evidence.XXXXXX")
raw_dir=$(mktemp -d "${TMPDIR:-/tmp}/koda-livepatch.XXXXXX")
trap 'rm -rf -- "$raw_dir"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

find_client() {
    client_path=$(command -v "$1" 2>/dev/null || true)
    case "$client_path" in
        /*) [ -x "$client_path" ] && return 0 ;;
    esac
    if [ "$1" = canonical-livepatch ] && [ -x /snap/bin/canonical-livepatch ]; then
        client_path=/snap/bin/canonical-livepatch
        return 0
    fi
    return 1
}

query_client() {
    # GNU timeout bounds a stalled status client; file-size limit bounds output.
    # Client stdout/stderr are temporary and never copied into scan results.
    (ulimit -f 2048; timeout --kill-after=5s 30s "$@") > "$raw_dir/report" 2> "$raw_dir/error"
}

capture_provider() {
    provider=$1
    client=$2
    shift 2
    evidence_file="$evidence_dir/$provider.json"
    reason=
    if ! find_client "$client"; then
        reason=not_installed
    elif ! command -v timeout >/dev/null 2>&1; then
        reason=query_failed
    else
        query_exit=0
        query_client "$client_path" "$@" || query_exit=$?
        if [ "$query_exit" -eq 124 ]; then
            reason=query_timed_out
        elif [ "$query_exit" -ne 0 ]; then
            reason=query_failed
        else
            if [ "$provider" = uptrack ]; then
                effective_args=
                if find_client uptrack-uname; then
                    if (ulimit -f 1; timeout --kill-after=5s 10s "$client_path" -r) > "$raw_dir/effective" 2>/dev/null; then
                        effective_args="$raw_dir/effective"
                    fi
                fi
                if [ -n "$effective_args" ]; then
                    "$collector" livepatch-evidence --provider "$provider" --input "$raw_dir/report" --effective-kernel-file "$effective_args" --output "$evidence_file" && return 0
                else
                    "$collector" livepatch-evidence --provider "$provider" --input "$raw_dir/report" --output "$evidence_file" && return 0
                fi
            else
                "$collector" livepatch-evidence --provider "$provider" --input "$raw_dir/report" --output "$evidence_file" && return 0
            fi
            reason=invalid_report
        fi
    fi
    "$collector" livepatch-evidence --provider "$provider" --query-status "$reason" --output "$evidence_file"
}

capture_provider canonical-livepatch canonical-livepatch status --verbose --format json
capture_provider ksplice ksplice kernel show
capture_provider uptrack uptrack-show

echo "Sanitized livepatch evidence: $evidence_dir" >&2
rm -rf -- "$raw_dir"
trap - EXIT HUP INT TERM
exec "$collector" scan --output-dir "$result_parent" \
    --livepatch-evidence "$evidence_dir/canonical-livepatch.json" \
    --livepatch-evidence "$evidence_dir/ksplice.json" \
    --livepatch-evidence "$evidence_dir/uptrack.json" "$@"
