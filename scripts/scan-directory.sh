#!/bin/sh
# Collect only a chosen directory tree; do not inspect live-host context.
set -eu
umask 077

usage_error() {
    echo "usage: $0 TARGET_DIRECTORY [RESULT_PARENT_DIRECTORY] [--cyclonedx-17] [--separate-boms] [--timeout DURATION] [--max-files N] [--exclude GLOB]... [--exclude-dir DIRECTORY]..." >&2
    exit 2
}

validate_option_names() {
    [ "$#" -le 256 ] || usage_error
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --cyclonedx-17|--cyclonedx-17=*|--separate-boms|--separate-boms=*)
                shift
                continue
                ;;
            --timeout|--max-files|--exclude|--exclude-dir)
                [ "$#" -ge 2 ] || usage_error
                shift 2
                ;;
            --timeout=*|--max-files=*|--exclude=*|--exclude-dir=*) shift ;;
            *) usage_error ;;
        esac
    done
}

[ "$#" -ge 1 ] && [ -n "$1" ] || usage_error
target_argument=$1
shift
output_argument=./sbom-output
if [ "$#" -gt 0 ]; then
    case "$1" in
        --*) ;;
        *) output_argument=$1; shift ;;
    esac
fi
validate_option_names "$@"
helper_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
collector="$helper_dir/koda-bom"
if [ ! -x "$collector" ]; then
    echo "Place this script beside the release koda-bom executable." >&2
    exit 2
fi
# Use the collector's pure parser for durations, counts and exclusion globs.
# No output directory or client query is created during this validation.
"$collector" validate-scan-options "$@"
if [ ! -d "$target_argument" ]; then
    echo "Target must be an existing readable directory." >&2
    exit 2
fi
if ! target_directory=$(CDPATH= cd -- "$target_argument" && pwd -P); then
    echo "Target directory could not be opened." >&2
    exit 2
fi
if [ "$target_directory" = / ]; then
    echo "Choose a specific directory below /. For a full host scan, use koda-bom scan." >&2
    exit 2
fi
exec "$collector" scan --target "$target_directory" --no-context \
    --output-dir "$output_argument" "$@"
