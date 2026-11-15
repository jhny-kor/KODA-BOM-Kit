#!/bin/sh
# Capture inventory only. Run Oracle's lsinventory separately as the Oracle Home owner.
set -eu
umask 077
PATH=/usr/bin:/usr/sbin:/bin:/sbin
LC_ALL=C
export PATH LC_ALL

usage() {
    printf '%s\n' "usage: $0 NEW_OUTPUT_DIRECTORY [ORACLE_HOME OPATCH_LSINVENTORY_FILE [SQLPATCH_CSV]]" \
        "       $0 NEW_OUTPUT_DIRECTORY --oracle-home HOME OPATCH_LSINVENTORY_FILE [--sqlpatch CSV] [--oracle-home HOME OPATCH_LSINVENTORY_FILE [--sqlpatch CSV]]..." >&2
    exit 2
}

[ "$#" -gt 0 ] && [ -n "$1" ] || usage
if [ "$(uname -s)" != AIX ]; then
    echo "This capture script requires IBM AIX." >&2
    exit 2
fi

case $1 in /*) output=$1 ;; *) output=./$1 ;; esac
shift
newline='
'
tab=$(printf '\t')
carriage_return=$(printf '\r')
canonical_home() {
    # Keep the final newline from pwd distinct from any newline in the path.
    if ! canonical=$(CDPATH= cd -- "$1" && pwd -P && printf '.'); then
        echo "ORACLE_HOME must identify an existing Oracle installation directory." >&2
        exit 2
    fi
    canonical=${canonical%?}
    canonical=${canonical%"$newline"}
    case $canonical in
        /|'')
            echo "ORACLE_HOME must identify an existing Oracle installation directory." >&2
            exit 2
            ;;
        *"$newline"*|*"$tab"*|*"$carriage_return"*)
            echo "ORACLE_HOME must not contain tabs or line breaks." >&2
            exit 2
            ;;
    esac
    printf '%s\n' "$canonical"
}

schema=koda-aix-evidence-v1
home_count=0
if [ "${1:-}" = --oracle-home ]; then
    schema=koda-aix-evidence-v2
    seen_homes=$newline
    remaining=$#
    # Rotate each validated triple to the end of the positional parameters.
    # remaining counts only the original, still-unparsed arguments.
    while [ "$remaining" -gt 0 ]; do
        [ "$remaining" -ge 3 ] && [ "$1" = --oracle-home ] && [ -n "$2" ] && [ -n "$3" ] || usage
        home=$(canonical_home "$2") || exit 2
        opatch_report=$3
        shift 3
        remaining=$((remaining - 3))
        sqlpatch_report=
        if [ "$remaining" -gt 0 ] && [ "$1" = --sqlpatch ]; then
            [ "$remaining" -ge 2 ] && [ -n "$2" ] || usage
            sqlpatch_report=$2
            shift 2
            remaining=$((remaining - 2))
        fi
        case $seen_homes in
            *"$newline$home$newline"*)
                echo "Each Oracle Home must be specified once." >&2
                exit 2
                ;;
        esac
        seen_homes="$seen_homes$home$newline"
        home_count=$((home_count + 1))
        if [ "$home_count" -gt 8 ]; then
            echo "At most eight Oracle Homes can be captured." >&2
            exit 2
        fi
        set -- "$@" "$home" "$opatch_report" "$sqlpatch_report"
    done
elif [ "$#" -gt 0 ]; then
    [ "$#" -eq 2 ] || [ "$#" -eq 3 ] || usage
    [ -n "$1" ] && [ -n "$2" ] || usage
    home=$(canonical_home "$1") || exit 2
    set -- "$home" "$2" "${3:-}"
    home_count=1
fi
if ! mkdir "$output"; then
    echo "Use a new output directory with an existing parent." >&2
    exit 2
fi
pending="$output/.capture.tsv"
trap 'rm -f "$pending"; exit 2' HUP INT TERM
printf '%s\n' "$schema" > "$pending"
partial=0

record() {
    printf '%s\t%s\n' "$1" "$2" >> "$pending"
    if [ "$2" = failed ]; then
        partial=1
        printf 'Could not capture %s\n' "$1" >&2
    fi
}

capture() {
    name=$1
    shift
    # POSIX ulimit -f uses 512-byte blocks. Bound command and copied-report output.
    if (ulimit -f 16384 && "$@") > "$output/$name" 2>/dev/null && [ -s "$output/$name" ]; then
        record "$name" ok
    else
        rm -f "$output/$name"
        record "$name" failed
    fi
}

copy_report() {
    [ -f "$1" ] && [ ! -L "$1" ] && cat < "$1"
}

listener_header() {
    # Capture the file header without executing the Listener or reading config.
    [ -d "$1/bin" ] && [ ! -L "$1/bin" ] && [ -r "$1/bin" ] && [ -x "$1/bin" ] || return 1
    listener="$1/bin/tnslsnr"
    if [ -L "$listener" ]; then
        return 1
    fi
    if [ ! -e "$listener" ]; then
        printf '%s\n' absent
        return
    fi
    [ -f "$listener" ] && [ -r "$listener" ] && [ -x "$listener" ] || return 1
    od -A n -N 24 -t x1 -v "$listener"
}

capture_home() {
    printf '%s\n' "$2" > "$output/${1}oracle-home.txt"
    record "${1}oracle-home.txt" ok
    capture "${1}opatch.txt" copy_report "$3"
    capture "${1}listener.txt" listener_header "$2"
    if [ -n "$4" ]; then
        capture "${1}sqlpatch.csv" copy_report "$4"
    else
        record "${1}sqlpatch.csv" omitted
    fi
}

capture oslevel.txt oslevel -s
capture lslpp.txt lslpp -Lcq
capture emgr.txt emgr -lv3
if [ "$schema" = koda-aix-evidence-v2 ]; then
    mkdir "$output/homes"
    index=1
    while [ "$index" -le "$home_count" ]; do
        mkdir "$output/homes/$index"
        capture_home "homes/$index/" "$1" "$2" "$3"
        shift 3
        index=$((index + 1))
    done
elif [ "$home_count" -eq 1 ]; then
    capture_home "" "$1" "$2" "$3"
else
    for name in oracle-home.txt opatch.txt listener.txt sqlpatch.csv; do
        record "$name" omitted
    done
fi
mv "$pending" "$output/capture.tsv"
printf '%s\n' "$output"
if [ "$partial" -ne 0 ]; then
    exit 3
fi
