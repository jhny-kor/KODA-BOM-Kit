#!/usr/bin/env python3
"""Verify deployed Go and Rust executable dependencies in an offline Linux scan."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request

from validate_outputs import validate


RUST_URL = "https://dl-cdn.alpinelinux.org/alpine/v3.22/community/x86_64/ripgrep-14.1.1-r0.apk"
RUST_APK_SHA256 = "ead003b3ebc2e15b198a98c5e6f5a0de995d5973504cbdce827e2f3b6196ff1a"
RUST_ELF_SHA256 = "9ac30d3491fc59a82c555378be647459789776362002abf076489f00bf57ce0c"
GO_PURL = "pkg:golang/github.com/bmatcuk/doublestar/v4@v4.10.2"
RUST_PURL = "pkg:cargo/aho-corasick@1.1.3"
COVERAGE_KEY = "koda:collection:coverage:v1"
GO_BINARY = "bin/deployed-go"
RUST_BINARY = "bin/deployed-rust"
MALFORMED_RUST = "bin/bad-rust-metadata"
NO_METADATA_RUST = "bin/no-rust-metadata"
SECRET = "KODA_INTEGRATION_GO_BUILD_FLAG_CANARY"
GO_TOOL_ID = "go-module-binary-cataloger"
RUST_TOOL_ID = "cargo-auditable-binary-cataloger"


def build_go_fixture(go, work, destination):
    source = work / "go-source"
    source.mkdir()
    (source / "go.mod").write_text(
        "module example.com/koda-binary-fixture\n\ngo 1.26.8\n\n"
        "require github.com/bmatcuk/doublestar/v4 v4.10.2\n"
    )
    (source / "go.sum").write_text(
        "github.com/bmatcuk/doublestar/v4 v4.10.2 h1:eF7W7HWKg3z9NrWV9pTLnNeoXaqq3Tq9DNKXVMfoCnw=\n"
        "github.com/bmatcuk/doublestar/v4 v4.10.2/go.mod h1:xBQ8jztBU6kakFMg+8WGxn0c6z1fTSPVIjEY1Wr7jzc=\n"
    )
    (source / "main.go").write_text(
        'package main\n\nimport (\n"os"\n"github.com/bmatcuk/doublestar/v4"\n)\n'
        'var token string\nfunc main() {\n'
        'ok,_ := doublestar.Match("**/file", "a/file")\n'
        'if ok { _ = os.WriteFile("/tmp/koda-target-ran", []byte(token), 0600) }\n}\n'
    )
    env = dict(os.environ, GOOS="linux", GOARCH="amd64", GOAMD64="v1", CGO_ENABLED="0",
               GOTOOLCHAIN="local", GOENV="off", GOWORK="off", GOFLAGS="", GOPROXY="off", GOSUMDB="off")
    subprocess.run(
        [go, "build", "-trimpath", "-buildvcs=false", "-ldflags", f"-s -w -X main.token={SECRET}",
         "-o", destination, "."], env=env, cwd=source, check=True, timeout=120
    )
    assert SECRET.encode() in destination.read_bytes(), "fixture must contain the untrusted build flag"


def load_rust_fixture(binary):
    if binary:
        data = binary.read_bytes()
    else:
        limit = 4 << 20
        with urllib.request.urlopen(RUST_URL, timeout=30) as response:
            package = response.read(limit + 1)
        assert len(package) <= limit and hashlib.sha256(package).hexdigest() == RUST_APK_SHA256, RUST_URL
        # Alpine packages have concatenated gzip streams with signature and control
        # archives before the file. ignore_zeros lets tarfile read all of them.
        with tarfile.open(fileobj=io.BytesIO(package), mode="r:gz", ignore_zeros=True) as archive:
            with archive.extractfile("usr/bin/rg") as executable:
                data = executable.read()
    assert hashlib.sha256(data).hexdigest() == RUST_ELF_SHA256, "expected the pinned Alpine ripgrep ELF"
    return data


def rust_section(data):
    """Find the exact section name and content offsets in the pinned ELF fixture."""
    assert data.startswith(b"\x7fELF\x02\x01"), "expected a little-endian ELF64 fixture"
    offset, = struct.unpack_from("<Q", data, 40)
    width, count, names_index = struct.unpack_from("<HHH", data, 58)
    names, = struct.unpack_from("<Q", data, offset + width * names_index + 24)
    for i in range(count):
        section = offset + i * width
        relative_name, = struct.unpack_from("<I", data, section)
        name_offset = names + relative_name
        if data.startswith(b".dep-v0\0", name_offset):
            content_offset, = struct.unpack_from("<Q", data, section + 24)
            return name_offset, content_offset
    raise AssertionError("pinned Rust fixture does not contain .dep-v0")


def prepare_tree(go, work, tree, rust_binary, commands):
    (tree / "bin").mkdir(parents=True)
    (tree / "excluded").mkdir()
    build_go_fixture(go, work, tree / GO_BINARY)
    rust = load_rust_fixture(rust_binary)
    name, content = rust_section(rust)
    (tree / RUST_BINARY).write_bytes(rust)
    # Keep the real ELF and use a small invalid compressed header as a negative
    # fixture. Another copy retains the bytes under an unrelated section name.
    (tree / MALFORMED_RUST).write_bytes(rust[:content] + b"\0\0" + rust[content + 2:])
    (tree / NO_METADATA_RUST).write_bytes(rust[:name] + b".unused" + rust[name + 7:])
    for filename in (RUST_BINARY, MALFORMED_RUST, NO_METADATA_RUST):
        (tree / filename).chmod(0o755)
    shutil.copy2(tree / GO_BINARY, tree / "excluded/go")
    shutil.copy2(tree / RUST_BINARY, tree / "excluded/rust")
    (tree / "go.mod").write_text(
        "module example.com/declared-only-go\n\ngo 1.26.8\n\nrequire example.com/unlinked-go-canary v1.2.3\n"
    )
    (tree / "Cargo.lock").write_text(
        'version = 4\n\n[[package]]\nname = "unlinked-rust-canary"\nversion = "1.2.3"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )
    commands.mkdir()
    for name in ("go", "cargo", "rustc"):
        tool = commands / name
        tool.write_text("#!/bin/sh\ntouch /tmp/koda-build-tool-ran\nexit 97\n")
        tool.chmod(0o755)


def run_scan(collector, tree, output, commands):
    command = [
        "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
        "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--cpus", "2", "--memory", "1536m",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
        "--mount", f"type=bind,src={collector},dst=/koda-bom,readonly",
        "--mount", f"type=bind,src={tree},dst=/fixture,readonly",
        "--mount", f"type=bind,src={output},dst=/results",
        "--mount", f"type=bind,src={commands},dst=/tool-canaries,readonly",
        "--env", "PATH=/tool-canaries:/usr/bin:/bin",
        "debian:bookworm-slim", "/bin/sh", "-c",
        '/koda-bom "$@"; scan_status=$?; '
        'test ! -e /tmp/koda-target-ran && test ! -e /tmp/koda-build-tool-ran || exit 97; '
        'exit "$scan_status"',
        "scan-fixtures", "scan", "--target", "/fixture", "--exclude-dir", "/fixture/excluded",
        "--output-dir", "/results", "--no-context",
    ]
    process = subprocess.run(command, capture_output=True, text=True, timeout=180)
    assert process.returncode == 3, (process.returncode, process.stdout, process.stderr)
    result, = output.iterdir()
    return result


def verify_coverage(cdx, spdx):
    cdx_coverage, = (prop["value"] for prop in cdx["metadata"]["properties"] if prop["name"] == COVERAGE_KEY)
    spdx_coverage = spdx["comment"]
    assert spdx_coverage.startswith(COVERAGE_KEY + " "), spdx_coverage
    coverage = json.loads(cdx_coverage)
    assert coverage == json.loads(spdx_coverage[len(COVERAGE_KEY) + 1:]), spdx_coverage
    assert coverage["status"] == "partial" and coverage["excludedDirectoryCount"] == 1, coverage
    assert {"code": "binary_metadata_unreadable", "count": 1} in coverage["issueCounts"], coverage


def verify_relationships(cdx, spdx):
    cdx_refs = {item["name"]: item["bom-ref"] for item in cdx["components"]}
    cdx_dependencies = {item["ref"]: item.get("dependsOn", []) for item in cdx["dependencies"]}
    spdx_ids = {item["name"]: item["SPDXID"] for item in spdx["packages"]}
    spdx_dependencies = {
        (item["relatedSpdxElement"], item["spdxElementId"])
        for item in spdx["relationships"] if item["relationshipType"] == "DEPENDENCY_OF"
    }
    for package, dependency in (
        ("example.com/koda-binary-fixture", "github.com/bmatcuk/doublestar/v4"),
        ("aho-corasick", "memchr"),
    ):
        assert cdx_refs[dependency] in cdx_dependencies[cdx_refs[package]], (package, dependency)
        assert (spdx_ids[package], spdx_ids[dependency]) in spdx_dependencies, (package, dependency)


def verify_evidence(result):
    schemas = validate(result)
    cdx = json.loads((result / "sbom.cdx.json").read_bytes())
    spdx = json.loads((result / "sbom.spdx.json").read_bytes())
    collection = json.loads((result / "collection.json").read_bytes())
    for path in result.glob("*.json"):
        data = path.read_bytes()
        for undesired in (SECRET, "unlinked-go-canary", "unlinked-rust-canary", "excluded/go", "excluded/rust"):
            assert undesired.encode() not in data, (path.name, undesired)
    cdx_packages = cdx.get("components", [])
    assert cdx_packages, "catalogers returned no deployed binaries"
    assert all(item["name"] != "cc" or item.get("purl") != "pkg:cargo/cc@1.1.18" for item in cdx_packages)
    local_rust, = (item for item in cdx_packages if item["name"] == "ripgrep")
    assert local_rust["version"] == "14.1.1" and not local_rust.get("purl"), local_rust
    local_go, = (item for item in cdx_packages if item["name"] == "example.com/koda-binary-fixture")
    assert not local_go.get("version") and not local_go.get("purl"), local_go
    counts = {item["name"]: item["packageCount"] for item in collection["collectorResults"]}
    assert counts[GO_TOOL_ID] and counts[RUST_TOOL_ID], counts
    issues = [
        item for item in collection["issues"]
        if item.get("code") == "binary_metadata_unreadable" and item.get("path", "").lstrip("/") == MALFORMED_RUST
    ]
    assert issues and not any(
        item.get("path", "").lstrip("/") == NO_METADATA_RUST for item in collection["issues"]
    ), collection["issues"]
    for purl, location in ((GO_PURL, GO_BINARY), (RUST_PURL, RUST_BINARY)):
        cdx_package, = (item for item in cdx_packages if item.get("purl") == purl)
        occurrences = cdx_package["evidence"]["occurrences"]
        assert {item["location"].lstrip("/") for item in occurrences} == {location}, cdx_package
        spdx_package, = (
            item for item in spdx["packages"]
            if ("purl", purl) in {(ref["referenceType"], ref["referenceLocator"]) for ref in item.get("externalRefs", [])}
        )
        evidence = json.loads(spdx_package["comment"])
        assert {path.lstrip("/") for path in evidence["evidencePaths"]} == {location}, spdx_package
    verify_coverage(cdx, spdx)
    verify_relationships(cdx, spdx)
    return {
        "passed": True, "validation": schemas, "network": "none",
        "Go": GO_PURL, "Rust": RUST_PURL,
        "malformedRustReported": True, "declaredOnlyExcluded": True, "dependencyRelationships": True,
        "fixtureAndBuildToolsNotExecuted": True,
    }


def verify_tracker(tracker_root, result):
    tracker_root = tracker_root.resolve(strict=True)
    script = """\
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / "apps/api"))
from koda_tracker.collection_coverage import coverage_for_bom
from koda_tracker.sbom import parse_sbom

result = Path(sys.argv[2])
expected_purls = set(sys.argv[3:])
summaries = {}
for filename in ("sbom.cdx.json", "sbom.spdx.json"):
    bom, _ = parse_sbom((result / filename).read_bytes())
    evidence, _ = coverage_for_bom(bom)
    coverage = evidence["collectionCoverage"]
    assert expected_purls <= {item.get("purl") for item in bom["components"]}, filename
    assert coverage["status"] == "partial" and coverage["excludedDirectoryCount"] == 1, coverage
    assert coverage["issueCounts"] == [{"code": "binary_metadata_unreadable", "count": 1}], coverage
    summaries[filename] = coverage
assert summaries["sbom.cdx.json"] == summaries["sbom.spdx.json"], summaries
print(json.dumps(summaries))
"""
    process = subprocess.run(
        [str(tracker_root / ".venv/bin/python"), "-c", script, str(tracker_root), str(result), GO_PURL, RUST_PURL],
        capture_output=True, text=True, timeout=60,
    )
    assert process.returncode == 0, (process.stdout, process.stderr)
    return json.loads(process.stdout)


def exercise(stage, go, rust_binary, tracker_root=None):
    collector = (stage / "koda-bom").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="koda-go-rust-binary-") as temp:
        work = Path(temp)
        tree, output, commands = work / "fixtures", work / "output", work / "command-canaries"
        output.mkdir()
        output.chmod(0o777)
        prepare_tree(go, work, tree, rust_binary, commands)
        result = run_scan(collector, tree, output, commands)
        report = verify_evidence(result)
        if tracker_root is not None:
            report["tracker"] = verify_tracker(tracker_root, result)
        return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--go", default="go", help="Go build tool with doublestar v4.10.2 already cached")
    parser.add_argument("--rust-binary", type=Path, help="verified Alpine ripgrep ELF to avoid downloading the APK")
    parser.add_argument("--tracker-root", type=Path, help="optional local Tracker checkout with an initialized .venv")
    args = parser.parse_args()
    print(json.dumps(exercise(args.stage, args.go, args.rust_binary, args.tracker_root), indent=2))
