#!/usr/bin/env python3
"""Verify physical npm dependency edges in real pnpm workspaces and deployments."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote

from validate_outputs import validate

PNPM_VERSION = "11.25.0"
CASES = ("workspace", "deployed", "deployed-default")
WORKSPACE_PACKAGES = {
    "workspace": (".", "1.0.0", {}),
    "legacy": ("packages/legacy", "1.0.0", {"is-odd": "2.0.0", "@koda-fixture/shared": "workspace:*"}),
    "modern": ("packages/modern", "1.0.0", {"is-odd": "3.0.1", "@koda-fixture/shared": "workspace:^1.2.0"}),
    "shared": ("packages/shared", "1.2.3", {"is-number": "6.0.0"}),
}
REENTRY_NAME = "reentry-dependency"
OUTSIDE_NAME = "escape-dependency"
EXCLUDED_NAME = "blocked-dependency"
CANARIES = (OUTSIDE_NAME, EXCLUDED_NAME, REENTRY_NAME)
SPDX_SOURCE_PREFIX = "acquired package info from installed node module manifest file: "

NODE_RESOLVE = """
const {createRequire} = require('node:module');
const fs = require('node:fs');
const queries = JSON.parse(process.argv[1]);
const resolved = queries.map(({manifest, name}) => {
  const file = createRequire(manifest).resolve(name + '/package.json');
  const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));
  return {manifest, name, file, foundName: pkg.name, version: pkg.version};
});
console.log(JSON.stringify(resolved));
"""


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_package(directory, name, version, dependencies=None):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(json.dumps({
        "name": name, "version": version, "private": True,
        "main": "index.js", "dependencies": dependencies or {},
    }, indent=2) + "\n", encoding="utf-8")
    (directory / "index.js").write_text("module.exports = {};\n", encoding="utf-8")


def create_deployment(root, pnpm, source_name, deployment_name, *, injected):
    workspace = root / source_name
    workspace.mkdir()
    workspace_config = "packages:\n  - 'packages/*'\n"
    if injected:
        workspace_config += "injectWorkspacePackages: true\n"
    (workspace / "pnpm-workspace.yaml").write_text(workspace_config, encoding="utf-8")
    for name, (relative, version, deps) in WORKSPACE_PACKAGES.items():
        write_package(workspace / relative, f"@koda-fixture/{name}", version, deps)

    common = ["--ignore-scripts", "--store-dir", str(root / "store")]
    deploy_options = [] if injected else ["--legacy"]
    env = {**os.environ, "CI": "true", "NO_UPDATE_NOTIFIER": "1"}
    commands = [
        [pnpm, "install", "--no-frozen-lockfile", *common],
        [pnpm, "--filter", "@koda-fixture/modern", "deploy", "--prod", *deploy_options,
         *common, str(root / deployment_name)],
    ]
    for index, command in enumerate(commands, 1):
        result = subprocess.run(command, cwd=workspace, capture_output=True, text=True, env=env, timeout=120, check=False)
        log = root / f"{deployment_name}-pnpm-{index}.log"
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        if result.returncode:
            raise AssertionError(f"pnpm fixture command failed ({deployment_name}, {index}): {log.read_text()}")


def create_fixture(root, pnpm):
    version = subprocess.check_output([pnpm, "--version"], text=True, timeout=20).strip()
    if version != PNPM_VERSION:
        raise AssertionError(f"Expected pnpm {PNPM_VERSION}, got {version}")
    root.mkdir(parents=True, exist_ok=True)
    create_deployment(root, pnpm, "workspace", "deployed", injected=False)
    create_deployment(root, pnpm, "injected-source", "deployed-default", injected=True)
    # The default deployment's manifest keeps the original source URI.
    # Relocate the source so it cannot establish a dependency in the scan.
    (root / "injected-source").rename(root / "retired-source")

    workspace = root / "workspace"
    boundary_targets = {
        OUTSIDE_NAME: root / "outside" / OUTSIDE_NAME,
        EXCLUDED_NAME: workspace / "private-cache" / EXCLUDED_NAME,
        REENTRY_NAME: workspace / "return-target" / REENTRY_NAME,
    }
    for name, destination in boundary_targets.items():
        write_package(destination, name, "9.0.0")
        # A farther installation of the same name is visible. A prohibited
        # nearer symlink must not cause resolution to pick the farther version.
        write_package(workspace / "node_modules" / name, name, "1.0.0")
        link_target = destination
        if name == REENTRY_NAME:
            link_target = root / "outside" / "relay"
            link_target.symlink_to(os.path.relpath(destination, link_target.parent), target_is_directory=True)
        link = workspace / "packages/legacy/node_modules" / name
        link.symlink_to(os.path.relpath(link_target, link.parent), target_is_directory=True)
    legacy = workspace / "packages/legacy/package.json"
    manifest = read_json(legacy)
    manifest["dependencies"].update(dict.fromkeys((OUTSIDE_NAME, EXCLUDED_NAME), "*"))
    manifest["optionalDependencies"] = {REENTRY_NAME: "*"}
    legacy.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def npm_purl(name, version):
    return f"pkg:npm/{quote(name, safe='/')}@{version}"


def fixture_model(root, node, case):
    workspace = case == "workspace"
    physical_store = "node_modules/.pnpm"
    is_odd = ("2.0.0", "3.0.1") if workspace else ("3.0.1",)
    numbers = ("4.0.0", "6.0.0") if workspace else ("6.0.0",)
    paths = {
        (name, version): f"{physical_store}/{name}@{version}/node_modules/{name}/package.json"
        for name, versions in (("is-odd", is_odd), ("is-number", numbers)) for version in versions
    }
    modern = ("@koda-fixture/modern", "1.0.0")
    shared = ("@koda-fixture/shared", "1.2.3")
    paths[modern] = "packages/modern/package.json" if workspace else "package.json"
    if workspace:
        paths[shared] = "packages/shared/package.json"
    elif case == "deployed":
        paths[shared] = f"{physical_store}/@koda-fixture+shared@file+packages+shared/node_modules/@koda-fixture/shared/package.json"
    else:
        target = (root / "node_modules/@koda-fixture/shared/package.json").resolve(strict=True)
        paths[shared] = target.relative_to(root).as_posix()
        assert paths[shared].startswith(f"{physical_store}/@koda-fixture+shared@file+"), paths[shared]
        declaration = read_json(root / "package.json")["dependencies"][shared[0]]
        source = root.parent / "injected-source/packages/shared"
        assert declaration == f"{shared[0]}@file://{source}" and not source.exists(), declaration
    expected = [
        (modern, ("is-odd", "3.0.1")), (modern, shared),
        (shared, ("is-number", "6.0.0")), (("is-odd", "3.0.1"), ("is-number", "6.0.0")),
    ]
    if workspace:
        legacy = ("@koda-fixture/legacy", "1.0.0")
        paths[legacy] = "packages/legacy/package.json"
        paths[("@koda-fixture/workspace", "1.0.0")] = "package.json"
        paths[(REENTRY_NAME, "9.0.0")] = f"return-target/{REENTRY_NAME}/package.json"
        for name in CANARIES:
            paths[(name, "1.0.0")] = f"node_modules/{name}/package.json"
        expected.extend([
            (legacy, ("is-odd", "2.0.0")), (legacy, shared), (("is-odd", "2.0.0"), ("is-number", "4.0.0")),
        ])

    queries = [{"manifest": str(root / paths[source]), "name": target[0]} for source, target in expected]
    if workspace:
        queries.extend({"manifest": str(root / paths[legacy]), "name": name} for name in CANARIES)
    result = subprocess.run([node, "-e", NODE_RESOLVE, json.dumps(queries)], capture_output=True, text=True, timeout=20, check=True)
    resolved = json.loads(result.stdout)
    for lookup, (_, target) in zip(resolved[:len(expected)], expected, strict=True):
        assert (lookup["foundName"], lookup["version"]) == target, lookup
        assert Path(lookup["file"]).relative_to(root).as_posix() == paths[target], lookup
    if workspace:
        for lookup, name in zip(resolved[len(expected):], CANARIES, strict=True):
            assert (lookup["foundName"], lookup["version"]) == (name, "9.0.0"), lookup
        assert not Path(resolved[-3]["file"]).is_relative_to(root), resolved[-3]
        assert Path(resolved[-2]["file"]).relative_to(root).parts[0] == "private-cache", resolved[-2]
        assert Path(resolved[-1]["file"]).relative_to(root).parts[0] == "return-target", resolved[-1]

    for (name, version), location in paths.items():
        manifest = read_json(root / location)
        assert (manifest["name"], manifest["version"]) == (name, version), (root.name, location)
    occurrences = {(npm_purl(*identity), location) for identity, location in paths.items()}
    relations = {(npm_purl(*source), paths[source], npm_purl(*target), paths[target]) for source, target in expected}
    return occurrences, relations


def read_cyclonedx(path):
    document = read_json(path)
    packages = []
    for item in document["components"]:
        paths = {
            prop["value"] for prop in item.get("properties", [])
            if re.fullmatch(r"syft:location:[0-9]+:path", prop["name"])
        }
        paths.update(value["location"] for value in (item.get("evidence") or {}).get("occurrences", []))
        packages.append((item["bom-ref"], item.get("purl", ""), paths))
    edges = {(entry["ref"], dependency) for entry in document.get("dependencies", []) for dependency in entry["dependsOn"]}
    root = document["metadata"]["component"]["bom-ref"]
    return packages, edges, root


def read_spdx(path):
    document = read_json(path)
    packages = []
    for item in document["packages"]:
        purl = next((ref["referenceLocator"] for ref in item.get("externalRefs", [])
                     if ref["referenceType"] == "purl"), "")
        location = item.get("sourceInfo", "").removeprefix(SPDX_SOURCE_PREFIX)
        paths = set(location.split(", ")) if item.get("sourceInfo", "").startswith(SPDX_SOURCE_PREFIX) else set()
        if item.get("comment", "").startswith("{"):
            paths.update(json.loads(item["comment"]).get("evidencePaths", []))
        packages.append((item["SPDXID"], purl, paths))
    edges = set()
    for edge in document.get("relationships", []):
        source, target = edge["spdxElementId"], edge["relatedSpdxElement"]
        if edge["relationshipType"] == "DEPENDENCY_OF":
            edges.add((target, source))
        elif edge["relationshipType"] == "DEPENDS_ON":
            edges.add((source, target))
    return packages, edges, document["SPDXID"]


def compare_format(packages, edges, root_ref, expected_packages, expected_edges):
    byref = {ref: (purl, paths) for ref, purl, paths in packages}
    assert len(byref) == len(packages), "duplicate component reference"
    npm_refs = {ref for ref, (purl, _paths) in byref.items() if purl.startswith("pkg:npm/")}
    observed_packages = {(byref[ref][0], path) for ref in npm_refs for path in byref[ref][1]}
    assert all(byref[ref][1] for ref in npm_refs), "a collected npm component had no manifest path"
    observed_edges = {
        (byref[source][0], left, byref[target][0], right)
        for source, target in edges if source in npm_refs and target in npm_refs
        for left in byref[source][1] for right in byref[target][1]
    }
    known = byref.keys() | {root_ref}
    dangling = sorted((source, target) for source, target in edges if source not in known or target not in known)
    return {
        "npmPackages": len(npm_refs),
        "duplicateOccurrences": sum(len(byref[ref][1]) for ref in npm_refs) - len(observed_packages),
        "observedEdges": sorted(observed_edges),
        "missingPackages": sorted(expected_packages - observed_packages),
        "unexpectedPackages": sorted(observed_packages - expected_packages),
        "missingEdges": sorted(expected_edges - observed_edges),
        "unexpectedEdges": sorted(observed_edges - expected_edges),
        "danglingEdges": dangling,
    }


def run_scan(root, binary, out, case, image):
    excludes = ("private-cache",) if case == "workspace" else ()
    expected_exit = 0 if case == "deployed-default" else 3
    return run_target_scan(root, binary, out, case, image, excludes, expected_exit)


def run_target_scan(root, binary, out, target, image, excludes, expected_exit):
    out.mkdir(mode=0o777)
    out.chmod(0o777)
    command = [
        "docker", "run", "--rm", "--pull", "never", "--platform", "linux/amd64", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--mount", f"type=bind,src={root},dst=/fixture,readonly",
        "--mount", f"type=bind,src={binary},dst=/koda-bom,readonly",
        "--mount", f"type=bind,src={out},dst=/output",
        image, "/koda-bom", "scan", "--target", f"/fixture/{target}", "--output-dir", "/output",
        "--no-context", "--format", "both",
    ]
    for excluded in excludes:
        command += ["--exclude-dir", excluded]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != expected_exit:
        raise AssertionError(f"{target} scan failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    run_dir, = out.iterdir()
    return run_dir, result.returncode


def case_result(root, case, binary, out, image, node):
    expected_packages, expected_edges = fixture_model(root / case, node, case)
    result, exit_code = run_scan(root, binary, out / case, case, image)
    collection = read_json(result / "collection.json")
    formats = {}
    for suffix, reader in (("cdx", read_cyclonedx), ("spdx", read_spdx)):
        path = result / f"sbom.{suffix}.json"
        formats[suffix] = compare_format(*reader(path), expected_packages, expected_edges)
        raw = path.read_text(encoding="utf-8")
        for marker in ("/fixture/", str(root), f"outside/{OUTSIDE_NAME}", "outside/relay",
                       f"private-cache/{EXCLUDED_NAME}/package.json"):
            assert marker not in raw, (case, suffix, marker)
    if case == "workspace":
        assert collection["excludedDirectories"] == ["private-cache"], collection
        expected_issues = {f"packages/legacy/node_modules/{name}" for name in CANARIES}
    elif case == "deployed":
        expected_issues = {"node_modules/.pnpm/node_modules/@koda-fixture/modern"}
    else:
        expected_issues = set()
    issues = {issue["path"] for issue in collection["issues"] if issue.get("collector") == "filesystem"}
    validation = validate(result)
    assert validation == {"schemas": "passed", "checksums": 5}, validation
    errors = (
        "duplicateOccurrences", "missingPackages", "unexpectedPackages", "missingEdges", "unexpectedEdges", "danglingEdges",
    )
    expected_status = "partial" if expected_issues else "completed"
    passed = collection["status"] == expected_status and issues == expected_issues and all(
        not row[error] for row in formats.values() for error in errors
    )
    return {
        "passed": passed,
        "exitCode": exit_code,
        "collectionStatus": collection["status"],
        "boundaryIssues": sorted(issues),
        "missingBoundaryIssues": sorted(expected_issues - issues),
        "unexpectedBoundaryIssues": sorted(issues - expected_issues),
        "validation": validation,
        "expectedEdges": sorted(expected_edges),
        "formatParity": formats["cdx"] == formats["spdx"],
        "formats": formats,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Linux amd64 koda-bom executable")
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--prepare-fixture", action="store_true", help="Install pinned projects and produce an isolated deployment")
    parser.add_argument("--pnpm", default="pnpm", help=f"pnpm {PNPM_VERSION} executable")
    parser.add_argument("--node", default="node", help="Node executable used to verify independent require.resolve results")
    parser.add_argument("--image", default="debian:bookworm-slim", help="preloaded linux/amd64 image")
    parser.add_argument("--keep-sboms", type=Path)
    parser.add_argument("--output", type=Path, help="write JSON verification report")
    parser.add_argument("--baseline", action="store_true", help="record results even when the expected graph is missing")
    args = parser.parse_args()
    root = args.fixture_dir.resolve()
    binary = args.binary.resolve(strict=True)
    if args.prepare_fixture:
        create_fixture(root, args.pnpm)
    with TemporaryDirectory(prefix="koda-pnpm-sbom-") as temp:
        output = args.keep_sboms.resolve() if args.keep_sboms else Path(temp)
        output.mkdir(parents=True, exist_ok=True)
        cases = {name: case_result(root, name, binary, output, args.image, args.node) for name in CASES}
        report = {
            "passed": all(case["passed"] and case["formatParity"] for case in cases.values()),
            "architecture": "linux/amd64",
            "network": "none",
            "pnpmVersion": PNPM_VERSION,
            "nodeVersion": subprocess.check_output([args.node, "--version"], text=True).strip(),
            "binarySHA256": sha256(binary),
            "cases": cases,
        }
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "expectedEdges": {name: len(case["expectedEdges"])
                      for name, case in cases.items()}}, indent=2))
    return 0 if report["passed"] or args.baseline else 1


if __name__ == "__main__":
    raise SystemExit(main())
