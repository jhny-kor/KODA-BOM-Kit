#!/usr/bin/env python3
"""Verify peer bindings against real pnpm package instances and Node resolution."""

import argparse
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from pnpm_workspace_integration import (
    PNPM_VERSION,
    compare_format,
    npm_purl,
    read_cyclonedx,
    read_json,
    read_spdx,
    run_scan,
    sha256,
    write_package,
)
from validate_outputs import validate

CONSUMER = "@koda-peer/consumer"
APPS = {
    "old": {CONSUMER: "workspace:*", "is-number": "4.0.0"},
    "new": {CONSUMER: "workspace:*", "is-number": "6.0.0", "is-odd": "3.0.1"},
}
PEERS = {"is-number": "^4 || ^6", "is-odd": "^3", "missing-koda-peer": "*"}
OPTIONAL_PEERS = ("is-odd", "missing-koda-peer")
OUTSIDE_PEER = "koda-outside-peer"
EXCLUDED_PEER = "koda-excluded-peer"
REENTRY_PEER = "koda-reentry-peer"
WRONG_VERSION_PEER = "koda-wrong-version-peer"
FAR_OPTIONAL_PEER = "koda-far-optional-peer"
CANARIES = (OUTSIDE_PEER, EXCLUDED_PEER, REENTRY_PEER)
VIRTUAL_STORE = Path("node_modules/.pnpm")
OLD_INSTANCE = "@koda-peer+consumer@file+packages+consumer_is-number@4.0.0"
NEW_INSTANCE = "@koda-peer+consumer@file+packages+consumer_is-number@6.0.0_is-odd@3.0.1"
NODE_RESOLVE = """
const {createRequire} = require('node:module');
const queries = JSON.parse(process.argv[1]);
console.log(JSON.stringify(queries.map(({manifest, name}) => {
  try {
    return createRequire(manifest).resolve(name + '/package.json');
  } catch (err) {
    if (err.code !== 'MODULE_NOT_FOUND') throw err;
    return null;
  }
})));
"""


def replace_manifest(path, change):
    manifest = read_json(path)
    change(manifest)
    temporary = path.with_name("package.json.test-copy")
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def install_fixture(root, pnpm, layout_settings=""):
    version = subprocess.check_output([pnpm, "--version"], text=True, timeout=20).strip()
    assert version == PNPM_VERSION, (version, PNPM_VERSION)
    workspace = root / "workspace"
    workspace.mkdir(parents=True)
    (workspace / "pnpm-workspace.yaml").write_text(
        "packages:\n"
        "  - 'packages/*'\n"
        "injectWorkspacePackages: true\n"
        "dedupeInjectedDeps: false\n"
        "dedupePeerDependents: false\n"
        "resolvePeersFromWorkspaceRoot: false\n"
        "autoInstallPeers: false\n"
        "hoist: false\n" + layout_settings,
        encoding="utf-8",
    )
    write_package(workspace, "@koda-peer/workspace", "1.0.0")
    for app, dependencies in APPS.items():
        write_package(workspace / "packages" / app, f"@koda-peer/{app}", "1.0.0", dependencies)
    source = workspace / "packages/consumer"
    write_package(source, CONSUMER, "1.0.0")
    replace_manifest(source / "package.json", lambda manifest: manifest.update(
        peerDependencies=PEERS, peerDependenciesMeta={peer: {"optional": True} for peer in OPTIONAL_PEERS},
    ))

    common = ["--ignore-scripts", "--store-dir", str(root / "store")]
    commands = [
        [pnpm, "install", "--no-frozen-lockfile", *common],
        [pnpm, "--filter", "@koda-peer/new", "deploy", "--prod", *common, str(root / "deployed-default")],
    ]
    env = {**os.environ, "CI": "true", "NO_UPDATE_NOTIFIER": "1"}
    for index, command in enumerate(commands, 1):
        result = subprocess.run(command, cwd=workspace, env=env, capture_output=True, text=True, timeout=120, check=False)
        log = root / f"pnpm-{index}.log"
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        assert result.returncode == 0, log.read_text(encoding="utf-8")


def create_fixture(root, pnpm):
    install_fixture(root, pnpm)
    add_scope_canaries(root, VIRTUAL_STORE)


def add_scope_canaries(root, store):
    workspace = root / "workspace"
    # Mutate one installed instance without changing the actual pnpm layouts
    # and without modifying any content-addressed files shared between copies.
    destinations = {
        OUTSIDE_PEER: root / "outside" / OUTSIDE_PEER,
        EXCLUDED_PEER: workspace / "private-cache" / EXCLUDED_PEER,
        REENTRY_PEER: workspace / "return-target" / REENTRY_PEER,
    }
    old_modules = workspace / store / OLD_INSTANCE / "node_modules"
    for name, destination in destinations.items():
        write_package(destination, name, "9.0.0")
        write_package(workspace / "node_modules" / name, name, "1.0.0")
        near = destination
        if name == REENTRY_PEER:
            near = root / "outside" / "relay"
            near.symlink_to(os.path.relpath(destination, near.parent), target_is_directory=True)
        (old_modules / name).symlink_to(os.path.relpath(near, old_modules), target_is_directory=True)
    write_package(old_modules / WRONG_VERSION_PEER, WRONG_VERSION_PEER, "2.0.0")
    write_package(workspace / "node_modules" / WRONG_VERSION_PEER, WRONG_VERSION_PEER, "1.0.0")
    write_package(workspace / store / "node_modules" / FAR_OPTIONAL_PEER, FAR_OPTIONAL_PEER, "1.0.0")

    def add_canaries(manifest):
        manifest["peerDependencies"].update(dict.fromkeys(CANARIES, "*"))
        manifest["peerDependencies"][WRONG_VERSION_PEER] = "^1.0.0"
        manifest["peerDependencies"][FAR_OPTIONAL_PEER] = "^1.0.0"
        manifest["peerDependenciesMeta"].update({
            REENTRY_PEER: {"optional": True}, FAR_OPTIONAL_PEER: {"optional": True},
        })

    replace_manifest(old_modules / CONSUMER / "package.json", add_canaries)


def default_model(root, store=VIRTUAL_STORE):
    deployment = root
    consumer_link = deployment / "node_modules" / CONSUMER
    assert consumer_link.is_symlink(), consumer_link
    consumer = (consumer_link / "package.json").resolve(strict=True).relative_to(deployment)
    assert consumer.is_relative_to(store), consumer
    app = Path("package.json")
    is_odd = store / "is-odd@3.0.1/node_modules/is-odd/package.json"
    number6 = store / "is-number@6.0.0/node_modules/is-number/package.json"
    paths = {
        app: ("@koda-peer/new", "1.0.0"),
        consumer: (CONSUMER, "1.0.0"),
        number6: ("is-number", "6.0.0"),
        is_odd: ("is-odd", "3.0.1"),
    }
    regular = [(app, consumer), (app, number6), (app, is_odd), (is_odd, number6)]
    peers = [(consumer, number6), (consumer, is_odd)]
    absent = [(consumer, "missing-koda-peer")]
    return paths, regular, peers, absent, []


def workspace_model(store=VIRTUAL_STORE):
    old = Path("packages/old/package.json")
    new = Path("packages/new/package.json")
    old_modules = store / OLD_INSTANCE / "node_modules"
    old_copy = old_modules / CONSUMER / "package.json"
    new_copy = store / NEW_INSTANCE / "node_modules" / CONSUMER / "package.json"
    source = Path("packages/consumer/package.json")
    is_odd = store / "is-odd@3.0.1/node_modules/is-odd/package.json"
    number4 = store / "is-number@4.0.0/node_modules/is-number/package.json"
    number6 = store / "is-number@6.0.0/node_modules/is-number/package.json"
    paths = {
        Path("package.json"): ("@koda-peer/workspace", "1.0.0"),
        old: ("@koda-peer/old", "1.0.0"),
        new: ("@koda-peer/new", "1.0.0"),
        source: (CONSUMER, "1.0.0"),
        old_copy: (CONSUMER, "1.0.0"),
        new_copy: (CONSUMER, "1.0.0"),
        number4: ("is-number", "4.0.0"),
        number6: ("is-number", "6.0.0"),
        is_odd: ("is-odd", "3.0.1"),
        Path(f"return-target/{REENTRY_PEER}/package.json"): (REENTRY_PEER, "9.0.0"),
        old_modules / WRONG_VERSION_PEER / "package.json": (WRONG_VERSION_PEER, "2.0.0"),
        store / "node_modules" / FAR_OPTIONAL_PEER / "package.json": (FAR_OPTIONAL_PEER, "1.0.0"),
    }
    for name in (*CANARIES, WRONG_VERSION_PEER):
        paths[Path(f"node_modules/{name}/package.json")] = (name, "1.0.0")
    regular = [(old, old_copy), (old, number4), (new, new_copy), (new, number6), (new, is_odd), (is_odd, number6)]
    peers = [(old_copy, number4), (new_copy, number6), (new_copy, is_odd)]
    absent = [
        (old_copy, "is-odd"), (old_copy, "missing-koda-peer"), (new_copy, "missing-koda-peer"),
        (source, "is-number"), (source, "is-odd"), (source, "missing-koda-peer"),
    ]
    rejected = [
        (old_copy, OUTSIDE_PEER, Path(f"../outside/{OUTSIDE_PEER}/package.json")),
        (old_copy, EXCLUDED_PEER, Path(f"private-cache/{EXCLUDED_PEER}/package.json")),
        (old_copy, REENTRY_PEER, Path(f"return-target/{REENTRY_PEER}/package.json")),
        (old_copy, WRONG_VERSION_PEER, old_modules / WRONG_VERSION_PEER / "package.json"),
        (old_copy, FAR_OPTIONAL_PEER, store / "node_modules" / FAR_OPTIONAL_PEER / "package.json"),
    ]
    return paths, regular, peers, absent, rejected


def match_node(root, node, paths, regular, peers, absent, rejected):
    bound = [(source, paths[target][0], target) for source, target in [*regular, *peers]]
    missing = [(source, name, None) for source, name in absent]
    expected = [*bound, *missing, *rejected]
    queries = [{"manifest": str(root / source), "name": name} for source, name, _ in expected]
    env = os.environ.copy()
    env.pop("NODE_PATH", None)
    env.pop("NODE_OPTIONS", None)
    result = subprocess.run([node, "-e", NODE_RESOLVE, json.dumps(queries)], env=env,
                            capture_output=True, text=True, timeout=20, check=True)
    for actual, (source, name, target) in zip(json.loads(result.stdout), expected, strict=True):
        intended = str((root / target).resolve(strict=True)) if target else None
        assert actual == intended, (source, name, actual, intended)
    for location, identity in paths.items():
        manifest = read_json(root / location)
        assert (manifest["name"], manifest["version"]) == identity, (location, identity)


def expected_case(root, case, node):
    if case == "combined":
        packages, edges, peers, issues = set(), set(), set(), set()
        for index, target in enumerate(("workspace", "deployed-default"), start=1):
            scoped_packages, scoped_edges, scoped_peers, scoped_issues = expected_case(root, target, node)
            prefix = f"target-{index}/"
            packages.update((purl, prefix + path) for purl, path in scoped_packages)
            edges.update((first, prefix + left, second, prefix + right) for first, left, second, right in scoped_edges)
            peers.update((first, prefix + left, second, prefix + right) for first, left, second, right in scoped_peers)
            issues.update(prefix + path for path in scoped_issues)
        return packages, edges, peers, issues

    paths, regular, peers, absent, rejected = workspace_model() if case == "workspace" else default_model(root / case)
    match_node(root / case, node, paths, regular, peers, absent, rejected)
    packages = {(npm_purl(*identity), path.as_posix()) for path, identity in paths.items()}

    def edge(source, target):
        return (npm_purl(*paths[source]), source.as_posix(), npm_purl(*paths[target]), target.as_posix())

    peer_edges = {edge(source, target) for source, target in peers}
    expected_edges = peer_edges | {edge(source, target) for source, target in regular}
    issues = {str(VIRTUAL_STORE / OLD_INSTANCE / "node_modules" / name) for name in CANARIES} if case == "workspace" else set()
    return packages, expected_edges, peer_edges, issues


def run_combined_scan(root, binary, out, image):
    out.mkdir(mode=0o777)
    out.chmod(0o777)
    command = [
        "docker", "run", "--rm", "--pull", "never", "--platform", "linux/amd64", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--mount", f"type=bind,src={root},dst=/fixture,readonly",
        "--mount", f"type=bind,src={binary},dst=/koda-bom,readonly",
        "--mount", f"type=bind,src={out},dst=/output",
        image, "/koda-bom", "scan", "--output-dir", "/output", "--no-context", "--format", "both",
        "--target", "/fixture/workspace", "--target", "/fixture/deployed-default",
        "--exclude-dir", "/fixture/workspace/private-cache",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 3, (result.returncode, result.stdout, result.stderr)
    run_dir, = out.iterdir()
    return run_dir, result.returncode


def case_result(root, case, binary, out, image, node):
    packages, expected_edges, peer_edges, issues = expected_case(root, case, node)
    consumer_purl = npm_purl(CONSUMER, "1.0.0")
    expected_consumer_refs = sum(purl == consumer_purl for purl, _ in packages)

    if case == "combined":
        result, exit_code = run_combined_scan(root, binary, out / case, image)
    else:
        result, exit_code = run_scan(root, binary, out / case, case, image)
    collection = read_json(result / "collection.json")
    boundary_issues = {issue["path"] for issue in collection["issues"] if issue.get("collector") == "filesystem"}
    if case == "workspace":
        assert collection["excludedDirectories"] == ["private-cache"], collection
    elif case == "combined":
        assert len(collection["targets"]) == 2, collection
        assert collection["targets"][0]["excludedDirectories"] == ["private-cache"], collection
    verification = validate(result)
    assert verification == {"schemas": "passed", "checksums": 5}, verification

    formats = {}
    errors = ("duplicateOccurrences", "missingPackages", "unexpectedPackages", "missingEdges",
              "unexpectedEdges", "danglingEdges")
    passed = collection["status"] == ("partial" if issues else "completed") and boundary_issues == issues
    for fmt, reader in (("cdx", read_cyclonedx), ("spdx", read_spdx)):
        path = result / f"sbom.{fmt}.json"
        raw = path.read_text(encoding="utf-8")
        for marker in ("/fixture/", str(root), f"outside/{OUTSIDE_PEER}", "outside/relay", "private-cache/"):
            assert marker not in raw, (case, fmt, marker)
        inventory, relations, root_ref = reader(path)
        comparison = compare_format(inventory, relations, root_ref, packages, expected_edges)
        consumer_refs = [ref for ref, purl, _ in inventory if purl == consumer_purl]
        comparison["consumerRefCount"] = len(consumer_refs)
        comparison["resolvedPeerEdges"] = sorted(set(comparison["observedEdges"]) & peer_edges)
        passed = (
            passed and len(consumer_refs) == expected_consumer_refs and comparison["npmPackages"] == len(packages)
            and all(not comparison[error] for error in errors)
        )
        formats[fmt] = comparison

    return {
        "passed": passed and formats["cdx"] == formats["spdx"],
        "exitCode": exit_code,
        "collectionStatus": collection["status"],
        "boundaryIssues": sorted(boundary_issues),
        "expectedBoundaryIssues": sorted(issues),
        "expectedConsumerRefCount": expected_consumer_refs,
        "expectedPeerEdges": sorted(peer_edges),
        "expectedAllEdges": sorted(expected_edges),
        "validation": verification,
        "formats": formats,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="Linux amd64 koda-bom executable")
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--prepare-fixture", action="store_true", help="Install and deploy the test workspace with pnpm")
    parser.add_argument("--pnpm", default="pnpm", help=f"pnpm {PNPM_VERSION} executable")
    parser.add_argument("--node", default="node", help="Node executable used to verify require.resolve")
    parser.add_argument("--image", default="debian:bookworm-slim", help="preloaded linux/amd64 image")
    parser.add_argument("--keep-sboms", type=Path)
    parser.add_argument("--output", type=Path, help="write the JSON verification report")
    parser.add_argument("--baseline", action="store_true", help="record results even when the expected graph is missing")
    args = parser.parse_args()
    root = args.fixture_dir.resolve()
    binary = args.binary.resolve(strict=True)
    if args.prepare_fixture:
        create_fixture(root, args.pnpm)
    with TemporaryDirectory(prefix="koda-pnpm-peer-sbom-") as temporary:
        out = args.keep_sboms.resolve() if args.keep_sboms else Path(temporary)
        out.mkdir(parents=True, exist_ok=True)
        cases = {name: case_result(root, name, binary, out, args.image, args.node)
                 for name in ("workspace", "deployed-default", "combined")}
    report = {
        "passed": all(case["passed"] for case in cases.values()),
        "architecture": "linux/amd64",
        "network": "none",
        "pnpmVersion": PNPM_VERSION,
        "nodeVersion": subprocess.check_output([args.node, "--version"], text=True).strip(),
        "binarySHA256": sha256(binary),
        "cases": cases,
    }
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "passed": report["passed"],
        "peerEdges": {name: {fmt: len(row["resolvedPeerEdges"]) for fmt, row in case["formats"].items()}
                      for name, case in cases.items()},
    }, indent=2))
    return 0 if report["passed"] or args.baseline else 1


if __name__ == "__main__":
    raise SystemExit(main())
