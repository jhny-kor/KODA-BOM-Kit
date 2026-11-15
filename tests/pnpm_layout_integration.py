#!/usr/bin/env python3
"""Check installed peer graphs for pnpm custom and hoisted layouts."""

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from pnpm_peer_integration import (
    CANARIES,
    CONSUMER,
    OLD_INSTANCE,
    OUTSIDE_PEER,
    WRONG_VERSION_PEER,
    add_scope_canaries,
    default_model,
    install_fixture,
    match_node,
    replace_manifest,
    workspace_model,
)
from pnpm_workspace_integration import (
    PNPM_VERSION,
    compare_format,
    npm_purl,
    read_cyclonedx,
    read_json,
    read_spdx,
    run_target_scan,
    sha256,
)
from validate_outputs import validate

CUSTOM_STORE = Path("vendor/virtual-store")
BAD_MANIFEST = "koda-unreadable-peer"
MISSING = "koda-missing-required-peer"
ABSENT_OPTIONAL = "missing-koda-peer"
TARGETS = (
    "custom/workspace", "custom/deployed-custom", "custom/workspace/packages/old",
    "hoisted/workspace", "hoisted/deployed-default", "hoisted/deployed-boundary",
)


def prepare_fixture(root, pnpm):
    custom = root / "custom"
    install_fixture(custom, pnpm, f"virtualStoreDir: {CUSTOM_STORE.as_posix()}\n")
    install_fixture(root / "hoisted", pnpm, "nodeLinker: hoisted\n")

    # Standalone deploy defaults back to .pnpm. Reinstall its production
    # manifest and lockfile in a clean directory with the custom layout.
    deployed = custom / "deployed-custom"
    deployed.mkdir()
    for filename in ("package.json", "pnpm-lock.yaml", "index.js"):
        shutil.copyfile(custom / "deployed-default" / filename, deployed / filename)
    (deployed / "pnpm-workspace.yaml").write_text(
        f"virtualStoreDir: {CUSTOM_STORE.as_posix()}\nhoist: false\nautoInstallPeers: false\n", encoding="utf-8",
    )
    command = [pnpm, "install", "--frozen-lockfile", "--offline", "--prod", "--ignore-scripts",
               "--store-dir", str(custom / "store")]
    env = {**os.environ, "CI": "true", "NO_UPDATE_NOTIFIER": "1"}
    result = subprocess.run(command, cwd=deployed, env=env, capture_output=True, text=True, timeout=120, check=False)
    (custom / "pnpm-custom-deploy.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    assert result.returncode == 0, (result.stdout, result.stderr)

    add_scope_canaries(custom, CUSTOM_STORE)
    old_modules = custom / "workspace" / CUSTOM_STORE / OLD_INSTANCE / "node_modules"
    broken = old_modules / BAD_MANIFEST / "package.json"
    broken.parent.mkdir()
    broken.write_text("{invalid JSON\n", encoding="utf-8")

    def add_diagnostic_cases(manifest):
        manifest["peerDependencies"].update({MISSING: "^1", BAD_MANIFEST: "^1"})

    replace_manifest(old_modules / CONSUMER / "package.json", add_diagnostic_cases)

    hoisted = root / "hoisted"
    boundary = hoisted / "deployed-boundary"
    shutil.copytree(hoisted / "deployed-default", boundary, symlinks=True)
    for name, destination in (
        ("is-odd", hoisted / "outside" / "is-odd"),
        ("is-number", boundary / "private-cache" / "is-number"),
    ):
        location = boundary / "node_modules" / name
        destination.parent.mkdir()
        location.rename(destination)
        location.symlink_to(os.path.relpath(destination, location.parent), target_is_directory=True)


def hoisted_model(workspace):
    app = Path("packages/new/package.json" if workspace else "package.json")
    consumer = Path("node_modules") / CONSUMER / "package.json"
    number6 = Path("node_modules/is-number/package.json")
    is_odd = Path("node_modules/is-odd/package.json")
    paths = {
        app: ("@koda-peer/new", "1.0.0"), consumer: (CONSUMER, "1.0.0"),
        number6: ("is-number", "6.0.0"), is_odd: ("is-odd", "3.0.1"),
    }
    regular = [(app, consumer), (app, number6), (app, is_odd), (is_odd, number6)]
    peers = [(consumer, number6), (consumer, is_odd)]
    absent = [(consumer, ABSENT_OPTIONAL)]
    rejected = []
    if workspace:
        old = Path("packages/old/package.json")
        old_consumer = Path("packages/old/node_modules") / CONSUMER / "package.json"
        number4 = Path("packages/old/node_modules/is-number/package.json")
        source = Path("packages/consumer/package.json")
        paths.update({
            old: ("@koda-peer/old", "1.0.0"), old_consumer: (CONSUMER, "1.0.0"),
            number4: ("is-number", "4.0.0"), source: (CONSUMER, "1.0.0"),
            Path("package.json"): ("@koda-peer/workspace", "1.0.0"),
        })
        regular.extend([(old, old_consumer), (old, number4)])
        peers.append((old_consumer, number4))
        absent.extend([(old_consumer, ABSENT_OPTIONAL), (source, ABSENT_OPTIONAL)])
        # Node can see these runtime fallbacks, but pnpm did not assign them to
        # these contexts. The injected original has no installed peer context.
        rejected.extend([(old_consumer, "is-odd", is_odd), (source, "is-odd", is_odd), (source, "is-number", number6)])
    return paths, regular, peers, absent, rejected


def expected_model(root, target):
    if target == "custom/workspace/packages/old":
        return {Path("package.json"): ("@koda-peer/old", "1.0.0")}, [], [], [], []

    metadata = read_json(root / target / "node_modules/.modules.yaml")
    if target.startswith("hoisted/"):
        assert metadata["nodeLinker"] == "hoisted", metadata
        model = hoisted_model(target.endswith("/workspace"))
        if not target.endswith("deployed-boundary"):
            return model
        paths, regular, peers, absent, rejected = model
        providers = {
            Path("node_modules/is-number/package.json"): Path("private-cache/is-number/package.json"),
            Path("node_modules/is-odd/package.json"): Path("../outside/is-odd/package.json"),
        }
        for source, destination in [*regular, *peers]:
            if destination in providers and source not in providers:
                rejected.append((source, paths[destination][0], providers[destination]))
        for item in providers:
            del paths[item]
        return paths, [(source, destination) for source, destination in regular if destination in paths], [], absent, rejected

    assert metadata["nodeLinker"] == "isolated", metadata
    assert (root / target / "node_modules" / metadata["virtualStoreDir"]).resolve() == root / target / CUSTOM_STORE
    if target.endswith("/workspace"):
        paths, regular, peers, absent, rejected = workspace_model(CUSTOM_STORE)
        absent.append((CUSTOM_STORE / OLD_INSTANCE / "node_modules" / CONSUMER / "package.json", MISSING))
        return paths, regular, peers, absent, rejected
    return default_model(root / target, CUSTOM_STORE)


def verify_case(root, target, node, binary, out, image):
    paths, regular, peers, absent, rejected = expected_model(root, target)
    if target.endswith("/packages/old"):
        app = Path("package.json")
        virtual = Path("../../") / CUSTOM_STORE
        rejected.extend([
            (app, CONSUMER, virtual / OLD_INSTANCE / "node_modules" / CONSUMER / "package.json"),
            (app, "is-number", virtual / "is-number@4.0.0/node_modules/is-number/package.json"),
        ])
    match_node(root / target, node, paths, regular, peers, absent, rejected)
    packages = {(npm_purl(*identity), location.as_posix()) for location, identity in paths.items()}

    def occurrence_edge(source, destination):
        return (npm_purl(*paths[source]), source.as_posix(), npm_purl(*paths[destination]), destination.as_posix())

    peer_edges = {occurrence_edge(*edge) for edge in peers}
    expected_edges = peer_edges | {occurrence_edge(*edge) for edge in regular}
    boundary_issues = set()
    excludes = ()
    diagnostics = set()
    if target == "custom/workspace":
        boundary_issues = {(CUSTOM_STORE / OLD_INSTANCE / "node_modules" / name).as_posix() for name in CANARIES}
        excludes = ("private-cache",)
        consumer = (CUSTOM_STORE / OLD_INSTANCE / "node_modules" / CONSUMER / "package.json").as_posix()
        diagnostics = {
            ("npm_dependency_missing", consumer, MISSING),
            ("npm_dependency_version_mismatch", consumer, WRONG_VERSION_PEER),
            ("npm_dependency_manifest_unreadable", consumer, BAD_MANIFEST),
        }
        diagnostics.update(("npm_dependency_scope_blocked", consumer, name) for name in CANARIES)
    elif target.endswith("/packages/old"):
        boundary_issues = {f"node_modules/{name}" for name in (CONSUMER, "is-number")}
        diagnostics = {("npm_dependency_scope_blocked", "package.json", name) for name in (CONSUMER, "is-number")}
    elif target.endswith("deployed-boundary"):
        boundary_issues = {"node_modules/is-number", "node_modules/is-odd"}
        excludes = ("private-cache",)
        diagnostics = {("npm_dependency_scope_blocked", source, name)
                       for source in ("package.json", f"node_modules/{CONSUMER}/package.json")
                       for name in ("is-number", "is-odd")}
    result, exit_code = run_target_scan(root, binary, out, target, image, excludes, 3 if boundary_issues else 0)

    recorded = read_json(result / "collection.json")["issues"]
    observed_issues = {issue["path"] for issue in recorded if issue["collector"] == "filesystem"}
    observed_diagnostics = {
        (issue["code"], issue.get("path", ""), issue["message"].split(" — ", 1)[0])
        for issue in recorded if issue.get("code", "").startswith("npm_dependency_")
    }
    assert not any(ABSENT_OPTIONAL in issue.get("message", "") for issue in recorded), recorded
    verification = validate(result)
    assert verification == {"schemas": "passed", "checksums": 5}, verification

    formats = {}
    errors = ("duplicateOccurrences", "missingPackages", "unexpectedPackages", "missingEdges",
              "unexpectedEdges", "danglingEdges")
    passed = observed_issues == boundary_issues and diagnostics <= observed_diagnostics
    for name, reader in (("cdx", read_cyclonedx), ("spdx", read_spdx)):
        output = result / f"sbom.{name}.json"
        raw = output.read_text(encoding="utf-8")
        for marker in (str(root), "/fixture/", f"outside/{OUTSIDE_PEER}", "outside/relay", "outside/is-odd", "private-cache/"):
            assert marker not in raw, (target, name, marker)
        inventory, relations, root_ref = reader(output)
        comparison = compare_format(inventory, relations, root_ref, packages, expected_edges)
        comparison["resolvedPeerEdges"] = sorted(set(comparison["observedEdges"]) & peer_edges)
        passed = passed and comparison["npmPackages"] == len(packages) and all(not comparison[error] for error in errors)
        formats[name] = comparison

    return {
        "passed": passed and formats["cdx"] == formats["spdx"],
        "exitCode": exit_code,
        "boundaryIssues": sorted(observed_issues),
        "diagnosticCodes": sorted({code for code, path, name in observed_diagnostics}),
        "missingDiagnostics": sorted(diagnostics - observed_diagnostics),
        "expectedPeerEdges": sorted(peer_edges),
        "verification": verification,
        "formats": formats,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--fixture-dir", required=True, type=Path)
    parser.add_argument("--prepare-fixture", action="store_true")
    parser.add_argument("--pnpm", default="pnpm")
    parser.add_argument("--node", default="node")
    parser.add_argument("--image", default="debian:bookworm-slim")
    parser.add_argument("--keep-sboms", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    root = args.fixture_dir.resolve()
    binary = args.binary.resolve(strict=True)
    if args.prepare_fixture:
        prepare_fixture(root, args.pnpm)
    with TemporaryDirectory(prefix="koda-pnpm-layout-sboms-") as temporary:
        out = args.keep_sboms.resolve() if args.keep_sboms else Path(temporary)
        out.mkdir(parents=True, exist_ok=True)
        cases = {target: verify_case(root, target, args.node, binary, out / target.replace("/", "-"), args.image)
                 for target in TARGETS}
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
    print(json.dumps({"passed": report["passed"], "cases": {name: case["passed"] for name, case in cases.items()}}))
    return 0 if report["passed"] or args.baseline else 1


if __name__ == "__main__":
    raise SystemExit(main())
