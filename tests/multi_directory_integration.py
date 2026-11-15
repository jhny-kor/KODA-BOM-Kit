#!/usr/bin/env python3
"""Verify that one offline SBOM keeps evidence from each requested directory."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

from validate_outputs import validate


APP = "/fixtures/z-private app"
RUNTIME = "/fixtures/a-private-runtime"
JQUERY = "pkg:npm/jquery@3.7.1"
OLD_JQUERY = "pkg:npm/jquery@2.2.4"
SHARED = "pkg:npm/multi-shared@1.2.3"
PY_CLIENT = "pkg:pypi/multi-client@2.0.0"
PY_COMMON = "pkg:pypi/multi-common@1.0.0"
RETAINED = {"pkg:npm/app-logs-retained@1.0.0", "pkg:npm/runtime-cache-retained@1.0.0"}
EXCLUDED_NAMES = (
    "app-cache-excluded", "runtime-logs-excluded", "app-glob-excluded",
    "runtime-glob-excluded", "outside-all-targets", "old-output-canary",
)


def put_package(root, directory, name, version="1.0.0"):
    package = root / directory / "node_modules" / name / "package.json"
    package.parent.mkdir(parents=True)
    package.write_text(json.dumps({"name": name, "version": version}), encoding="utf-8")


def put_fixtures(fixtures):
    app, runtime = (fixtures / Path(target).name for target in (APP, RUNTIME))
    for root in (app, runtime):
        (root / "assets").mkdir(parents=True)
        (root / "assets/jquery.min.js").write_text("/*! jQuery v3.7.1 | jquery.com */", encoding="utf-8")
        put_package(root, "lib", "multi-shared", "1.2.3")
        site = root / "lib/python3.11/site-packages"
        for name, version, dependency in (
            ("multi_client", "2.0.0", "Requires-Dist: multi-common (>=1.0)\n"),
            ("multi_common", "1.0.0", ""),
        ):
            metadata = site / f"{name}-{version}.dist-info/METADATA"
            metadata.parent.mkdir(parents=True)
            display_name = name.replace("_", "-")
            metadata.write_text(f"Metadata-Version: 2.1\nName: {display_name}\nVersion: {version}\n{dependency}", encoding="utf-8")
    put_package(app, "logs", "app-logs-retained")
    put_package(runtime, "cache [old]", "runtime-cache-retained")
    put_package(app, "cache [old]", "app-cache-excluded")
    put_package(runtime, "logs", "runtime-logs-excluded")
    put_package(app, "generated-app", "app-glob-excluded")
    put_package(runtime, "generated-runtime", "runtime-glob-excluded")
    put_package(fixtures, "outside", "outside-all-targets")
    with zipfile.ZipFile(runtime / "app.war", "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/jquery.min.js", "/*! jQuery v2.2.4 | jquery.com */")
    (app / "outside-link").symlink_to("/fixtures/outside", target_is_directory=True)
    (app / "runtime-logs-link").symlink_to(RUNTIME + "/logs", target_is_directory=True)
    (fixtures / "duplicate-alias").symlink_to(APP, target_is_directory=True)


def read_document(result, filename):
    return json.loads((result / filename).read_text(encoding="utf-8"))


def verify(result):
    formats = ("sbom.cdx.json", "sbom.spdx.json", "inventory.syft.json")
    for filename in (*formats, "collection.json", "context.json"):
        raw = (result / filename).read_text(encoding="utf-8")
        assert all(value not in raw for value in ("/fixtures/", Path(APP).name, Path(RUNTIME).name)), filename
        assert all(name not in raw for name in EXCLUDED_NAMES), filename
    schemas = validate(result)
    cdx = read_document(result, "sbom.cdx.json")
    spdx = read_document(result, "sbom.spdx.json")
    expected = {
        JQUERY: {"target-1/assets/jquery.min.js", "target-2/assets/jquery.min.js"},
        OLD_JQUERY: {"target-2/app.war!/assets/jquery.min.js"},
        SHARED: {"target-1/lib/node_modules/multi-shared/package.json",
                 "target-2/lib/node_modules/multi-shared/package.json"},
    }
    for purl, directory in ((PY_CLIENT, "multi_client-2.0.0.dist-info"), (PY_COMMON, "multi_common-1.0.0.dist-info")):
        expected[purl] = {f"target-{index}/lib/python3.11/site-packages/{directory}/METADATA" for index in (1, 2)}
    cdx_identities = {item.get("purl") for item in cdx["components"]}
    assert cdx_identities == set(expected) | RETAINED, cdx_identities
    cdx_refs, spdx_refs = {}, {}
    for purl, paths in expected.items():
        component, = (item for item in cdx["components"] if item.get("purl") == purl)
        assert {item["location"] for item in component["evidence"]["occurrences"]} == paths, component
        package, = (
            item for item in spdx["packages"]
            if any(ref["referenceType"] == "purl" and ref["referenceLocator"] == purl
                   for ref in item.get("externalRefs", []))
        )
        assert set(json.loads(package["comment"])["evidencePaths"]) == paths, package
        cdx_refs[purl], spdx_refs[purl] = component["bom-ref"], package["SPDXID"]
    cdx_relation, = (row for row in cdx["dependencies"] if row["ref"] == cdx_refs[PY_CLIENT])
    assert cdx_relation["dependsOn"] == [cdx_refs[PY_COMMON]], cdx_relation
    spdx_relation, = (row for row in spdx["relationships"] if row["relationshipType"] == "DEPENDENCY_OF")
    assert spdx_relation["spdxElementId"] == spdx_refs[PY_COMMON], spdx_relation
    assert spdx_relation["relatedSpdxElement"] == spdx_refs[PY_CLIENT], spdx_relation

    collection = read_document(result, "collection.json")
    assert collection["source"] == {"type": "filesystem", "path": "."}, collection["source"]
    app, runtime = collection["targets"]
    assert app["id"] == "target-1" and runtime["id"] == "target-2", (app, runtime)
    assert app["excludedDirectories"] == ["cache [old]"], app
    assert runtime["excludedDirectories"] == ["logs"], runtime
    assert app["filesystemFileCount"] == 5 and runtime["filesystemFileCount"] == 6, (app, runtime)
    assert collection["filesystemFileCount"] == 11 and collection["limits"]["maxFiles"] == 11, collection
    assert app["packageCount"] == 5 and runtime["packageCount"] == 6, (app, runtime)
    assert collection["packageCount"] == 7, collection
    assert app["status"] == collection["status"] == "partial", collection
    assert runtime["status"] == "completed", runtime
    assert any(issue.get("path") == "target-1/outside-link" for issue in collection["issues"]), collection["issues"]
    context = read_document(result, "context.json")
    assert context["mode"] == context["status"] == "disabled", context
    return {"validation": schemas, "fileCount": collection["filesystemFileCount"], "packageCount": collection["packageCount"]}


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
summaries = {}
for filename in ("sbom.cdx.json", "sbom.spdx.json"):
    bom, _ = parse_sbom((result / filename).read_bytes())
    evidence, root = coverage_for_bom(bom)
    coverage = evidence["collectionCoverage"]
    assert coverage["sourceType"] == "filesystem" and coverage["status"] == "partial", coverage
    assert coverage["componentCount"] == 7 and coverage["excludedDirectoryCount"] == 2, coverage
    assert (root is not None) == filename.endswith(".spdx.json"), root
    purls = sorted(item["purl"] for item in bom["components"] if item.get("purl"))
    assert len(purls) == 7 and purls.count("pkg:npm/jquery@3.7.1") == 1, purls
    summaries[filename] = {"coverage": coverage, "purls": purls}
assert summaries["sbom.cdx.json"] == summaries["sbom.spdx.json"], summaries
print(json.dumps(summaries))
"""
    process = subprocess.run(
        [str(tracker_root / ".venv/bin/python"), "-c", script, str(tracker_root), str(result)],
        capture_output=True, text=True, timeout=60,
    )
    assert process.returncode == 0, (process.stdout, process.stderr)
    return json.loads(process.stdout)


def exercise(stage, tracker_root=None):
    stage = stage.resolve(strict=True)
    binary = stage / "koda-sbom"
    assert binary.is_file(), binary
    with tempfile.TemporaryDirectory(prefix="koda-multi-directory-") as temporary:
        work = Path(temporary)
        fixtures, output = work / "fixtures", work / "output"
        fixtures.mkdir()
        output.mkdir()
        output.chmod(0o777)
        put_fixtures(fixtures)

        def invoke(options, name, expected, *, in_target=False):
            output_path = f"/results/{name}"
            mounts = []
            if in_target:
                output_path = f"{APP}/local-results"
                (fixtures / Path(APP).name / "local-results").mkdir()
                put_package(output / name, "", "old-output-canary", "8.0.0")
                (output / name).chmod(0o777)
                mounts = ["--mount", f"type=bind,src={output / name},dst={output_path}"]
            command = [
                "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "65534:65534", "--cpus", "2", "--memory", "1536m",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
                "--mount", f"type=bind,src={stage},dst=/release,readonly",
                "--mount", f"type=bind,src={fixtures},dst=/fixtures,readonly",
                "--mount", f"type=bind,src={output},dst=/results", *mounts,
                "debian:bookworm-slim", "/release/koda-sbom", "scan",
                "--output-dir", output_path, *options,
            ]
            process = subprocess.run(command, capture_output=True, text=True, timeout=180)
            assert process.returncode == expected, (name, process.returncode, process.stdout, process.stderr)
            return process

        targets = ["--target", APP, "--target", RUNTIME]
        excludes = [
            "--exclude-dir", f"{APP}/cache [old]", "--exclude-dir", f"{RUNTIME}/logs",
            "--exclude", "**/generated-*",
        ]
        success = invoke([*targets, *excludes, "--max-files", "11"], "combined", 3)
        result, = (output / "combined").iterdir()
        assert success.stdout.splitlines()[-1] == f"/results/combined/{result.name}", success.stdout
        verified = verify(result)
        if tracker_root is not None:
            verified["tracker"] = verify_tracker(tracker_root, result)

        invoke([*targets, *excludes, "--max-files", "11"], "local-results", 3, in_target=True)
        local_result, = (output / "local-results").glob("koda-sbom-*")
        verify(local_result)
        local_scopes = read_document(local_result, "collection.json")["targets"]
        assert "/local-results" in local_scopes[0]["excludedPaths"]
        assert "/local-results" not in local_scopes[1]["excludedPaths"]

        # One limit is crossed within the second root. The other is exhausted
        # after the first root and must not turn into an unlimited second scan.
        for limit in (10, 5):
            name = f"aggregate-limit-{limit}"
            limited = invoke([*targets, *excludes, "--max-files", str(limit)], name, 2)
            limited_parent = output / name
            assert not list(limited_parent.rglob("sbom.*.json")), limited.stdout
            reports = list(limited_parent.rglob("collection.json"))
            if reports:
                report_path, = reports
                report = json.loads(report_path.read_text(encoding="utf-8"))
                assert report["status"] == "failed", report
                assert any(
                    issue.get("code") == "file_limit_exceeded"
                    and issue.get("limit") == limit and issue.get("observed") == limit + 1
                    for issue in report["issues"]
                ), report["issues"]
            else:
                assert f"limit={limit}" in limited.stderr and f"observed={limit + 1}" in limited.stderr, limited.stderr

        invalid_options = [
            ["--target", APP, "--target", APP],
            ["--target", APP, "--target", "/fixtures/duplicate-alias"],
            ["--target", APP, "--target", f"{APP}/assets"],
            ["--target", APP, "--target", "/fixtures/missing"],
            ["--target", APP, "--target", "/"],
            [*targets, "--exclude-dir", "logs"],
            [*targets, "--exclude-dir", "/fixtures/outside"],
            [*targets, "--exclude-dir", APP],
            [*targets, "--image-archive", "/fixtures/image.tar"],
            [*targets, "--exclude", "["],
        ]
        for index, options in enumerate(invalid_options):
            name = f"invalid-{index}"
            rejected = invoke(options, name, 2)
            assert rejected.stderr.strip() and not rejected.stdout.strip(), (options, rejected)
            assert not (output / name).exists(), options
    return {
        "passed": True,
        "architecture": "linux/amd64",
        "network": "none",
        "rootfs": "read-only",
        "binarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "combined": verified,
        "aggregateFileLimit": "passed",
        "outputWithinTarget": "passed",
        "invalidCases": len(invalid_options),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    parser.add_argument("--tracker-root", type=Path, help="Optional local Tracker checkout with an initialized .venv")
    args = parser.parse_args()
    print(json.dumps(exercise(args.stage, args.tracker_root), ensure_ascii=False, indent=2))
