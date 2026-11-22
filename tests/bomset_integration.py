#!/usr/bin/env python3
"""Exercise standalone BOM split/merge and scan exports through the public CLI."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from fixtures import make_tree
from validate_outputs import SCHEMAS, require, require_unoptimized, validate, validate_schema


PROFILES = ("sbom", "hbom", "cbom", "obom")


def read_document(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_document(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_checksums(directory):
    names = sorted(path.name for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text("".join(checksum(directory / name) + "  " + name + "\n" for name in names))


def entities(document):
    result = {}

    def visit(items):
        for item in items:
            if item.get("bom-ref"):
                require(item["bom-ref"] not in result, "duplicate entity reference")
                result[item["bom-ref"]] = item
            visit(item.get("components", []))
            visit(item.get("services", []))

    root = document.get("metadata", {}).get("component")
    visit(([root] if root else []) + document.get("components", []) + document.get("services", []))
    return result


def edges(document):
    return {(item["ref"], relation, target)
            for item in document.get("dependencies", [])
            for relation in ("dependsOn", "provides")
            for target in item.get(relation, [])}


def verify_references(document):
    known = entities(document)
    seen = set()
    for row in document.get("dependencies", []):
        require(row["ref"] in known and row["ref"] not in seen, "invalid dependency source")
        seen.add(row["ref"])
        for relation in ("dependsOn", "provides"):
            require(set(row.get(relation, [])) <= known.keys(), "unresolved dependency target")
    for row in document.get("compositions", []):
        for relation in ("assemblies", "dependencies"):
            require(set(row.get(relation, [])) <= known.keys(), "unresolved composition target")
    for node in known.values():
        crypto = node.get("cryptoProperties", {})
        for field in ("certificateProperties", "protocolProperties", "relatedCryptoMaterialProperties"):
            values = crypto.get(field, {})
            targets = [values[key] for key in ("signatureAlgorithmRef", "subjectPublicKeyRef", "algorithmRef") if key in values]
            targets.extend(values.get("cryptoRefArray", []))
            require(all(ref in known and known[ref]["type"] == "cryptographic-asset" for ref in targets),
                    "unresolved cryptographic reference")
    return known


def fixture(directory, marker="first", dual=True, operations=True):
    """Minimal recorded source with cross-category edges and two distinct roots."""
    directory.mkdir()
    primary = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "metadata": {"component": {"type": "application", "bom-ref": "inventory-root", "name": "inventory"},
                     "properties": [{"name": "fixture:collection", "value": marker}]},
        "components": [
            {"type": "application", "bom-ref": "application", "name": "sample", "version": marker,
             "components": [{"type": "library", "bom-ref": "nested-library", "name": "nested", "version": "1.0"}]},
            {"type": "library", "bom-ref": "installed-library", "name": "runtime-library", "version": "1.0",
             "purl": "pkg:generic/runtime-library@1.0", "licenses": [{"license": {"id": "MIT"}}]},
            {"type": "device", "bom-ref": "board", "name": "controller", "version": "A"},
            {"type": "firmware", "bom-ref": "firmware", "name": "controller firmware", "version": "2.0"},
            {"type": "device-driver", "bom-ref": "driver", "name": "controller driver", "version": "3.0"},
            {"type": "cryptographic-asset", "bom-ref": "algorithm", "name": "RSA",
             "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "pke"}}},
            {"type": "cryptographic-asset", "bom-ref": "public-key", "name": "public key",
             "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {
                 "type": "public-key", "algorithmRef": "algorithm"}}},
            {"type": "cryptographic-asset", "bom-ref": "certificate", "name": "certificate",
             "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                 "certificateFormat": "X.509", "signatureAlgorithmRef": "algorithm", "subjectPublicKeyRef": "public-key"}}},
        ],
        "services": [{"bom-ref": "tls-consumer", "name": "configured TLS service", "properties": [
            {"name": "koda:crypto:relationship", "value": "declared-use"}]}],
        "dependencies": [
            {"ref": "inventory-root", "dependsOn": ["application", "board", "tls-consumer"]},
            {"ref": "application", "dependsOn": ["installed-library", "firmware"], "provides": ["nested-library"]},
            {"ref": "board", "dependsOn": ["firmware", "driver"]},
            {"ref": "firmware", "dependsOn": ["public-key"]},
            {"ref": "driver", "dependsOn": ["installed-library"]},
            {"ref": "tls-consumer", "dependsOn": ["certificate"]},
            {"ref": "certificate", "dependsOn": ["algorithm", "public-key"]},
            {"ref": "public-key", "dependsOn": ["algorithm"]},
        ],
        "compositions": [{"aggregate": "incomplete", "assemblies": ["application", "board", "certificate"]}],
    }
    runtime = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "device", "bom-ref": "operational-host", "name": "observed host"},
                     "lifecycles": [{"phase": "operations"}],
                     "properties": [{"name": "koda:obom:source-status", "value": "partial"}]},
        "components": [
            {"type": "container", "bom-ref": "running-container", "name": "container"},
            {"type": "application", "bom-ref": "running-process", "name": "process 42", "properties": [
                {"name": "koda:obom:pid", "value": "42"},
                {"name": "koda:obom:executable-package", "value": "runtime-owner"}]},
            {"type": "library", "bom-ref": "runtime-owner", "name": "runtime-library", "version": "1.0",
             "purl": "pkg:generic/runtime-library@1.0"},
        ],
        "services": [{"bom-ref": "observed-listener", "name": "TCP listener", "endpoints": ["tcp://127.0.0.1:18443"]}],
        "dependencies": [
            {"ref": "operational-host", "dependsOn": ["running-container"]},
            {"ref": "running-container", "dependsOn": ["running-process", "observed-listener"]},
            {"ref": "observed-listener", "dependsOn": ["running-process"]},
            {"ref": "running-process", "dependsOn": ["runtime-owner"]},
        ],
    }
    for prefix, document in [("sbom", primary)] + ([("obom", runtime)] if operations else []):
        validate_schema(document, SCHEMAS / "bom-1.6.schema.json")
        write_document(directory / (prefix + ".cdx.json"), document)
        if dual:
            companion = copy.deepcopy(document)
            companion["specVersion"] = "1.7"
            validate_schema(companion, SCHEMAS / "cyclonedx-1.7/bom-1.7.schema.json")
            write_document(directory / (prefix + ".cdx-1.7.json"), companion)
    write_document(directory / "collection.json", {
        "schema": "koda-sbom-collection-v1", "status": "partial", "source": marker,
        "startedAt": "2026-11-21T00:00:00Z", "tool": {"version": "fixture"},
    })
    write_checksums(directory)
    return primary, runtime


def verify_merge(primary, runtime, merged):
    actual = verify_references(merged)
    sources = [primary] + ([runtime] if runtime else [])
    expected_edges = set()
    for source in sources:
        expected_edges |= edges(source)
        for ref, expected in entities(source).items():
            require(ref in actual, "source entity lost after merge")
            for key, value in expected.items():
                if key == "properties":
                    require(all(item in actual[ref].get(key, []) for item in value), "source properties changed")
                else:
                    require(actual[ref].get(key) == value, "source entity content changed")
    require(expected_edges <= edges(merged), "cross-profile or runtime relationships lost")
    for row in primary.get("compositions", []):
        require(row in merged.get("compositions", []), "source composition lost")
    metadata = merged.get("metadata", {})
    for prop in primary.get("metadata", {}).get("properties", []):
        require(prop in metadata.get("properties", []), "source metadata lost")
    if runtime:
        require("installed-library" in actual and "runtime-owner" in actual,
                "package observations from distinct scopes conflated")
    return {"sourceEntities": sum(len(entities(source)) for source in sources), "sourceRelationships": len(expected_edges)}


def exercise(binary, docker_platform=None):
    require_unoptimized()
    binary = Path(binary).resolve(strict=True)
    report = []
    with tempfile.TemporaryDirectory(prefix="koda-bomset-qa-") as temporary:
        work = Path(temporary)
        output = work / "output"
        output.mkdir()

        def call(args):
            if docker_platform:
                translated = [str(arg).replace(str(work), "/work") for arg in args]
                command = ["docker", "run", "--rm", "--platform", docker_platform, "--network", "none",
                           "--pull", "never", "--read-only", "--cap-drop", "ALL", "--tmpfs", "/tmp",
                           "-v", str(binary) + ":/koda-bom:ro", "-v", str(work) + ":/work",
                           "debian:bookworm-slim", "/koda-bom", *translated]
            else:
                command = [str(binary), *map(str, args)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
            if docker_platform:
                result.stdout = result.stdout.replace("/work", str(work))
            return result

        def invoke(args, success=True):
            before = set(output.iterdir())
            result = call(args)
            if not success:
                require(result.returncode != 0, "invalid set accepted")
                require(set(output.iterdir()) == before, "failed operation published output")
                return None
            require(result.returncode == 0, (result.returncode, result.stderr))
            created = set(output.iterdir()) - before
            require(len(created) == 1, "operation must publish one result directory")
            directory = created.pop()
            require(directory.is_dir() and Path(result.stdout.strip()).resolve() == directory.resolve(), "CLI output path mismatch")
            return directory

        source = work / "source"
        primary, runtime = fixture(source)
        original_digests = {item.name: checksum(item) for item in source.iterdir()}
        split = invoke(["bom-split", "--collection", source, "--output-dir", output, "--cyclonedx-17"])
        require((split / "bom-set.json").is_file(), "missing merge manifest")
        for profile in PROFILES:
            for suffix in (".cdx.json", ".cdx-1.7.json"):
                require((split / (profile + suffix)).is_file(), "missing requested profile/version")
                verify_references(read_document(split / (profile + suffix)))
        profile_entities = {name: entities(read_document(split / (name + ".cdx.json"))) for name in PROFILES}
        require("installed-library" in profile_entities["sbom"] and "nested-library" in profile_entities["sbom"], "software missing")
        require({"board", "firmware"} <= profile_entities["hbom"].keys(), "hardware missing")
        require({"certificate", "algorithm", "public-key"} <= profile_entities["cbom"].keys(), "crypto assets missing")
        for name, forbidden in {"sbom": {"board", "certificate"}, "hbom": {"installed-library", "certificate"},
                                "cbom": {"installed-library", "board"}}.items():
            require(not forbidden & profile_entities[name].keys(), "profile contains unrelated assets")
        require(validate(split)["schemas"] == "passed", "split schema verification")
        merged = invoke(["bom-merge", "--set", split, "--output-dir", output, "--cyclonedx-17"])
        require(validate(merged)["schemas"] == "passed", "merged schema verification")
        counts = verify_merge(primary, runtime, read_document(merged / "bom.cdx.json"))
        verify_merge(primary, runtime, read_document(merged / "bom.cdx-1.7.json"))
        require({item.name: checksum(item) for item in source.iterdir()} == original_digests, "source changed")
        report.append({"case": "four-profile dual-version roundtrip", **counts})

        second = work / "second-source"
        fixture(second, marker="different")
        second_set = invoke(["bom-split", "--collection", second, "--output-dir", output, "--cyclonedx-17"])
        swapped = work / "swapped-set"
        shutil.copytree(split, swapped)
        shutil.copyfile(second_set / "sbom.cdx.json", swapped / "sbom.cdx.json")
        write_checksums(swapped)
        invoke(["bom-merge", "--set", swapped, "--output-dir", output], success=False)
        missing = work / "missing-set"
        shutil.copytree(split, missing)
        (missing / "cbom.cdx.json").unlink()
        write_checksums(missing)
        invoke(["bom-merge", "--set", missing, "--output-dir", output], success=False)
        tampered = work / "tampered-source"
        shutil.copytree(source, tampered)
        with (tampered / "sbom.cdx.json").open("a") as stream:
            stream.write("\n")
        invoke(["bom-split", "--collection", tampered, "--output-dir", output], success=False)
        report.append({"case": "rejected changed source, missing profile and profile from another collection"})

        single = work / "single-version-source"
        single_primary, _ = fixture(single, dual=False, operations=False)
        invoke(["bom-split", "--collection", single, "--output-dir", output, "--cyclonedx-17"], success=False)
        single_set = invoke(["bom-split", "--collection", single, "--output-dir", output])
        require(not list(single_set.glob("*.cdx-1.7.json")), "unexpected synthesized version")
        invoke(["bom-merge", "--set", single_set, "--output-dir", output, "--cyclonedx-17"], success=False)
        single_merged = invoke(["bom-merge", "--set", single_set, "--output-dir", output])
        validate(single_set)
        validate(single_merged)
        verify_merge(single_primary, None, read_document(single_merged / "bom.cdx.json"))
        report.append({"case": "software, hardware and crypto export without runtime evidence"})

        tree = make_tree(work / "fixture")
        assets = work / "assets.json"
        write_document(assets, {"schema": "koda-assets-1", "assets": [
            {"id": "controller", "kind": "device", "name": "fixture controller"},
            {"id": "firmware", "kind": "firmware", "name": "fixture firmware", "version": "1.0", "parentId": "controller"},
        ]})
        before = set(output.iterdir())
        result = call(["scan", "--target", tree, "--no-context", "--separate-boms",
                       "--cyclonedx-17", "--asset-evidence", assets, "--output-dir", output])
        require(result.returncode in (0, 3), (result.returncode, result.stderr))
        created = set(output.iterdir()) - before
        require(len(created) == 1, "scan output missing")
        scanned = created.pop()
        validate(scanned)
        validate(scanned / "boms")
        integrated = read_document(scanned / "sbom.cdx.json")
        scan_merged = invoke(["bom-merge", "--set", scanned / "boms", "--output-dir", output, "--cyclonedx-17"])
        validate(scan_merged)
        verify_merge(integrated, None, read_document(scan_merged / "bom.cdx.json"))
        report.append({"case": "normal scan with separate BOMs and later merge"})
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--docker-platform", choices=("linux/amd64", "linux/arm64"))
    arguments = parser.parse_args()
    print(json.dumps({"passed": True, "binarySHA256": checksum(arguments.binary),
                      "cases": exercise(arguments.binary, arguments.docker_platform)}, indent=2))
