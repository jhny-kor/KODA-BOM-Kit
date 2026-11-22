#!/usr/bin/env python3
"""Exercise supplier SBOM comparison against deployed WAR/EAR bytes offline."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

from validate_outputs import validate


JQUERY = "pkg:npm/jquery@3.1.1"
OLD_UI = "pkg:npm/jquery-ui@1.12.1"
NEW_UI = "pkg:npm/jquery-ui@1.14.2"
MAVEN_JAR = "pkg:maven/org.example/deployed-jar@2.3.4"
SUPPLIER_ONLY = "pkg:npm/only-in-supplier@4.0.0"
OUTSIDE = "pkg:npm/jquery@2.2.4"
UNRESOLVED_JS = "assets/jquery.fancytree.childcounter.min.js"
SUPPLIER_UNRESOLVED = "fixture-unresolved-supplier"
FILENAME_PURL = "pkg:npm/extension@'jquery.fancytree.childcounter.min.js'"


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def document(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
    return path


def war_bytes(*, changed=False):
    jquery = "/*! jQuery v3.1.1 | (c) jQuery Foundation | jquery.org/license */\n"
    jquery_ui = "/*! jQuery UI - v1.14.2 - 2026-01-28\n * https://jqueryui.com\n */\n"
    jar = io.BytesIO()
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n\n")
        archive.writestr("META-INF/maven/org.example/deployed-jar/pom.properties",
                         "groupId=org.example\nartifactId=deployed-jar\nversion=2.3.4\n")
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/jquery.min.js", jquery)
        archive.writestr("assets/jquery-ui.min.js", jquery_ui)
        archive.writestr("WEB-INF/lib/deployed-jar-2.3.4.jar", jar.getvalue())
        archive.writestr(UNRESOLVED_JS, "/* FIXTURE_PRIVATE_JAVASCRIPT */\n")
        if changed:
            archive.writestr("unrelated.txt", "changed deployed bytes")
    return data.getvalue()


def create_artifact(path, *, changed=False):
    if path.suffix == ".war":
        path.write_bytes(war_bytes(changed=changed))
    else:
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("apps/app.war", war_bytes(changed=changed))
    return path


def cdx_supplier(digest, *, missing=False, conflicting=False):
    root = {"type": "application", "name": "fixture-app", "version": "1.0.0"}
    if not missing:
        root["hashes"] = [{"alg": "SHA-256", "content": digest.upper()}]
        if conflicting:
            root["hashes"].append({"alg": "SHA-256", "content": "0" * 64})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": root},
        "components": [
            {"type": "library", "name": "jquery", "version": "3.1.1", "purl": JQUERY},
            {"type": "library", "name": "jquery-ui", "version": "1.12.1", "purl": OLD_UI},
            {"type": "library", "name": "only-in-supplier", "version": "4.0.0", "purl": SUPPLIER_ONLY,
             "hashes": [{"alg": "SHA-256", "content": digest}]},
            {"type": "library", "name": "extension", "version": "'jquery.fancytree.childcounter.min.js'", "purl": FILENAME_PURL},
        ],
    }


def spdx_supplier(digest, *, missing=False):
    root_id = "SPDXRef-application"

    def package(package_id, name, version=None, purl=None):
        value = {"SPDXID": package_id, "name": name, "downloadLocation": "NOASSERTION"}
        if version:
            value["versionInfo"] = version
        if purl:
            value["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl,
            }]
        return value

    root = package(root_id, "fixture-app", "1.0.0")
    if not missing:
        root["checksums"] = [{"algorithm": "SHA256", "checksumValue": digest}]
    supplier_only = package("SPDXRef-only-in-supplier", "only-in-supplier", "4.0.0", SUPPLIER_ONLY)
    supplier_only["checksums"] = [{"algorithm": "SHA256", "checksumValue": digest}]
    return {
        "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
        "name": "fixture", "documentNamespace": "https://example.invalid/reconcile-spdx",
        "creationInfo": {"created": "2026-11-14T00:00:00Z", "creators": ["Tool: fixture"]},
        "documentDescribes": [root_id],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id},
        ],
        "packages": [
            root, package("SPDXRef-jquery", "jquery", "3.1.1", JQUERY),
            package("SPDXRef-jquery-ui", "jquery-ui", "1.12.1", OLD_UI),
            supplier_only, package("SPDXRef-unresolved", "extension", "'jquery.fancytree.childcounter.min.js'", FILENAME_PURL),
        ],
    }


def check_result(result, artifact, supplier, supplier_format, archive_path):
    for name in ("sbom.cdx.json", "sbom.spdx.json", "collection.json", "reconcile.json"):
        assert (result / name).is_file(), (result, name)
    schemas = validate(result)
    checksum_names = {line.split("  ", 1)[1] for line in (result / "SHA256SUMS").read_text().splitlines()}
    assert checksum_names == {item.name for item in result.iterdir() if item.name != "SHA256SUMS"}, checksum_names
    report = document(result / "reconcile.json")
    assert report["schema"] == "koda-sbom-reconciliation-v1", report
    assert report["artifactSha256"] == checksum(artifact), report
    assert report["artifactType"] == artifact.suffix.lstrip("."), report
    assert report["supplierSbomSha256"] == checksum(supplier), report
    assert report["supplierFormat"] == supplier_format, report
    assert artifact.name not in json.dumps(report) and supplier.name not in json.dumps(report), report
    collection = document(result / "collection.json")
    assert report["observedStatus"] == collection["status"] == "partial", (report, collection)
    assert report["collectionCoverage"]["componentCount"] == collection["packageCount"]
    assert any(
        item["code"] == "static_js_identity_unconfirmed" and item["path"].endswith(UNRESOLVED_JS)
        for item in collection["issues"]
    ), collection["issues"]
    comparison = report["comparison"]
    common = {entry["purl"]: entry for entry in comparison["common"]}
    assert set(common) == {JQUERY}, comparison
    assert common[JQUERY]["observedCount"] == common[JQUERY]["supplierCount"] == 1, common[JQUERY]
    assert {entry["purl"] for entry in comparison["observedOnly"]} == {NEW_UI, MAVEN_JAR}, comparison
    assert {entry["purl"] for entry in comparison["supplierOnly"]} == {OLD_UI, SUPPLIER_ONLY}, comparison
    assert sum(item["supplierCount"] for item in comparison["unresolved"]) == 1, comparison
    supplier_issues = [item["reason"] for item in comparison["unresolved"] if item["supplierCount"]]
    assert len(supplier_issues) == 1 and supplier_issues[0] in {"invalid_purl", "nonconcrete_version"}, comparison
    # WAR/EAR graph nodes carry physical evidence even if the outer archives
    # do not declare a Maven identity.
    assert [item["reason"] for item in comparison["unresolved"] if item["observedCount"]] == ["missing_purl"], comparison
    assert FILENAME_PURL not in json.dumps(report)

    cdx = document(result / "sbom.cdx.json")
    spdx = document(result / "sbom.spdx.json")
    cdx_purls = {entry["purl"] for entry in cdx["components"] if entry.get("purl")}
    spdx_purls = {
        ref["referenceLocator"] for package in spdx["packages"]
        for ref in package.get("externalRefs", []) if ref["referenceType"] == "purl"
    }
    assert {JQUERY, NEW_UI, MAVEN_JAR} <= cdx_purls and {JQUERY, NEW_UI, MAVEN_JAR} <= spdx_purls, (cdx_purls, spdx_purls)
    jquery, = (entry for entry in cdx["components"] if entry.get("purl") == JQUERY)
    assert archive_path in {item["location"] for item in jquery["evidence"]["occurrences"]}, jquery
    for name in ("sbom.cdx.json", "sbom.spdx.json", "inventory.syft.json"):
        contents = (result / name).read_text()
        for absent in (OLD_UI, SUPPLIER_ONLY, FILENAME_PURL, OUTSIDE, artifact.name, "FIXTURE_PRIVATE_JAVASCRIPT"):
            assert absent not in contents, (name, absent)
    return {"validation": schemas, "artifactSha256": report["artifactSha256"], "comparison": comparison}


def exercise(stage):
    stage = stage.resolve(strict=True)
    binary = stage / "koda-bom"
    assert binary.is_file(), binary
    with tempfile.TemporaryDirectory(prefix="koda-supplier-reconcile-") as temporary:
        work = Path(temporary)
        fixtures, output = work / "fixtures", work / "output"
        fixtures.mkdir()
        output.mkdir()
        output.chmod(0o777)
        war = create_artifact(fixtures / "release build.war")
        ear = create_artifact(fixtures / "release.ear")
        (fixtures / "jquery.min.js").write_text("/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */\n")
        (fixtures / "different-build").mkdir()
        changed = create_artifact(fixtures / "different-build" / war.name, changed=True)
        cdx = write_json(fixtures / "supplier.cdx.json", cdx_supplier(checksum(war)))
        spdx = write_json(fixtures / "supplier.spdx.json", spdx_supplier(checksum(ear)))
        bad_hash = write_json(fixtures / "bad-hash.cdx.json", cdx_supplier("0" * 64))
        missing_cdx = write_json(fixtures / "no-subject-hash.cdx.json", cdx_supplier(checksum(war), missing=True))
        missing_spdx = write_json(fixtures / "no-subject-hash.spdx.json", spdx_supplier(checksum(ear), missing=True))
        conflict = write_json(fixtures / "conflicting-hash.cdx.json", cdx_supplier(checksum(war), conflicting=True))
        invalid = fixtures / "not-a-zip.war"
        invalid.write_text("An artifact hash is not evidence of a readable archive.")
        invalid_cdx = write_json(fixtures / "invalid.cdx.json", cdx_supplier(checksum(invalid)))
        clean_war = fixtures / "verified.war"
        with zipfile.ZipFile(clean_war, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("js/jquery.min.js", "/*! jQuery v3.1.1 | (c) jQuery Foundation | jquery.org/license */\n")
        clean = cdx_supplier(checksum(clean_war))
        clean["components"] = clean["components"][:1]
        clean_cdx = write_json(fixtures / "verified.cdx.json", clean)
        clean["components"].append({"type": "library", "name": SUPPLIER_UNRESOLVED})
        unresolved_cdx = write_json(fixtures / "unresolved.cdx.json", clean)

        def invoke(artifact, supplier, expected, *options):
            before = set(output.iterdir())
            command = [
                "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "65534:65534", "--cpus", "2", "--memory", "1536m",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
                "--mount", f"type=bind,src={stage},dst=/release,readonly",
                "--mount", f"type=bind,src={fixtures},dst=/fixtures,readonly",
                "--mount", f"type=bind,src={output},dst=/results",
                "debian:bookworm-slim", "/release/koda-bom", "reconcile",
                "--artifact", f"/fixtures/{artifact.relative_to(fixtures).as_posix()}",
                "--supplier-sbom", f"/fixtures/{supplier.relative_to(fixtures).as_posix()}",
                "--output-dir", "/results", *options,
            ]
            process = subprocess.run(command, capture_output=True, text=True, timeout=180)
            created = set(output.iterdir()) - before
            diagnostics = {
                item.name: (item / "collection.json").read_text() for item in created
                if process.returncode != expected and (item / "collection.json").is_file()
            }
            assert process.returncode == expected, (process.returncode, process.stdout, process.stderr, diagnostics)
            if expected == 2:
                assert not created and not process.stdout.strip(), (created, process.stdout)
                assert process.stderr.strip(), "rejection lacked a diagnostic"
                return None
            result, = created
            assert process.stdout.splitlines()[-1] == f"/results/{result.name}", process.stdout
            return result

        cdx_result = check_result(invoke(war, cdx, 3), war, cdx, "cyclonedx-json", "deployment.war!/assets/jquery.min.js")
        spdx_result = check_result(
            invoke(ear, spdx, 3), ear, spdx, "spdx-json", "deployment.ear!/apps/app.war!/assets/jquery.min.js",
        )
        for artifact, supplier in [(war, bad_hash), (changed, cdx), (war, missing_cdx), (ear, missing_spdx), (war, conflict), (invalid, invalid_cdx)]:
            invoke(artifact, supplier, 2)
        invoke(war, cdx, 2, "--timeout=1ns")
        clean_result = invoke(clean_war, clean_cdx, 0, "--format=cyclonedx", "--timeout=0")
        assert (clean_result / "sbom.cdx.json").is_file() and not (clean_result / "sbom.spdx.json").exists()
        assert document(clean_result / "reconcile.json")["observedStatus"] == "completed"
        unresolved = invoke(clean_war, unresolved_cdx, 3)
        report = document(unresolved / "reconcile.json")
        assert report["observedStatus"] == "completed" and report["comparison"]["unresolved"] == [
            {"reason": "missing_purl", "observedCount": 0, "supplierCount": 1},
        ], report
    return {
        "passed": True, "architecture": "linux/amd64", "network": "none", "rootfs": "read-only",
        "binarySHA256": checksum(binary), "cycloneDX": cdx_result, "spdx": spdx_result,
        "completeCollectionCases": 2, "negativeCases": 7,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(exercise(args.stage), ensure_ascii=False, indent=2))
