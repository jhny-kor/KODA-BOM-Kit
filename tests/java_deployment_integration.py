#!/usr/bin/env python3
"""Compare Linux collector Java SBOMs against a pinned WAR and tested EAR wrapper."""

import argparse
import hashlib
import json
import subprocess
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen
from zipfile import ZipFile, ZipInfo

from validate_outputs import validate

WAR = "struts2-showcase-7.1.1.war"
EAR = "showcase-wrapper.ear"
WAR_PURL = "pkg:maven/org.apache.struts/struts2-showcase@7.1.1"
CODEC_PURL = "pkg:maven/commons-codec/commons-codec@1.19.0"
ASM_PURL = "pkg:maven/org.ow2.asm/asm@9.8"
WAR_URL = "https://repo.maven.apache.org/maven2/org/apache/struts/struts2-showcase/7.1.1/" + WAR
WAR_SHA256 = "c47fc69604df4b3385b8feb58cd229b591f7e46b7d096ecafde129c69d77f42e"
CODEC = "commons-codec-1.19.0.jar"
CODEC_URL = "https://repo.maven.apache.org/maven2/commons-codec/commons-codec/1.19.0/" + CODEC
CODEC_SHA256 = "5c3881e4f556855e9c532927ee0c9dfde94cc66760d5805c031a59887070af5f"


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def obtain_artifact(path, url, digest):
    if path.exists() and sha256(path) == digest:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(url, timeout=60) as response:
        data = response.read(64 << 20)
    if hashlib.sha256(data).hexdigest() != digest:
        raise AssertionError(f"published Maven Central artifact changed: {url}")
    path.write_bytes(data)


def write_archive(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(ZipInfo(name), content)


def prepare_fixtures(fixture_dir, include_probes):
    """Fetch checksum-pinned upstream artifacts on the online setup host only."""
    war = fixture_dir / "input" / WAR
    codec = fixture_dir / "maven" / CODEC
    obtain_artifact(war, WAR_URL, WAR_SHA256)
    obtain_artifact(codec, CODEC_URL, CODEC_SHA256)
    application = f'''<?xml version="1.0" encoding="UTF-8"?>
<application xmlns="https://jakarta.ee/xml/ns/jakartaee" version="10">
  <module><web><web-uri>apps/{WAR}</web-uri><context-root>/showcase</context-root></web></module>
  <library-directory>lib</library-directory>
</application>
'''.encode()
    write_archive(fixture_dir / "ear-input" / EAR, {
        "META-INF/application.xml": application,
        "META-INF/MANIFEST.MF": manifest("Showcase wrapper"),
        f"apps/{WAR}": war.read_bytes(), f"lib/{CODEC}": codec.read_bytes(),
    })
    if include_probes:
        with ZipFile(war) as archive:
            asm = archive.read("WEB-INF/lib/asm-9.8.jar")
            cglib = archive.read("WEB-INF/lib/cglib-2.2.2.jar")
        with ZipFile(BytesIO(cglib)) as original, BytesIO() as buffer:
            with ZipFile(buffer, "w") as stripped:
                for info in original.infolist():
                    if info.filename.upper() != "META-INF/MANIFEST.MF" and not info.filename.startswith("META-INF/maven/"):
                        stripped.writestr(info, original.read(info))
            cglib = buffer.getvalue()
        write_archive(fixture_dir / "filename-input/filename-probe.war", {
            "META-INF/MANIFEST.MF": manifest("filename-probe"), "WEB-INF/lib/asm-99.0.jar": asm,
        })
        write_archive(fixture_dir / "nometa-input/nometa-probe.war", {
            "META-INF/MANIFEST.MF": manifest("nometa-probe"), "WEB-INF/lib/cglib-2.2.2.jar": cglib,
        })


def manifest(title):
    return f"Manifest-Version: 1.0\r\nImplementation-Title: {title}\r\nImplementation-Version: 1.0.0\r\n\r\n".encode()


def physical_jars(archive, prefix):
    """Enumerate entry SHA-256 values independently of either SBOM encoder."""
    files = {}
    for info in archive.infolist():
        path = f"{prefix}!/{info.filename}"
        if not info.is_dir() and info.filename.endswith(".jar"):
            if path in files:
                raise AssertionError(f"ambiguous archive path: {path}")
            files[path] = hashlib.sha256(archive.read(info)).hexdigest()
        elif not info.is_dir() and info.filename.endswith(".war"):
            with ZipFile(BytesIO(archive.read(info))) as war:
                children = physical_jars(war, path)
                if files.keys() & children.keys():
                    raise AssertionError(f"ambiguous archive path: {path}")
                files.update(children)
    return files


def spdx_path_evidence(package):
    comment = package.get("comment")
    if not comment or not comment.startswith("{"):
        return []
    return json.loads(comment).get("evidencePaths", [])


def legacy_java_paths(result, archive_name):
    """Recover physical paths in the old Syft model to diagnose baseline output only."""
    paths = {}
    prefix = archive_name + ":"
    for item in load(result / "inventory.syft.json")["artifacts"]:
        if item.get("foundBy") != "java-archive-cataloger":
            continue
        virtual_path = item.get("metadata", {}).get("virtualPath", "")
        if virtual_path == archive_name:
            path = archive_name
        elif virtual_path.startswith(prefix):
            entries = virtual_path[len(prefix):].split(":")
            path = "!/".join([archive_name, *entries])
        else:
            continue
        paths.setdefault((item.get("purl"), item["name"], item["version"]), []).append(path)
    return paths


def documents(result):
    cdx = load(result / "sbom.cdx.json")
    spdx = load(result / "sbom.spdx.json")
    cdx_rows = {item["bom-ref"]: {
        "purl": item.get("purl"), "name": item["name"], "version": item.get("version"),
        "paths": [value["location"] for value in item.get("evidence", {}).get("occurrences", [])],
    } for item in cdx["components"]}
    spdx_rows = {item["SPDXID"]: {
        "purl": next((ref["referenceLocator"] for ref in item.get("externalRefs", [])
                      if ref["referenceType"] == "purl"), None),
        "name": item["name"], "version": item.get("versionInfo"), "paths": spdx_path_evidence(item),
    } for item in spdx["packages"]}
    cdx_edges = {(item["ref"], dependency) for item in cdx.get("dependencies", [])
                 for dependency in item.get("dependsOn", [])}
    spdx_edges = set()
    for item in spdx.get("relationships", []):
        origin, target = item["spdxElementId"], item["relatedSpdxElement"]
        if item["relationshipType"] == "DEPENDENCY_OF":
            spdx_edges.add((target, origin))
        elif item["relationshipType"] == "DEPENDS_ON":
            spdx_edges.add((origin, target))
    cdx_root = cdx.get("metadata", {}).get("component", {}).get("bom-ref")
    return {
        "cyclonedx": (cdx_rows, cdx_edges, {cdx_root} if cdx_root else set()),
        "spdx": (spdx_rows, spdx_edges, {spdx["SPDXID"]}),
    }


def ref_by_identity(rows, purl, path=None):
    candidates = [ref for ref, item in rows.items()
                  if (purl and item["purl"] == purl) or (not purl and path in item["paths"])]
    return candidates[0] if len(candidates) == 1 else None


def format_comparison(rows, edges, document_refs, expected, archive_name, declared_edges, legacy_paths):
    missing_paths, wrong_coordinates, wrong_versions, missing_edges = [], [], [], []
    by_path = {}
    java_nodes = set()
    for ref, item in rows.items():
        paths = item["paths"] or legacy_paths.get((item["purl"], item["name"], item["version"]), [])
        for path in paths:
            if path in expected:
                by_path.setdefault(path, []).append(ref)
            if path.startswith(archive_name) and path.lower().endswith((".jar", ".war", ".ear")):
                java_nodes.add(ref)
        if (item["purl"] or "").startswith("pkg:maven/"):
            java_nodes.add(ref)
    archive_war = ref_by_identity(rows, WAR_PURL)
    archive_ear = ref_by_identity(rows, None, EAR) if archive_name == EAR else None
    if archive_name == EAR and archive_ear is None:
        legacy_ear = [ref for ref, row in rows.items()
                      if legacy_paths.get((row["purl"], row["name"], row["version"]), []) == [EAR]]
        archive_ear = legacy_ear[0] if len(legacy_ear) == 1 else None
    jar_refs = {}
    for path, identity in expected.items():
        expected_purl, expected_version = identity["expectedPurl"], identity["expectedVersion"]
        matching_path = by_path.get(path, [])
        matches = [ref for ref in matching_path if rows[ref]["purl"] == expected_purl]
        if not any(path in rows[ref]["paths"] for ref in matching_path):
            missing_paths.append(path)
        if len(matches) != 1:
            if not matching_path:
                # Try a legacy row with the verified coordinate for edge/count diagnosis.
                ref = ref_by_identity(rows, expected_purl)
                if ref is not None:
                    jar_refs[path] = ref
            else:
                wrong_coordinates.append({"path": path, "expected": expected_purl,
                                          "actual": [rows[ref]["purl"] for ref in matching_path]})
                if len(matching_path) == 1:
                    jar_refs[path] = matching_path[0]
                    if rows[matching_path[0]]["version"] != expected_version:
                        wrong_versions.append({"path": path, "expected": expected_version,
                                               "actual": rows[matching_path[0]]["version"]})
            continue
        ref = matches[0]
        jar_refs[path] = ref
        if rows[ref]["version"] != expected_version:
            wrong_versions.append({"path": path, "expected": expected_version, "actual": rows[ref]["version"]})
    for path, ref in jar_refs.items():
        if (archive_ear if "!/lib/" in path and archive_name == EAR else archive_war, ref) not in edges:
            missing_edges.append(path)
    if archive_name == EAR and (archive_ear, archive_war) not in edges:
        missing_edges.append(f"{EAR}!/apps/{WAR}")
    direct_pom = [
        [origin, target] for origin, target in declared_edges
        if (ref_by_identity(rows, origin), ref_by_identity(rows, target)) not in edges
    ]
    archive_paths = [f"{EAR}!/apps/{WAR}", EAR] if archive_name == EAR else [WAR]
    archive_refs = [archive_war, archive_ear] if archive_name == EAR else [archive_war]
    for path, ref in zip(archive_paths, archive_refs, strict=True):
        if not ref or path not in rows[ref]["paths"]:
            missing_paths.append(path)

    def label(ref):
        item = rows[ref]
        return item["purl"] or "file:" + "|".join(sorted(item["paths"]))

    known_refs = rows.keys() | document_refs
    return {
        "jarPathsMatched": len(expected) - sum(path in expected for path in missing_paths),
        "javaPackages": len(java_nodes),
        "physicalDependenciesVerified": len(jar_refs) + int(archive_name == EAR) - len(missing_edges),
        "missingPaths": missing_paths, "wrongCoordinates": wrong_coordinates, "wrongVersions": wrong_versions,
        "missingArchiveDependencies": missing_edges, "missingExactBundledPomDependencies": direct_pom,
        "javaDependencies": sorted((label(origin), label(target)) for origin, target in edges
                                   if origin in java_nodes and target in java_nodes),
        "danglingDependencies": sorted((origin, target) for origin, target in edges
                                       if origin not in known_refs or target not in known_refs),
    }


def scan(binary, archive, output, image):
    # Mount only one archive so references may never resolve against a sibling
    # deployment accidentally. Package contents are never executed.
    output.mkdir()
    invocation = [
        "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
        "--mount", f"type=bind,src={binary},dst=/koda-bom,readonly",
        "--mount", f"type=bind,src={archive},dst=/input/{archive.name},readonly",
        "--mount", f"type=bind,src={output},dst=/output", image, "/koda-bom",
        "scan", "--target", "/input", "--no-context", "--output-dir", "/output", "--format", "both",
    ]
    proc = subprocess.run(invocation, check=False, text=True, capture_output=True, timeout=150)
    if proc.returncode not in (0, 3):
        raise AssertionError((archive.name, proc.returncode, proc.stderr))
    result, = output.iterdir()
    integrity = validate(result)
    if integrity["checksums"] < 5:
        raise AssertionError(f"SBOM files did not all have checksums: {integrity}")
    return result, {"exitCode": proc.returncode, "status": load(result / "collection.json")["status"], **integrity}


def compare_real_archive(binary, archive, output, image, expected_rows, declared_edges, baseline):
    expected = {row["path"]: row for row in expected_rows}
    with ZipFile(archive) as app:
        actual = physical_jars(app, archive.name)
    if actual != {path: row["sha256"] for path, row in expected.items()}:
        raise AssertionError(f"independently checked archive library inventory changed: {archive.name}")
    result, integrity = scan(binary, archive, output, image)
    legacy = legacy_java_paths(result, archive.name) if baseline else {}
    formatted = {
        format_name: format_comparison(rows, edges, document_refs, expected, archive.name, declared_edges, legacy)
        for format_name, (rows, edges, document_refs) in documents(result).items()
    }
    return {"archiveSHA256": sha256(archive), "physicalJars": len(actual), "collection": integrity,
            "crossFormatGraphParity": formatted["cyclonedx"]["javaDependencies"] == formatted["spdx"]["javaDependencies"],
            "formats": formatted}


def compare_probe(binary, archive, output, image, jar, *, coordinate, version):
    result, integrity = scan(binary, archive, output, image)
    path = f"{archive.name}!/WEB-INF/lib/{jar}"
    formats = {}
    for name, (rows, edges, _) in documents(result).items():
        root = next((ref for ref, item in rows.items() if archive.name in item["paths"]), None)
        matched = [item for ref, item in rows.items() if path in item["paths"] and (root, ref) in edges]
        formats[name] = {"pass": len(matched) == 1 and matched[0]["purl"] == coordinate and
                         matched[0]["version"] == version, "matched": matched}
    return {"archiveSHA256": sha256(archive), "verifiedPath": path, "collection": integrity, "formats": formats}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path, help="Linux amd64 koda-bom executable")
    parser.add_argument("--fixture-dir", required=True, type=Path,
                        help="directory containing the pinned archive fixtures")
    parser.add_argument("--expected-dir", type=Path,
                        help="directory containing provenance and independent physical inventory (defaults to --fixture-dir)")
    parser.add_argument("--prepare-fixture", action="store_true",
                        help="fetch checksum-pinned archives and build the wrapper/probes before the offline scan")
    parser.add_argument("--image", default="debian:bookworm-slim", help="preloaded linux/amd64 image")
    parser.add_argument("--output", type=Path, help="retain small verification JSON")
    parser.add_argument("--keep-sboms", type=Path, help="retain generated SBOM directories here")
    parser.add_argument("--baseline", action="store_true", help="record baseline differences without requiring a pass")
    parser.add_argument("--probes", action="store_true", help="also require renamed-version and missing-metadata regressions")
    parser.add_argument("--require-declared-dependencies", action="store_true",
                        help="require six exact-version dependency declarations from the bundled Java POMs")
    args = parser.parse_args()
    fixtures = args.fixture_dir.resolve()
    expected = args.expected_dir.resolve() if args.expected_dir else fixtures
    binary = args.binary.resolve()
    if args.prepare_fixture:
        prepare_fixtures(fixtures, args.probes)
    provenance = load(expected / "archive-fixture-provenance.json")
    war = fixtures / "input" / WAR
    ear = fixtures / "ear-input" / EAR
    if sha256(war) != provenance["publishedWar"]["sha256"] or sha256(ear) != provenance["testEar"]["sha256"]:
        raise AssertionError("Java deployment fixture checksum mismatch")
    with ZipFile(ear) as wrapped:
        if hashlib.sha256(wrapped.read(f"apps/{WAR}")).hexdigest() != provenance["publishedWar"]["sha256"]:
            raise AssertionError("EAR does not embed the exact published WAR")
    pom_edges = [("pkg:maven/" + item["from"].replace(":", "/", 1).replace(":", "@", 1),
                  "pkg:maven/" + item["to"].replace(":", "/", 1).replace(":", "@", 1))
                 for item in load(expected / "physical-dependency-candidates.json")
                 if item["classification"] == "exact version"]
    if len(pom_edges) != 6:
        raise AssertionError("Java dependency fixture changed")
    with TemporaryDirectory(prefix="koda-java-deployment-") as temporary:
        output = args.keep_sboms.resolve() if args.keep_sboms else Path(temporary)
        output.mkdir(parents=True, exist_ok=True)
        report = {
            "binarySHA256": sha256(binary), "network": "none", "architecture": "linux/amd64",
            "provenance": provenance,
            "deployments": {
                "war": compare_real_archive(binary, war, output / "war", args.image,
                                            load(expected / "physical-inventory.json"), pom_edges, args.baseline),
                "ear": compare_real_archive(binary, ear, output / "ear", args.image,
                                            load(expected / "physical-ear-inventory.json"), pom_edges, args.baseline),
            },
        }
        if args.probes:
            report["probes"] = {
                "renamedVersion": compare_probe(binary, fixtures / "filename-input/filename-probe.war",
                                                output / "filename", args.image, "asm-99.0.jar",
                                                coordinate=ASM_PURL, version="9.8"),
                "metadataFreeJar": compare_probe(binary, fixtures / "nometa-input/nometa-probe.war",
                                                 output / "nometa", args.image, "cglib-2.2.2.jar",
                                                 coordinate=None, version=None),
            }
        passed = True
        for result in report["deployments"].values():
            passed &= result["crossFormatGraphParity"] and result["collection"]["status"] == "completed"
            for fmt in result["formats"].values():
                passed &= not any(fmt[key] for key in ("missingPaths", "wrongCoordinates", "wrongVersions",
                                                         "missingArchiveDependencies", "danglingDependencies"))
                if args.require_declared_dependencies:
                    passed &= not fmt["missingExactBundledPomDependencies"]
        for probe in report.get("probes", {}).values():
            passed &= (probe["collection"]["status"] == "completed"
                        and all(fmt["pass"] for fmt in probe["formats"].values()))
        report["passed"] = passed
        if args.output:
            args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"passed": passed, "deployments": {name: item["physicalJars"] for name, item in
                                                             report["deployments"].items()}}, indent=2))
        return 0 if passed or args.baseline else 1


if __name__ == "__main__":
    raise SystemExit(main())
