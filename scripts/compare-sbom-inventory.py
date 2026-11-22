#!/usr/bin/env python3
"""Scan one directory with KODA, Syft and Trivy and compare inventory evidence."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import quote, unquote

TOOLS = ("koda", "syft", "trivy")
SYFT_LOCATION = re.compile(r"syft:location:(\d+):(path|fullPath)")


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def deployment_digest(root):
    digest = hashlib.sha256()

    def record(directory):
        for child in sorted(directory.iterdir()):
            details = child.lstat()
            name = child.relative_to(root).as_posix()
            mode = details.st_mode
            if stat.S_ISLNK(mode):
                payload = ("link", os.readlink(child))
            elif stat.S_ISREG(mode):
                payload = ("file", file_digest(child))
            elif stat.S_ISDIR(mode):
                payload = ("directory",)
            else:
                raise ValueError(f"Unsupported deployment file type: {name}")
            digest.update(os.fsencode(json.dumps((name, mode, *payload), ensure_ascii=True)))
            digest.update(b"\n")
            if stat.S_ISDIR(mode):
                record(child)

    record(root)
    return digest.hexdigest()


def package_identity(purl):
    """Return a versioned PURL without qualifiers or subpath for comparison."""
    purl = purl.split("#", 1)[0].split("?", 1)[0]
    purl, _, version = purl.partition("@")
    kind, sep, path = purl.partition("/")
    if not sep or not kind.startswith("pkg:") or not path.rsplit("/", 1)[-1]:
        raise ValueError(f"Invalid PURL in inventory: {purl!r}")
    kind = kind.lower()
    path = [unquote(segment, errors="strict") for segment in path.split("/")]
    if kind == "pkg:pypi":
        path[-1] = re.sub(r"[-_.]+", "-", path[-1]).lower()
    elif kind == "pkg:nuget":
        path = [segment.lower() for segment in path]
    coordinate = kind + "/" + "/".join(quote(segment, safe="") for segment in path)
    return coordinate, unquote(version, errors="strict")


def qualified_identity(identity, purl):
    raw, _, subpath = purl.partition("#")
    _, _, qualifiers = raw.partition("?")
    fields = []
    for qualifier in qualifiers.split("&") if qualifiers else ():
        key, sep, value = qualifier.partition("=")
        if not key or not sep:
            raise ValueError(f"Invalid PURL qualifier: {qualifier!r}")
        fields.append((key.lower(), quote(unquote(value, errors="strict"), safe="")))
    query = "&".join(f"{key}={value}" for key, value in sorted(fields))
    normalized_subpath = "/".join(quote(unquote(segment, errors="strict"), safe="") for segment in subpath.split("/"))
    return identity + ("?" + query if query else "") + ("#" + normalized_subpath if subpath else "")


@dataclass
class Inventory:
    components: list
    identities: set
    versions: dict
    edges: set
    exact_edges: set
    other_edges: dict
    excluded: Counter
    unresolved: list
    path_evidence: "PathEvidence"


@dataclass
class PathEvidence:
    occurrences: set
    unique_occurrences: set
    edges: set
    paths_by_ref: dict
    ambiguous_edges: set
    qualified_rows: Counter
    qualified_edges: Counter

    @property
    def pathless_refs(self):
        return {ref for ref, (_, paths) in self.paths_by_ref.items() if not paths}


def occurrence_path(value):
    if not isinstance(value, str) or not value or "://" in value or any(ord(char) < 32 for char in value):
        return None
    path = PurePosixPath(value.lstrip("/"))
    return path.as_posix() if path.parts and ".." not in path.parts else None


def cyclonedx_paths(node):
    standard = [row.get("location") for row in (node.get("evidence") or {}).get("occurrences", ())]
    if standard:
        return standard
    locations = defaultdict(dict)
    for prop in node.get("properties", ()):
        match = SYFT_LOCATION.fullmatch(prop.get("name", ""))
        if match and prop.get("value"):
            index, kind = match.groups()
            locations[index][kind] = prop["value"]
    return [values.get("fullPath") or values.get("path") for values in locations.values()]


def collect_path_evidence(rows, ref_edges):
    paths_by_ref = {
        ref: (identity, {path for value in paths if (path := occurrence_path(value))})
        for ref, identity, paths in rows if ref and identity.startswith("pkg:")
    }
    counts = Counter((identity, path) for identity, paths in paths_by_ref.values() for path in paths)
    precise = {
        ref: (identity, path) for ref, (identity, paths) in paths_by_ref.items() if len(paths) == 1
        for path in paths if counts[identity, path] == 1
    }
    edges, ambiguous_edges = set(), set()
    qualified_edges = Counter()
    for source, target in ref_edges:
        if source not in paths_by_ref or target not in paths_by_ref:
            continue
        qualified_edges[paths_by_ref[source][0], paths_by_ref[target][0]] += 1
        if source in precise and target in precise:
            edges.add((precise[source], precise[target]))
        else:
            # A package reference can carry several locations. The edge alone
            # cannot identify which location is involved and must not fan out.
            ambiguous_edges.add((source, target))
    qualified_rows = Counter(identity for identity, _ in paths_by_ref.values())
    return PathEvidence(set(counts), set(precise.values()), edges, paths_by_ref, ambiguous_edges,
                        qualified_rows, qualified_edges)


def inventory(document):
    if document.get("bomFormat") != "CycloneDX":
        raise ValueError("Expected a CycloneDX inventory")
    components, unresolved, occurrence_rows = [], [], []
    references, versions = {}, defaultdict(set)
    excluded = Counter()

    def visit(node, is_document_root=False):
        purl = node.get("purl", "")
        name = node.get("name", "")
        version = node.get("version", "")
        component_type = node.get("type", "")
        ref = node.get("bom-ref")
        identity = exact = None
        manifest = not purl and component_type == "application" and any(
            item.get("name") == "aquasecurity:trivy:Class" and item.get("value") == "lang-pkgs"
            for item in node.get("properties", ())
        )
        if is_document_root:
            label = "document"
        elif manifest or component_type in {"file", "data"}:
            label = "manifest" if manifest else component_type
            excluded[label] += 1
        else:
            label = "package"
            if purl:
                coordinate, purl_version = package_identity(purl)
                if version and purl_version and version != purl_version:
                    unresolved.append({"ref": ref, "componentVersion": version, "purlVersion": purl_version})
                version = purl_version or version
                identity = coordinate + ("@" + quote(version, safe="") if version else "")
            else:
                coordinate = f"{component_type}:{node.get('group', '')}/{name}"
                identity = f"{coordinate}@{version}" if version else coordinate
            versions[coordinate].add(version)
            exact = qualified_identity(identity, purl) if purl else identity
            components.append({"identity": identity, "qualifiedIdentity": exact, "purl": purl, "version": version,
                               "name": name, "type": component_type, "ref": ref})
            if purl:
                occurrence_rows.append((ref, exact, cyclonedx_paths(node)))
        if ref:
            if ref in references:
                raise ValueError(f"Duplicate CycloneDX reference: {ref}")
            references[ref] = (label, identity, exact)
        for child in node.get("components", ()):
            visit(child)

    root = document.get("metadata", {}).get("component")
    if root:
        visit(root, True)
    for component in document.get("components", ()):
        visit(component)
    for service in document.get("services", ()):
        visit_service(service, references)
    edges, exact_edges, ref_edges, other_edges = set(), set(), set(), defaultdict(set)
    for entry in document.get("dependencies", ()):
        source = entry["ref"]
        source_type, source_id, source_exact = references.get(source, ("unmapped", None, None))
        for destination in entry.get("dependsOn", ()):
            target_type, target_id, target_exact = references.get(destination, ("unmapped", None, None))
            if source_type == target_type == "package":
                edges.add((source_id, target_id))
                exact_edges.add((source_exact, target_exact))
                ref_edges.add((source, destination))
            else:
                other_edges[f"{source_type}->{target_type}"].add((source, destination))
    return Inventory(components, {row["identity"] for row in components}, versions,
                     edges, exact_edges, {kind: sorted(rows) for kind, rows in sorted(other_edges.items())},
                     excluded, unresolved, collect_path_evidence(occurrence_rows, ref_edges))


def spdx_path_evidence(document):
    if not document.get("spdxVersion", "").startswith("SPDX-2."):
        raise ValueError("Expected an SPDX 2.x inventory")
    files = {file["SPDXID"]: file["fileName"] for file in document.get("files", ())}
    provenance, edges = defaultdict(list), set()
    for relationship in document.get("relationships", ()):
        source, target = relationship["spdxElementId"], relationship["relatedSpdxElement"]
        kind = relationship["relationshipType"]
        if kind == "DEPENDS_ON":
            edges.add((source, target))
        elif kind == "DEPENDENCY_OF":
            edges.add((target, source))
        elif kind == "OTHER" and relationship.get("comment", "").startswith("evident-by:") and target in files:
            provenance[source].append(files[target])

    rows, seen = [], set()
    for node in document.get("packages", ()):
        ref = node["SPDXID"]
        if ref in seen:
            raise ValueError(f"Duplicate SPDX package reference: {ref}")
        seen.add(ref)
        purl = next((row["referenceLocator"] for row in node.get("externalRefs", ())
                     if row.get("referenceType") == "purl"), "")
        if not purl:
            continue
        coordinate, version = package_identity(purl)
        package_version = node.get("versionInfo", "")
        if version and package_version and version != package_version:
            raise ValueError(f"SPDX package version disagrees with PURL: {ref}")
        version = version or package_version
        identity = coordinate + ("@" + quote(version, safe="") if version else "")
        paths = provenance[ref]
        comment = node.get("comment", "")
        if comment.startswith("{"):
            try:
                structured = json.loads(comment)
            except ValueError:
                structured = {}
            if isinstance(structured.get("evidencePaths"), list) and structured["evidencePaths"]:
                # For nested archives this records the inner entry, while
                # SPDX file relationships can point to the containing archive.
                paths = structured["evidencePaths"]
        if not paths:
            source_info = node.get("sourceInfo", "")
            _, _, location = source_info.partition(": ")
            if source_info.startswith("acquired package info from ") and location and ", " not in location:
                paths = [location]
        rows.append((ref, qualified_identity(identity, purl), paths))
    return collect_path_evidence(rows, edges)


def visit_service(service, references):
    ref = service.get("bom-ref")
    if ref:
        if ref in references:
            raise ValueError(f"Duplicate CycloneDX reference: {ref}")
        references[ref] = ("service", None, None)
    for child in service.get("services", ()):
        visit_service(child, references)


def identity_encoding_differences(koda, other, common):
    left, right = defaultdict(set), defaultdict(set)
    for rows, by_name in ((koda.components, left), (other.components, right)):
        for row in rows:
            if row["identity"] not in common and row["name"] and row["version"]:
                key = (row["name"].casefold(), row["version"])
                by_name[key].add((row["identity"], bool(row["purl"])))
    candidates = []
    for key in sorted(left.keys() & right.keys()):
        if len(left[key]) == len(right[key]) == 1:
            (a, has_purl_a), = left[key]
            (b, has_purl_b), = right[key]
            if has_purl_a != has_purl_b:
                candidates.append([a, b])
    return candidates


def compare(left, right, left_name, right_name):
    common = left.identities & right.identities
    version_changes = []
    for key in sorted(left.versions.keys() & right.versions.keys()):
        if left.versions[key] != right.versions[key]:
            version_changes.append({"coordinate": key, left_name: sorted(left.versions[key]),
                                    right_name: sorted(right.versions[key])})
    only_left = sorted(left.edges - right.edges)
    only_right = sorted(right.edges - left.edges)
    return {
        "commonComponentCount": len(common),
        "componentsOnlyIn": {left_name: sorted(left.identities - right.identities),
                             right_name: sorted(right.identities - left.identities)},
        "versionDifferences": version_changes,
        "sameNameAndVersionWithDifferentIdentityEncoding": identity_encoding_differences(left, right, common),
        "commonDependencyCount": len(left.edges & right.edges),
        "dependenciesOnlyIn": {left_name: only_left, right_name: only_right},
        "dependencyDifferencesWithBothEndpointsPresent": {
            left_name: [edge for edge in only_left if set(edge) <= common],
            right_name: [edge for edge in only_right if set(edge) <= common],
        },
        "pathComparison": compare_path_evidence(left.path_evidence, right.path_evidence, left_name, right_name),
    }


def expected_gaps(current, components, dependencies, absent=()):
    return {
        "missingComponents": sorted(components - current.identities),
        "missingDependencies": sorted(dependencies - current.edges),
        "unexpectedComponents": sorted(current.identities.intersection(absent)),
    }


def compare_path_evidence(left, right, left_name, right_name, *, same_collector=False):
    shared = left.occurrences & right.occurrences
    comparable = left.unique_occurrences & right.unique_occurrences
    left_edges, right_edges = left.edges, right.edges
    if not same_collector:
        # Peer scanners can use a lockfile or omit locations altogether.
        # Compare only when each scanner reports both endpoints unambiguously.
        left_edges = {edge for edge in left_edges if set(edge) <= comparable}
        right_edges = {edge for edge in right_edges if set(edge) <= comparable}
    comparison = {
        "sharedOccurrenceCount": len(shared),
        "comparableOccurrenceCount": len(comparable),
        "observedOccurrencesOnlyIn": {
            left_name: sorted(left.occurrences - right.occurrences),
            right_name: sorted(right.occurrences - left.occurrences),
        },
        "dependenciesOnlyIn": {
            left_name: sorted(left_edges - right_edges),
            right_name: sorted(right_edges - left_edges),
        },
    }
    if same_collector:
        # An unresolved path must not hide a missing package or relationship
        # in one of the two serializations of the same package inventory.
        comparison["qualifiedPackageRowsOnlyIn"] = {
            left_name: dict(sorted((left.qualified_rows - right.qualified_rows).items())),
            right_name: dict(sorted((right.qualified_rows - left.qualified_rows).items())),
        }
        comparison["qualifiedDependenciesOnlyIn"] = {
            left_name: [(source, target, count) for (source, target), count in
                        sorted((left.qualified_edges - right.qualified_edges).items())],
            right_name: [(source, target, count) for (source, target), count in
                         sorted((right.qualified_edges - left.qualified_edges).items())],
        }
    return comparison


def expected_path_item(value):
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        raise ValueError("Each occurrence requires a qualified PURL and a relative evidence path")
    purl, raw = value
    path = occurrence_path(raw)
    if not isinstance(purl, str) or not purl.startswith("pkg:") or not path or raw.startswith("/"):
        raise ValueError("Each occurrence requires a qualified PURL and a relative evidence path")
    return purl, path


def expected_path_edges(entries):
    result = set()
    for entry in entries:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError("Each occurrence dependency must connect two occurrences")
        source, target = map(expected_path_item, entry)
        result.add((source, target))
    return result


def path_gaps(current, expected):
    required = {expected_path_item(row) for row in expected.get("occurrences", ())}
    absent = {expected_path_item(row) for row in expected.get("absentOccurrences", ())}
    dependencies = expected_path_edges(expected.get("occurrenceDependencies", ()))
    no_dependencies = expected_path_edges(expected.get("absentOccurrenceDependencies", ()))
    if required & absent or dependencies & no_dependencies:
        raise ValueError("An occurrence or occurrence dependency cannot be both required and absent")
    pathless_identities = {identity for identity, paths in current.paths_by_ref.values() if not paths}
    ambiguous_by_endpoint = defaultdict(list)
    if no_dependencies:
        for source_ref, target_ref in current.ambiguous_edges:
            source, source_paths = current.paths_by_ref[source_ref]
            target, target_paths = current.paths_by_ref[target_ref]
            ambiguous_by_endpoint[source, target].append((source_paths, target_paths))
    return {
        "missingOccurrences": sorted(required - current.occurrences),
        "unexpectedOccurrences": sorted(absent & current.occurrences),
        "missingOccurrenceDependencies": sorted(dependencies - current.edges),
        "unexpectedOccurrenceDependencies": sorted(no_dependencies & current.edges),
        "unverifiedAbsentOccurrences": sorted(row for row in absent - current.occurrences if row[0] in pathless_identities),
        "unverifiedAbsentOccurrenceDependencies": sorted(
            ((source, left), (target, right)) for (source, left), (target, right) in no_dependencies - current.edges
            if any((not source_paths or left in source_paths) and (not target_paths or right in target_paths)
                   for source_paths, target_paths in ambiguous_by_endpoint[source, target])
        ),
    }


def summarize_path_evidence(current):
    return {
        "occurrences": sorted(current.occurrences),
        "occurrenceDependencies": sorted(current.edges),
        "referencesWithoutPaths": sorted(current.pathless_refs),
        "dependenciesWithoutUniquePaths": sorted(current.ambiguous_edges),
    }


def summarize(current):
    return {
        "componentRows": len(current.components),
        "componentIdentities": sorted(current.identities),
        "qualifiedComponentRows": dict(sorted(Counter(row["qualifiedIdentity"] for row in current.components).items())),
        "componentsWithoutPurl": sorted({row["identity"] for row in current.components if not row["purl"]}),
        "excludedNonPackageRows": current.excluded,
        "componentVersionConflicts": current.unresolved,
        "packageDependencies": sorted(current.edges),
        "qualifiedPackageDependencies": sorted(current.exact_edges),
        "otherDependencyReferences": current.other_edges,
        "components": current.components,
        "pathEvidence": summarize_path_evidence(current.path_evidence),
    }


def execute(command, log, env, work_dir, timeout, valid=(0,)):
    with log.open("wb") as stream:
        result = subprocess.run(command, cwd=work_dir, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, check=False, timeout=timeout)
    if result.returncode not in valid:
        raise ValueError(f"{Path(command[0]).name} exit {result.returncode}. See {log}")
    return result.returncode


def scan(args, out, work_dir, initial_digest):
    config_file = work_dir / "scanner-config.yaml"
    config_file.write_text("{}\n", encoding="utf-8")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("SYFT_", "TRIVY_", "KODA_TRACKER_"))}
    env.update(HOME=str(work_dir), XDG_CONFIG_HOME=str(work_dir), SYFT_CHECK_FOR_APP_UPDATE="false")
    cache = args.trivy_cache_dir.resolve(strict=True) if args.trivy_cache_dir else work_dir / "trivy-cache"
    koda, syft, trivy = (str(getattr(args, key).resolve(strict=True)) for key in TOOLS)
    commands = {
        "koda": [koda, "scan", "--target", str(args.deployment), "--no-context",
                 "--format", "both", "--output-dir", str(out / "koda")],
        "syft": [syft, "scan", "--config", str(config_file), f"dir:{args.deployment}",
                 "-o", f"cyclonedx-json={out / 'syft.cdx.json'}"],
        "trivy": [trivy, "fs", "--config", str(config_file), "--cache-dir", str(cache),
                  "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
                  "--disable-telemetry", "--skip-version-check", "--ignorefile=", "--format", "cyclonedx",
                  "--output", str(out / "trivy.cdx.json"), str(args.deployment)],
    }
    versions = {"koda": [koda, "version"], "syft": [syft, "version"], "trivy": [trivy, "--version"]}
    codes = {}
    for key in TOOLS:
        execute(versions[key], out / f"{key}.version.txt", env, work_dir, args.timeout)
        codes[key] = execute(commands[key], out / f"{key}.log", env, work_dir,
                             args.timeout, (0, 3) if key == "koda" else (0,))
        if deployment_digest(args.deployment) != initial_digest:
            raise ValueError(f"Deployment changed during {key} scan. Compare an immutable copy.")
    koda_output, = (out / "koda").glob("*/collection.json")
    result = {"koda": koda_output.with_name("sbom.cdx.json"),
              "syft": out / "syft.cdx.json", "trivy": out / "trivy.cdx.json"}
    return result, koda_output, codes, commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory outside the deployment")
    parser.add_argument("--koda", type=Path, required=True, help="locally installed koda-bom binary")
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--trivy-cache-dir", type=Path, help="local cache with Java index when required")
    parser.add_argument("--expected", type=Path, help="required and absent components, dependencies and paths")
    parser.add_argument("--baseline", type=Path, help="prior comparison.json, gate on removed KODA components, edges or paths")
    parser.add_argument("--require-complete", action="store_true", help="fail for a partial KODA scan")
    parser.add_argument("--timeout", default=1800, type=int, help="per subprocess timeout in seconds")
    parser.add_argument("--tracker", action="store_true", help="upload both KODA outputs to a configured test Tracker")
    parser.add_argument("--upload-peers", action="store_true", help="also verify Tracker uploads of Syft and Trivy CycloneDX")
    parser.add_argument("--create-test-service", action="store_true", help="create a disposable Tracker service in the configured test instance")
    parser.add_argument("--service-id")
    parser.add_argument("--environment-id")
    parser.add_argument("--normalized-bom-command", type=Path, help="Tracker normalized-BOM exporter for edge comparison")
    args = parser.parse_args()
    scope_selected = bool(args.service_id) and bool(args.environment_id)
    if args.tracker:
        if args.create_test_service == scope_selected or bool(args.service_id) != bool(args.environment_id):
            parser.error("use --create-test-service or both --service-id and --environment-id")
    elif any((args.upload_peers, args.create_test_service, args.service_id, args.environment_id, args.normalized_bom_command)):
        parser.error("Tracker options require --tracker")
    if args.timeout < 1:
        parser.error("--timeout must be positive")
    args.deployment = args.deployment.resolve(strict=True)
    output = args.output_dir.resolve()
    if not args.deployment.is_dir() or output.is_relative_to(args.deployment):
        parser.error("Provide a directory and an output directory outside it")
    output.mkdir(parents=True, exist_ok=False)
    expected = load(args.expected) if args.expected else {}
    expected_components = set(expected.get("components", ()))
    absent_components = set(expected.get("absentComponents", ()))
    expected_dependencies = {tuple(edge) for edge in expected.get("dependencies", ())}
    if set.intersection(expected_components, absent_components):
        raise ValueError("Expected component cannot be both required and absent")
    if any(len(edge) != 2 or not set(edge) <= expected_components for edge in expected_dependencies):
        raise ValueError("Each expected dependency must connect two expected components")
    deployment_before = deployment_digest(args.deployment)
    with tempfile.TemporaryDirectory(prefix="koda-inventory-compare-") as temporary:
        paths, collection, codes, commands = scan(args, output, Path(temporary), deployment_before)
    scans = {name: inventory(load(path)) for name, path in paths.items()}
    koda = scans["koda"]
    spdx_path = collection.with_name("sbom.spdx.json")
    spdx = spdx_path_evidence(load(spdx_path))
    format_comparison = compare_path_evidence(koda.path_evidence, spdx, "cyclonedx", "spdx", same_collector=True)
    format_passes = not any(format_comparison[key][name]
                            for key in ("observedOccurrencesOnlyIn", "dependenciesOnlyIn",
                                        "qualifiedPackageRowsOnlyIn", "qualifiedDependenciesOnlyIn")
                            for name in ("cyclonedx", "spdx"))
    cdx_path_gaps = path_gaps(koda.path_evidence, expected)
    spdx_path_gaps = path_gaps(spdx, expected)
    reports = {key: {"version": (output / f"{key}.version.txt").read_text().strip(),
                     "path": paths[key].relative_to(output).as_posix(),
                     "sha256": file_digest(paths[key]), "exitCode": codes[key],
                     "expectedGaps": expected_gaps(scans[key], expected_components, expected_dependencies, absent_components),
                     **summarize(scans[key])} for key in TOOLS}
    expected_koda = reports["koda"]["expectedGaps"]
    regressions = {}
    baseline_has_paths = False
    if args.baseline:
        baseline = load(args.baseline)
        if baseline["deploymentSha256"] != deployment_before:
            raise ValueError("Baseline was made on a different deployment")
        reference = baseline["tools"]["koda"]
        regressions = expected_gaps(koda, set(reference["componentIdentities"]),
                                     {tuple(edge) for edge in reference["packageDependencies"]})
        if baseline.get("schemaVersion") not in (2, 3):
            raise ValueError("Recreate the baseline with this version to verify qualified component instances")
        current_rows = Counter(row["qualifiedIdentity"] for row in koda.components)
        regressions["missingQualifiedComponentRows"] = dict(sorted((Counter(reference["qualifiedComponentRows"]) - current_rows).items()))
        regressions["missingQualifiedDependencies"] = sorted(
            set(map(tuple, reference["qualifiedPackageDependencies"])) - koda.exact_edges)
        regressions["becamePartial"] = reference["exitCode"] == 0 and codes["koda"] == 3
        baseline_has_paths = baseline["schemaVersion"] == 3
        if baseline_has_paths:
            path_reference = reference["pathEvidence"]
            regressions.update(path_gaps(koda.path_evidence, path_reference))
    coverage = load(collection)
    collection_fields = ("status", "packageCount", "issues", "excludedDirectories", "omittedIssueCount")
    passes = (not any(expected_koda.values()) and not any(regressions.values())
              and format_passes and not any(cdx_path_gaps.values()) and not any(spdx_path_gaps.values())
              and (not args.require_complete or codes["koda"] == 0) and not koda.unresolved)
    report = {
        "schemaVersion": 3, "deploymentSha256": deployment_before,
        "commands": commands, "tools": reports,
        "comparisons": {f"{left}-{right}": compare(scans[left], scans[right], left, right)
                        for left, right in (("koda", "syft"), ("koda", "trivy"), ("syft", "trivy"))},
        "kodaCollection": {field: coverage[field] for field in collection_fields if field in coverage},
        "kodaBaselineRegressions": regressions,
        "kodaBaselinePathChecks": baseline_has_paths,
        "kodaPathComparison": {
            "passed": format_passes,
            "comparedFormats": format_comparison,
            "expectedGaps": {"cyclonedx": cdx_path_gaps, "spdx": spdx_path_gaps},
            "spdx": {"path": spdx_path.relative_to(output).as_posix(), "sha256": file_digest(spdx_path),
                     **summarize_path_evidence(spdx)},
        },
        "kodaInventoryPassed": passes,
        "passed": passes,
    }
    result = output / "comparison.json"
    dump(result, report)
    print(result)
    if args.tracker:
        verifier = Path(__file__).with_name("verify-tracker-inventory.py")
        tracker_report = output / "tracker.json"
        command = [sys.executable, str(verifier), "--cyclonedx", str(paths["koda"]),
                   "--spdx", str(collection.with_name("sbom.spdx.json")), "--output", str(tracker_report)]
        if args.create_test_service:
            command.append("--create-test-service")
        if args.upload_peers:
            for key in TOOLS[1:]:
                command.extend(("--peer-cyclonedx", key, str(paths[key])))
        for option, value in (("--service-id", args.service_id), ("--environment-id", args.environment_id),
                              ("--normalized-bom-command", args.normalized_bom_command)):
            if value is not None:
                command.extend((option, str(value.resolve()) if isinstance(value, Path) else str(value)))
        tracker = subprocess.run(command, check=False, timeout=args.timeout)
        report["tracker"] = {"report": tracker_report.name, "passed": tracker.returncode == 0}
        report["passed"] = passes and report["tracker"]["passed"]
        dump(result, report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Inventory comparison failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
