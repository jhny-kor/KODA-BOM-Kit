#!/usr/bin/env python3
"""Validate exported results from the disposable Oracle 8.2 real-kernel VM.

This runs on the build host, never on a target server. A directory fixture is not
proof of a booted kernel: the runner must retain QEMU and input-artifact evidence
alongside this independent guest-baseline comparison.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import parse_qs

HERE = Path(__file__).resolve().parent
MAX_JSON_BYTES = 256 << 20
REQUIRED = {"sbom.cdx.json", "sbom.spdx.json", "inventory.syft.json", "context.json", "collection.json"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RESULT_NAME = re.compile(r"^koda-sbom-[A-Za-z0-9._-]+$")


class VerificationError(ValueError):
    """A malformed or unsafe exported validation input."""


def confined(root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise VerificationError("unsafe exported evidence filename")
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise VerificationError("exported evidence is missing or outside its root: " + relative) from exc
    if not resolved.is_file():
        raise VerificationError("exported evidence is not a regular file: " + relative)
    return resolved


def load_json(root: Path, relative: str) -> dict:
    file = confined(root, relative)
    if file.stat().st_size > MAX_JSON_BYTES:
        raise VerificationError("exported JSON exceeds validation limit: " + relative)
    try:
        value = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("cannot parse exported JSON: " + relative) from exc
    if not isinstance(value, dict):
        raise VerificationError("exported JSON must be an object: " + relative)
    return value


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def standard_validator():
    # Import the repository's existing fully offline schema/integrity verifier.
    spec = importlib.util.spec_from_file_location("koda_local_validate_outputs", HERE.parent / "validate_outputs.py")
    if spec is None or spec.loader is None:
        raise VerificationError("offline standard-output validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate


def as_objects(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def standard_purls(cdx: dict, spdx: dict) -> tuple[set[str], set[str]]:
    cyclonedx = {p["purl"] for p in as_objects(cdx.get("components")) if isinstance(p.get("purl"), str)}
    spdx_values = {
        r["referenceLocator"]
        for p in as_objects(spdx.get("packages"))
        for r in as_objects(p.get("externalRefs"))
        if r.get("referenceType") == "purl" and isinstance(r.get("referenceLocator"), str)
    }
    return cyclonedx, spdx_values


def validate_vm(directory: Path | str, *, expected_kernel: str | None = None,
                binary: Path | str | None = None, binary_sha256: str | None = None) -> dict:
    if not __debug__:
        raise VerificationError("run without Python -O: the shared offline verifier uses assertions")
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise VerificationError("extracted VM result root is not a directory")
    manifest = json.loads((HERE / "kernels.json").read_text(encoding="utf-8"))
    expected_packages = manifest["packages"]
    releases = sorted({p["kernelRelease"] for p in expected_packages})
    if expected_kernel is not None and expected_kernel not in releases:
        raise VerificationError("expected kernel must exactly match one Oracle 8.2 release: " + ", ".join(releases))
    if binary_sha256 is not None and not SHA256.fullmatch(binary_sha256):
        raise VerificationError("expected binary SHA-256 must be 64 lowercase hexadecimal characters")
    if binary is not None:
        computed = digest_file(Path(binary))
        if binary_sha256 is not None and computed != binary_sha256:
            raise VerificationError("--binary and --binary-sha256 refer to different collector builds")
        binary_sha256 = computed

    baseline = load_json(root, "baseline.json")
    checks = []
    def check(name, passed, detail=None):
        record = {"name": name, "passed": bool(passed)}
        if detail is not None:
            record["detail"] = detail
        checks.append(record)

    check("baseline_schema", baseline.get("schema") == "koda-sbom-oracle-vm-baseline-v1")
    running = baseline.get("unameRelease")
    check("supported_oracle_kernel", running in releases, {"running": running, "supported": releases})
    if expected_kernel is not None:
        check("expected_boot_kernel", running == expected_kernel, {"expected": expected_kernel, "observed": running})
    check("independent_uname_proc_match", bool(running) and baseline.get("procRelease") == running)
    check("guest_architecture", baseline.get("unameMachine") == "x86_64")
    os_release = baseline.get("osRelease") or {}
    check("guest_oracle_linux_82", isinstance(os_release, dict) and os_release.get("ID") == "ol" and os_release.get("VERSION_ID") == "8.2")
    check("harness_completed_without_timeout", baseline.get("scanTimedOut") is False)
    check("harness_export_completed", not baseline.get("exportError"))
    check("harness_issues_empty", baseline.get("issues") == [], {"count": len(baseline.get("issues") or [])})
    exit_code = baseline.get("scanExitCode")
    check("collector_exit_is_success_or_explicit_partial", type(exit_code) is int and exit_code in (0, 3), {"exitCode": exit_code})
    check("guest_collector_digest_present", isinstance(baseline.get("binarySha256"), str) and bool(SHA256.fullmatch(baseline.get("binarySha256", ""))))
    if binary_sha256 is not None:
        check("guest_collector_matches_requested_binary", baseline.get("binarySha256") == binary_sha256)

    result_dirs = baseline.get("resultDirectories")
    if not isinstance(result_dirs, list) or len(result_dirs) != 1 or not isinstance(result_dirs[0], str) or not RESULT_NAME.fullmatch(result_dirs[0]):
        raise VerificationError("one unambiguous koda-bom result directory must be declared in baseline.json")
    result_name = result_dirs[0]
    result = (root / result_name).resolve(strict=True)
    try:
        result.relative_to(root)
    except ValueError as exc:
        raise VerificationError("result directory escapes extracted VM root") from exc
    actual_dirs = sorted(p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("koda-sbom-"))
    check("single_exported_scan_result", actual_dirs == [result_name])
    for filename in REQUIRED | {"SHA256SUMS"}:
        confined(root, result_name + "/" + filename)
    checksum_lines = (result / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    checksum_names = []
    for line in checksum_lines:
        parts = line.split("  ", 1)
        if len(parts) != 2 or not SHA256.fullmatch(parts[0]):
            raise VerificationError("invalid SHA256SUMS record")
        name = parts[1]
        if Path(name).name != name or not name or name == "SHA256SUMS":
            raise VerificationError("unsafe SHA256SUMS filename")
        confined(root, result_name + "/" + name)
        checksum_names.append(name)
    check("required_outputs_all_checksummed", REQUIRED.issubset(checksum_names) and len(checksum_names) == len(set(checksum_names)))
    try:
        output_validation = standard_validator()(result)
        check("dual_schema_and_file_integrity", True, output_validation)
    except Exception as exc:
        check("dual_schema_and_file_integrity", False, str(exc)[:1000])

    context = load_json(root, result_name + "/context.json")
    collection = load_json(root, result_name + "/collection.json")
    inventory = load_json(root, result_name + "/inventory.syft.json")
    cdx = load_json(root, result_name + "/sbom.cdx.json")
    spdx = load_json(root, result_name + "/sbom.spdx.json")
    check("context_is_actual_live_host_mode", context.get("mode") == "live-host")
    check("context_running_kernel_matches_independent_baseline", context.get("runningKernel") == running)
    flavor = "UEK" if isinstance(running, str) and "el8uek" in running else "RHCK-compatible"
    check("context_kernel_flavor", context.get("kernelFlavor") == flavor, {"expected": flavor, "observed": context.get("kernelFlavor")})
    check("collection_schema", collection.get("schema") == "koda-sbom-collection-v1")
    check("exit_status_consistent", (exit_code == 0 and collection.get("status") == "completed") or (exit_code == 3 and collection.get("status") == "partial"), {"exitCode": exit_code, "collectionStatus": collection.get("status")})
    check("context_status_valid", context.get("status") in ("completed", "partial"))
    if exit_code == 0:
        check("success_context_has_no_partial_state", context.get("status") == "completed")
    distro = inventory.get("distro") or {}
    check("native_inventory_oracle_82", isinstance(distro, dict) and distro.get("id") == "ol" and distro.get("versionID") == "8.2")
    reported_distro = collection.get("distribution") or {}
    check("collection_oracle_82", isinstance(reported_distro, dict) and reported_distro.get("ID") == "ol" and reported_distro.get("VersionID") == "8.2")
    check("exact_requested_standard_versions", cdx.get("bomFormat") == "CycloneDX" and cdx.get("specVersion") == "1.6" and spdx.get("spdxVersion") == "SPDX-2.3")

    baseline_modules = baseline.get("loadedModulesAfter")
    observed_modules = context.get("loadedModules")
    module_inputs_valid = isinstance(baseline_modules, list) and all(isinstance(x, str) for x in baseline_modules) and isinstance(observed_modules, list) and all(isinstance(x, str) for x in observed_modules)
    check("loaded_module_lists_present", module_inputs_valid)
    if module_inputs_valid:
        # init runs no background services; module lists should not race arbitrary
        # userspace probes between the independent baseline and collector read.
        check("loaded_modules_match_independent_baseline", set(observed_modules) == set(baseline_modules), {"baselineCount": len(baseline_modules), "contextCount": len(observed_modules)})
    module_state = baseline.get("moduleLoadState")
    check("module_probe_state_known", module_state in ("loaded", "already-loaded", "failed", "not-supplied"))
    if module_state in ("loaded", "already-loaded"):
        check("loop_observed_in_baseline_and_context", module_inputs_valid and "loop" in baseline_modules and "loop" in observed_modules)
        check("loaded_module_digest_recorded", isinstance(baseline.get("moduleSha256"), str) and bool(SHA256.fullmatch(baseline.get("moduleSha256", ""))))
        check("loaded_module_belongs_to_booted_kernel", baseline.get("modulePath") == f"/vm-test/modules/{running}/loop.ko")

    artifacts = as_objects(inventory.get("artifacts"))
    check("native_artifact_collection_not_empty", bool(artifacts))
    check("collection_count_matches_native_inventory", type(collection.get("packageCount")) is int and collection.get("packageCount") == len(artifacts))
    rpm_artifacts = [p for p in artifacts if p.get("type") == "rpm"]
    cdx_purls, spdx_purls = standard_purls(cdx, spdx)
    rpm_summary = []
    for expected in expected_packages:
        name, version, release = expected["name"], expected["version"], expected["release"]
        candidates = [p for p in rpm_artifacts if p.get("name") == name and isinstance(p.get("metadata"), dict) and p["metadata"].get("version") == version and p["metadata"].get("release") == release and p["metadata"].get("architecture") == expected["architecture"]]
        check("rpm_nevra_" + expected["id"], bool(candidates), {"name": name, "version": version, "release": release, "architecture": expected["architecture"]})
        if not candidates:
            continue
        expected_source = ("kernel-uek" if name == "kernel-uek" else "kernel") + f"-{version}-{release}.src.rpm"
        # At least one exactly matching record must retain all required
        # distribution metadata, not merely a similarly numbered upstream kernel.
        valid = []
        for package in candidates:
            metadata = package["metadata"]
            epoch = metadata.get("epoch")
            purl = package.get("purl") if isinstance(package.get("purl"), str) else ""
            qualifiers = parse_qs(purl.partition("?")[2])
            if "epoch" in metadata and (epoch is None or type(epoch) is int and epoch >= 0) and metadata.get("sourceRpm") == expected_source and isinstance(metadata.get("vendor"), str) and "oracle" in metadata["vendor"].lower() and qualifiers.get("arch") == ["x86_64"] and qualifiers.get("distro") == ["ol-8.2"] and qualifiers.get("upstream") == [expected_source] and purl in cdx_purls and purl in spdx_purls:
                valid.append(package)
        check("rpm_backport_identity_and_both_formats_" + expected["id"], bool(valid), {"sourceRpm": expected_source})
        if valid:
            metadata = valid[0]["metadata"]
            rpm_summary.append({"name": name, "version": version, "release": release, "epoch": metadata.get("epoch"), "architecture": metadata["architecture"], "sourceRpm": metadata["sourceRpm"], "vendor": metadata["vendor"]})

    kernel_artifacts = [p for p in artifacts if p.get("type") == "linux-kernel"]
    module_artifacts = [p for p in artifacts if p.get("type") == "linux-kernel-module"]
    module_summary = {}
    for release in releases:
        kernels = [p for p in kernel_artifacts if p.get("version") == release and isinstance(p.get("metadata"), dict) and p["metadata"].get("version") == release]
        check("installed_kernel_image_" + release, bool(kernels))
        modules = [p for p in module_artifacts if isinstance(p.get("metadata"), dict) and p["metadata"].get("kernelVersion") == release]
        check("installed_module_kernel_version_" + release, bool(modules))
        if modules:
            path_and_magic = [p for p in modules if isinstance(p["metadata"].get("versionMagic"), str) and p["metadata"]["versionMagic"].split(" ", 1)[0] == release and any(f"/modules/{release}/" in "/" + str(v).lstrip("/") for v in [p["metadata"].get("path", "")] + [loc.get("path", "") for loc in as_objects(p.get("locations"))])]
            check("module_vermagic_and_install_tree_" + release, bool(path_and_magic))
        module_summary[release] = len(modules)
    check("one_running_kernel_distinct_from_two_installed_kernels", context.get("runningKernel") in releases and len(releases) == 2 and all(any(p.get("version") == release for p in kernel_artifacts) for release in releases))

    return {
        "schema": "koda-sbom-oracle-vm-verification-v1",
        "passed": all(c["passed"] for c in checks),
        "evidenceKind": "independent-guest-baseline-vs-live-host-collector",
        "limitations": ["Retain the QEMU runner log and kernel/RPM/initramfs checksums to establish that the guest actually booted; fabricated JSON fixtures alone do not prove VM execution.", "Actual Oracle guest kernel validation is distinct from physical or production-server validation.", "A module installed for an inactive kernel is not inferred to be loaded or exploitable."],
        "runningKernel": running,
        "kernelFlavor": context.get("kernelFlavor"),
        "collectorSHA256": baseline.get("binarySha256"),
        "requestedBinaryChecked": binary_sha256 is not None,
        "scanExitCode": exit_code,
        "collectionStatus": collection.get("status"),
        "contextStatus": context.get("status"),
        "moduleLoadState": module_state,
        "installedKernelReleases": releases,
        "installedKernelRPMs": rpm_summary,
        "moduleCountsByBuiltForKernel": module_summary,
        "checks": checks,
        "failedChecks": [c for c in checks if not c["passed"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="extracted guest result root containing baseline.json")
    parser.add_argument("--expected-kernel", help="exact booted kernel release, including distro release and architecture")
    parser.add_argument("--binary", type=Path, help="collector binary used by the VM, compared by SHA-256")
    parser.add_argument("--binary-sha256", help="expected collector SHA-256 without needing the binary file")
    parser.add_argument("--report", type=Path, help="optional new JSON report path; existing files are never overwritten")
    args = parser.parse_args()
    try:
        report = validate_vm(args.directory, expected_kernel=args.expected_kernel, binary=args.binary, binary_sha256=args.binary_sha256)
    except (OSError, ValueError, TypeError, KeyError, ImportError) as exc:
        report = {"schema": "koda-sbom-oracle-vm-verification-v1", "passed": False, "error": str(exc)}
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.report:
        try:
            with args.report.open("x", encoding="utf-8") as stream:
                stream.write(text)
        except OSError as exc:
            print(json.dumps({"passed": False, "error": "cannot create new report: " + str(exc)}), file=sys.stderr)
            return 2
    print(text, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
