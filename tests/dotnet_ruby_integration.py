#!/usr/bin/env python3
"""Compare SBOMs for the same .NET publish folder and installed Ruby gems."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen
from zipfile import ZipFile

from validate_outputs import validate


RUNNER = "debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8"
RUBY = "ruby@sha256:d1bd04fc230dec182310f7b12bbce0d409879c1f2c52d5a57df40b564d28e11e"
PLATFORM = "linux/amd64"
APP = "Koda.Stage7.App"
APP_DIR = "opt/koda-app"
RUBY_DIR = "opt/ruby"
DLL_DIR = "opt/koda-dll"
DEFAULT_GEM = "usr/local/lib/ruby/gems/3.4.0/specifications/default/benchmark-0.4.0.gemspec"
NUGET = "https://api.nuget.org/v3-flatcontainer"
GEMS = "https://rubygems.org/downloads"
GITHUB = "https://github.com"
PACKAGES = {
    "newtonsoft.json.13.0.3.nupkg": (
        f"{NUGET}/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg",
        "872fc189e638ab1056555b03aaa38f68bcb54286e221aa646eb1129babf63c77",
    ),
    "serilog.4.2.0.nupkg": (
        f"{NUGET}/serilog/4.2.0/serilog.4.2.0.nupkg",
        "edfdc4a42b046c3c5782cba1138df4295235e29ee80d4b82b70469382aad9dbb",
    ),
    "rack-3.1.7.gem": (
        f"{GEMS}/rack-3.1.7.gem",
        "0e9982db4ea9013326788ca2a7f48e32a4e746765e7c3512d424ef0dd22ae58b",
    ),
    "rake-13.2.1.gem": (
        f"{GEMS}/rake-13.2.1.gem",
        "46cb38dae65d7d74b6020a4ac9d48afed8eb8149c040eccf0523bec91907059d",
    ),
}
SCANNERS = {
    "syft-1.55.0": (
        f"{GITHUB}/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz",
        "bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d",
        "syft",
    ),
    "syft-1.57.1": (
        f"{GITHUB}/anchore/syft/releases/download/v1.57.1/syft_1.57.1_linux_amd64.tar.gz",
        "bf52519eb57f675d47c07d43213cb6dff6449f3d6d1147ff6701ed91f44eef0c",
        "syft",
    ),
    "trivy-0.76.2": (
        f"{GITHUB}/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz",
        "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
        "trivy",
    ),
}
EXPECTED_PURLS = {
    "pkg:nuget/newtonsoft.json@13.0.3",
    "pkg:gem/benchmark@0.4.0",
    "pkg:gem/rack@3.1.7",
    "pkg:gem/rake@13.2.1",
}
UNINSTALLED = {"koda.unshipped", "koda.lockonly", "koda-lock-only", "koda-orphan"}


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def acquire(path, url, expected):
    if not path.exists():
        with urlopen(url, timeout=60) as response:
            blob = response.read((128 << 20) + 1)
        assert len(blob) <= (128 << 20), url
        assert hashlib.sha256(blob).hexdigest() == expected, url
        path.write_bytes(blob)
    assert sha256(path) == expected, path
    return path


def download_fixtures(cache, work, compare):
    cache.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=6) as pool:
        packages = {
            name: pool.submit(acquire, cache / name, url, checksum)
            for name, (url, checksum) in PACKAGES.items()
        }
        archives = {
            name: pool.submit(acquire, cache / f"{name}.tar.gz", url, checksum)
            for name, (url, checksum, _) in SCANNERS.items() if compare
        }
        for future in packages.values():
            future.result()
        for name, future in archives.items():
            with tarfile.open(future.result(), "r:gz") as archive:
                with archive.extractfile(SCANNERS[name][2]) as source, (work / name).open("wb") as binary:
                    shutil.copyfileobj(source, binary)
            (work / name).chmod(0o755)


def command(args, *, allowed=(0,), **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=180, **kwargs)
    assert result.returncode in allowed, (args, result.returncode, result.stdout, result.stderr)
    return result


def mount(path, destination, writable=False):
    return ["--mount", f"type=bind,src={path},dst={destination}" + ("" if writable else ",readonly")]


def docker(image, args, mounts, *, allowed=(0,)):
    return command([
        "docker", "run", "--rm", "--pull", "never", "--platform", PLATFORM,
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--memory", "1536m", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
        "--env", "HOME=/tmp", "--env", "SYFT_CHECK_FOR_APP_UPDATE=false",
        *mounts, image, *args,
    ], allowed=allowed)


def prepare_deployment(work, cache, dotnet):
    project = work / "project"
    project.mkdir()
    (project / f"{APP}.csproj").write_text(f"""\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>{APP}</AssemblyName>
    <Version>1.2.3</Version>
    <RuntimeIdentifier>linux-x64</RuntimeIdentifier>
    <SelfContained>false</SelfContained>
    <UseAppHost>false</UseAppHost>
    <DebugType>none</DebugType>
    <NuGetAudit>false</NuGetAudit>
  </PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3"/></ItemGroup>
</Project>
""")
    (project / "Program.cs").write_text(
        'System.Console.WriteLine(Newtonsoft.Json.JsonConvert.SerializeObject(new { status = "ready" }));\n'
    )
    tree = work / "deployment"
    environment = dict(
        os.environ, DOTNET_CLI_HOME=str(work / "dotnet-home"),
        DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1", NUGET_PACKAGES=str(work / "nuget"),
    )
    sdk = command([dotnet, "--version"], env=environment).stdout.strip()
    command([
        dotnet, "publish", str(project / f"{APP}.csproj"), "-c", "Release",
        "--output", str(tree / APP_DIR), "--source", str(cache), "-p:RestoreIgnoreFailedSources=false",
        f"-p:PathMap={project}=/src",
    ], env=environment)
    with ZipFile(cache / "serilog.4.2.0.nupkg") as package:
        (tree / DLL_DIR).mkdir()
        (tree / DLL_DIR / "Serilog.dll").write_bytes(package.read("lib/net9.0/Serilog.dll"))

    gems = tree / RUBY_DIR
    gems.mkdir()
    gems.chmod(0o777)
    ruby_version = docker(RUBY, ["ruby", "--version"], []).stdout.strip()
    docker(RUBY, [
        "gem", "install", "--local", "--no-document", "--install-dir", "/gem-home",
        "/packages/rack-3.1.7.gem", "/packages/rake-13.2.1.gem",
    ], mount(cache, "/packages") + mount(gems, "/gem-home", writable=True))
    ruby_stdlib = tree / "usr"
    ruby_stdlib.mkdir()
    ruby_stdlib.chmod(0o777)
    docker(RUBY, ["/bin/sh", "-ec", '''
        for source in /usr/local/lib/ruby/3.4.0/benchmark.rb "$1"; do
            destination="/fixture${source}"
            mkdir -p "${destination%/*}"
            cp "$source" "$destination"
        done
    ''', "copy-default-gem", f"/{DEFAULT_GEM}"], mount(ruby_stdlib, "/fixture/usr", writable=True))
    assert (tree / APP_DIR / "Newtonsoft.Json.dll").read_bytes().startswith(b"MZ")
    assert (gems / "gems/rack-3.1.7/lib/rack.rb").is_file()
    assert (gems / "gems/rake-13.2.1/lib/rake.rb").is_file()
    add_negative_evidence(tree)
    return tree, {"dotnetSdk": sdk, "dotnetRid": "linux-x64", "ruby": ruby_version, "rubyImage": RUBY}


def add_negative_evidence(tree):
    deps = tree / APP_DIR / f"{APP}.deps.json"
    published = json.loads(deps.read_bytes())
    target = published["targets"][published["runtimeTarget"]["name"]]
    target[f"{APP}/1.2.3"]["dependencies"]["Koda.Unshipped"] = "9.9.9"
    target["Koda.Unshipped/9.9.9"] = {"runtime": {"lib/net10.0/Koda.Unshipped.dll": {}}}
    published["libraries"]["Koda.Unshipped/9.9.9"] = {"type": "package", "path": "koda.unshipped/9.9.9"}
    deps.write_text(json.dumps(published, indent=2) + "\n")
    (tree / RUBY_DIR / "specifications/koda-orphan-8.9.10.gemspec").write_text(
        'Gem::Specification.new do |s|\n  s.name = "koda-orphan"\n  s.version = "8.9.10"\nend\n'
    )
    declared = tree / "opt/source-only"
    declared.mkdir()
    (declared / "Gemfile.lock").write_text(
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    koda-lock-only (7.8.9)\n\n"
        "PLATFORMS\n  ruby\n\nDEPENDENCIES\n  koda-lock-only (= 7.8.9)\n"
    )
    (declared / "packages.lock.json").write_text(json.dumps({
        "version": 1, "dependencies": {
            "net10.0": {"Koda.LockOnly": {"type": "Direct", "requested": "[7.8.9, )", "resolved": "7.8.9"}},
        },
    }) + "\n")


def summarize_cdx(document):
    records = []
    nodes = {item.get("bom-ref"): item for item in document.get("components", [])}
    # The two peer CLIs sometimes encode a manifest as a graph node instead of an
    # occurrence property. Keep that evidence when the node identifies a file.
    file_nodes = {ref: item["name"].removeprefix("/deployment/").lstrip("/")
                  for ref, item in nodes.items()
                  if item.get("type") == "file" or any(
                      entry["name"] == "aquasecurity:trivy:Class" and entry["value"] == "lang-pkgs"
                      for entry in item.get("properties", []))}
    manifests = {}
    for edge in document.get("dependencies", []):
        if edge.get("ref") in file_nodes:
            for target in edge.get("dependsOn", []):
                manifests.setdefault(target, set()).add(file_nodes[edge["ref"]])
    for item in document.get("components", []):
        if item.get("bom-ref") in file_nodes:
            continue
        paths = {i["location"].lstrip("/") for i in item.get("evidence", {}).get("occurrences", [])}
        properties = {entry["name"]: entry["value"] for entry in item.get("properties", [])}
        paths.update(value.lstrip("/") for name, value in properties.items()
                     if name.startswith("syft:location:") and name.endswith(":path"))
        paths.update(value.lstrip("/") for name, value in properties.items()
                     if name in {"aquasecurity:trivy:FilePath", "aquasecurity:trivy:SrcFile"})
        paths.update(manifests.get(item.get("bom-ref"), ()))
        records.append({"name": item["name"], "version": item.get("version"), "purl": item.get("purl"),
                        "paths": sorted(paths)})
    return sorted(records, key=lambda item: (item["name"].lower(), item["version"] or "", item["paths"]))


def run_koda(binary, tree, output, exclude=None):
    output.mkdir()
    output.chmod(0o777)
    args = ["/scanner", "scan", "--target", "/deployment", "--output-dir", "/results", "--no-context"]
    if exclude:
        args.extend(["--exclude-dir", f"/deployment/{exclude}"])
    run = docker(RUNNER, args, mount(binary, "/scanner") + mount(tree, "/deployment") +
                 mount(output, "/results", writable=True), allowed=(0, 3))
    result, = output.iterdir()
    return result, run.returncode


def verify_koda(result):
    report = validate(result)
    cyclonedx = json.loads((result / "sbom.cdx.json").read_bytes())
    spdx = json.loads((result / "sbom.spdx.json").read_bytes())
    records = summarize_cdx(cyclonedx)
    assert {r["purl"].lower() for r in records if r["purl"]} >= EXPECTED_PURLS, records
    assert not UNINSTALLED.intersection(r["name"].lower() for r in records), records
    expected_paths = {
        "newtonsoft.json": {f"{APP_DIR}/{APP}.deps.json", f"{APP_DIR}/Newtonsoft.Json.dll"},
        "benchmark": {DEFAULT_GEM},
        "rack": {f"{RUBY_DIR}/specifications/rack-3.1.7.gemspec"},
        "rake": {f"{RUBY_DIR}/specifications/rake-13.2.1.gemspec"},
        "serilog": {f"{DLL_DIR}/Serilog.dll"},
        APP.lower(): {f"{APP_DIR}/{APP}.dll"},
    }
    for package, paths in expected_paths.items():
        cdx_package, = (item for item in records if item["name"].lower() == package)
        spdx_package, = (item for item in spdx["packages"] if item["name"].lower() == package)
        comment = json.loads(spdx_package["comment"])
        assert paths <= set(cdx_package["paths"]), cdx_package
        assert paths <= {path.lstrip("/") for path in comment["evidencePaths"]}, comment
        if package in {"serilog", APP.lower()}:
            assert cdx_package["version"] and not cdx_package["purl"], cdx_package
    cdx_ids = {item["name"].lower(): item["bom-ref"] for item in cyclonedx["components"]}
    cdx_edges = {item["ref"]: item.get("dependsOn", []) for item in cyclonedx["dependencies"]}
    assert cdx_ids["newtonsoft.json"] in cdx_edges[cdx_ids[APP.lower()]], cdx_edges
    spdx_ids = {item["name"].lower(): item["SPDXID"] for item in spdx["packages"]}
    assert any(item["relationshipType"] == "DEPENDENCY_OF" and
               item["spdxElementId"] == spdx_ids["newtonsoft.json"] and
               item["relatedSpdxElement"] == spdx_ids[APP.lower()]
               for item in spdx["relationships"]), spdx["relationships"]
    return records, report


def verify_diagnostics(binary, tree, output, original_records):
    diagnostics = tree / "diagnostics"
    diagnostics.mkdir()
    path = diagnostics / "broken.deps.json"
    path.write_text('{"targets": {"KODA_DEPLOYMENT_RAW_ERROR_CANARY": @}}\n')
    (diagnostics / "not-a-managed-library.dll").write_text("ordinary file content\n")
    result, status = run_koda(binary, tree, output, "excluded")
    assert status == 3, status
    records, _ = verify_koda(result)
    assert records == original_records, (records, original_records)
    collection = json.loads((result / "collection.json").read_bytes())
    assert collection["status"] == "partial", collection
    assert any(issue.get("code") == "deployment_metadata_unreadable" and
               issue.get("path") == "diagnostics/broken.deps.json"
               for issue in collection["issues"]), collection["issues"]
    for document in result.glob("*.json"):
        assert b"KODA_DEPLOYMENT_RAW_ERROR_CANARY" not in document.read_bytes(), document.name
    return result


def verify_tracker(tracker, result, expected_status):
    script = """\
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(sys.argv[1]) / "apps/api"))
from koda_tracker.collection_coverage import coverage_for_bom
from koda_tracker.sbom import parse_sbom

result = Path(sys.argv[2])
expected_status = sys.argv[3]
expected_purls = set(sys.argv[4:])
summaries = {}
for name in ("sbom.cdx.json", "sbom.spdx.json"):
    bom, _ = parse_sbom((result / name).read_bytes())
    evidence, _ = coverage_for_bom(bom)
    coverage = evidence["collectionCoverage"]
    assert coverage["status"] == expected_status, coverage
    packages = {item["name"].lower(): item for item in bom["components"]}
    purls = {item["purl"].lower() for item in packages.values() if item.get("purl")}
    assert purls == expected_purls, purls
    assert packages["serilog"]["version"] and not packages["serilog"].get("purl"), packages["serilog"]
    if expected_status == "partial":
        assert {"code": "deployment_metadata_unreadable", "count": 1} in coverage["issueCounts"], coverage
    summaries[name] = coverage
assert summaries["sbom.cdx.json"] == summaries["sbom.spdx.json"], summaries
print(json.dumps(summaries))
"""
    return json.loads(command([
        str(tracker / ".venv/bin/python"), "-c", script, str(tracker), str(result),
        expected_status, *sorted(EXPECTED_PURLS),
    ]).stdout)


def inventory_digest(tree):
    digest = hashlib.sha256()
    count = 0
    for path in sorted(tree.rglob("*")):
        if path.is_file():
            digest.update(f"{path.relative_to(tree).as_posix()}\0{sha256(path)}\n".encode())
            count += 1
    return {"regularFiles": count, "manifestSHA256": digest.hexdigest()}


def run_peer(label, mode, work, tree):
    binary = work / label
    if mode == "dir":
        args = ["scan", "dir:/deployment", "-o", "cyclonedx-json"]
    else:
        args = [
            mode, "--format", "cyclonedx", "--offline-scan", "--skip-db-update",
            "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
            "--cache-dir", "/tmp/trivy", "/deployment",
        ]
    run = docker(RUNNER, ["/scanner", *args], mount(binary, "/scanner") + mount(tree, "/deployment"))
    document = json.loads(run.stdout)
    assert not document.get("vulnerabilities"), document.get("vulnerabilities")
    records = summarize_cdx(document)
    return {"components": records, "binarySHA256": sha256(binary),
            "sbomSHA256": hashlib.sha256(run.stdout.encode()).hexdigest(),
            "mode": mode, "arguments": args}


def describe_deltas(records):
    purls = {item["purl"].lower() for item in records if item["purl"]}
    names = {item["name"].lower() for item in records}
    return {
        "verifiedInstalledPURLs": sorted(EXPECTED_PURLS & purls),
        "missingVerifiedInstalledPURLs": sorted(EXPECTED_PURLS - purls),
        "observedStandaloneSerilog": [item for item in records if item["name"].lower() == "serilog"],
        "reportedUninstalledCanaries": sorted(names & UNINSTALLED),
    }


def exercise(binary, work, cache, dotnet, compare, tracker=None):
    download_fixtures(cache, work, compare)
    tree, build = prepare_deployment(work, cache, dotnet)
    before = inventory_digest(tree)
    result, status = run_koda(binary, tree, work / "koda")
    original_result = result
    records, schemas = verify_koda(result)
    report = {
        "passed": True, "platform": PLATFORM, "network": "none", "rootfs": "read-only",
        "sameDeploymentFixtureMountedReadOnly": True, "scannerImage": RUNNER,
        "fixture": before | build,
        "packageInputs": {name: {"source": source, "sha256": checksum}
                          for name, (source, checksum) in PACKAGES.items()},
        "releaseArchives": {name: {"source": source, "sha256": checksum}
                            for name, (source, checksum, _) in SCANNERS.items() if compare},
        "scans": {
            "koda": {"components": records, "binarySHA256": sha256(binary),
                     "exitCode": status, "validation": schemas} | describe_deltas(records),
        },
    }
    if compare:
        for label, mode in (("syft-1.55.0", "dir"), ("syft-1.57.1", "dir"),
                            ("trivy-0.76.2", "rootfs"), ("trivy-0.76.2", "fs")):
            peer = run_peer(label, mode, work, tree)
            report["scans"][f"{label}-{mode}"] = peer | describe_deltas(peer["components"])
    assert before == inventory_digest(tree), "scan changed deployment fixture"
    excluded = tree / "excluded"
    shutil.copytree(tree / APP_DIR, excluded / "koda-app")
    shutil.copytree(tree / RUBY_DIR, excluded / "ruby")
    result, _ = run_koda(binary, tree, work / "koda-exclusions", "excluded")
    excluded_records, _ = verify_koda(result)
    assert excluded_records == records, (records, excluded_records)
    report["kodaExcludedDirectoryVerified"] = True
    diagnostics_result = verify_diagnostics(binary, tree, work / "koda-diagnostics", records)
    report["kodaMalformedMetadataVerified"] = True
    if tracker:
        report["tracker"] = {
            "ordinary": verify_tracker(tracker, original_result, "completed"),
            "malformedMetadata": verify_tracker(tracker, diagnostics_result, "partial"),
        }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path, help="directory with the Linux amd64 koda-sbom binary")
    parser.add_argument("--cache", required=True, type=Path, help="workspace cache for hash-checked upstream inputs")
    parser.add_argument("--dotnet", default="dotnet", help=".NET 10 SDK executable")
    parser.add_argument("--koda-only", action="store_true", help="run identity and exclusion checks without peer scans")
    parser.add_argument("--tracker-root", type=Path, help="optional local Tracker checkout with an initialized .venv")
    args = parser.parse_args()
    binary = (args.stage / "koda-sbom").resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="koda-dotnet-ruby-") as tmp:
        tracker = args.tracker_root.resolve(strict=True) if args.tracker_root else None
        report = exercise(binary, Path(tmp).resolve(), args.cache.resolve(), args.dotnet, not args.koda_only, tracker)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
