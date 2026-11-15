#!/usr/bin/env python3
"""Assemble the inventory parity deployment and its independently known expectations."""

import argparse
import json
import shutil
import tempfile
from pathlib import Path

from dotnet_ruby_integration import (
    APP,
    APP_DIR,
    DEFAULT_GEM,
    DLL_DIR,
    EXPECTED_PURLS,
    RUBY_DIR,
    download_fixtures,
    inventory_digest,
    prepare_deployment,
)
from fancytree_fingerprint_integration import POSITIVE, script
from fancytree_fingerprint_integration import PURL as FANCYTREE_PURL

DOTNET_APP = f"library:/{APP}@1.2.3"
ABSENT_COMPONENTS = [
    "pkg:gem/koda-lock-only@7.8.9",
    "pkg:gem/koda-orphan@8.9.10",
    "pkg:nuget/koda.lockonly@7.8.9",
    "pkg:nuget/koda.unshipped@9.9.9",
]


def write(root, relative_path, content):
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_json(root, relative_path, document):
    write(root, relative_path, json.dumps(document, indent=2) + "\n")


def add_node_deployment(tree):
    root = tree / "opt/fixture-node"
    packages = {
        "koda-fixture-web": ("1.2.0", {"koda-fixture-router": "2.3.1"}),
        "koda-fixture-router": ("2.3.1", {"koda-fixture-util": "3.4.2"}),
        "koda-fixture-util": ("3.4.2", {}),
    }
    lock = {}
    for name, (version, dependencies) in packages.items():
        target = "" if name == "koda-fixture-web" else f"node_modules/{name}"
        manifest = {"name": name, "version": version, "license": "MIT", "main": "index.js"}
        if dependencies:
            manifest["dependencies"] = dependencies
        write_json(root / target, "package.json", manifest)
        entrypoint = "".join(f"require({json.dumps(dep)});\n" for dep in dependencies)
        write(root / target, "index.js", entrypoint + "module.exports = {};\n")
        lock[target] = manifest
    write_json(root, "package-lock.json", {
        "name": "koda-fixture-web",
        "version": "1.2.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": lock,
    })
    return {
        name: (f"pkg:npm/{name}@{version}", dependencies)
        for name, (version, dependencies) in packages.items()
    }


def add_python_deployment(tree):
    root = tree / "opt/fixture-python/venv/lib/python3.12/site-packages"
    packages = {
        "koda-fixture-worker": ("4.5.0", {"koda-fixture-common": "5.6.1"}),
        "koda-fixture-common": ("5.6.1", {}),
    }
    for name, (version, dependencies) in packages.items():
        module = name.replace("-", "_")
        metadata = f"{module}-{version}.dist-info"
        lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}", "License: MIT"]
        lines.extend(f"Requires-Dist: {dep} == {required}" for dep, required in dependencies.items())
        write(root, f"{metadata}/METADATA", "\n".join(lines) + "\n")
        write(root, f"{metadata}/RECORD", f"{module}/__init__.py,,\n{metadata}/METADATA,,\n")
        imports = "".join(f"import {dep.replace('-', '_')}\n" for dep in dependencies)
        write(root, f"{module}/__init__.py", imports + f'__version__ = "{version}"\n')
    return {
        name: (f"pkg:pypi/{name}@{version}", dependencies)
        for name, (version, dependencies) in packages.items()
    }


def build_fixture(fixture, fancytree_cache, existing_deployment, package_cache, dotnet):
    # Read the fingerprint-checked upstream JS before creating the output tree.
    javascript = script(fancytree_cache, "2.17.0", "menu", POSITIVE)
    with tempfile.TemporaryDirectory(prefix="koda-inventory-fixture-") as temporary:
        work = Path(temporary)
        if existing_deployment:
            tree = existing_deployment
        else:
            download_fixtures(package_cache, work, compare=False)
            tree, _ = prepare_deployment(work, package_cache, dotnet)
        expected_layout = (
            f"{APP_DIR}/{APP}.deps.json", f"{APP_DIR}/{APP}.dll", f"{APP_DIR}/Newtonsoft.Json.dll",
            f"{DLL_DIR}/Serilog.dll", DEFAULT_GEM,
            f"{RUBY_DIR}/specifications/rack-3.1.7.gemspec",
            f"{RUBY_DIR}/specifications/rake-13.2.1.gemspec",
        )
        for path in expected_layout:
            if not (tree / path).is_file():
                raise ValueError(f".NET/Ruby deployment is missing {path}")
        shutil.copytree(tree, fixture)
    vendor = fixture / "opt/fixture-node/public/vendor"
    vendor.mkdir(parents=True)
    (vendor / "jquery.fancytree.menu.min.js").write_bytes(javascript)

    node = add_node_deployment(fixture)
    python = add_python_deployment(fixture)
    components = set(EXPECTED_PURLS) | {FANCYTREE_PURL, DOTNET_APP, "library:/Serilog@4.2.0.0"}
    relationships = [(DOTNET_APP, "pkg:nuget/newtonsoft.json@13.0.3")]
    for ecosystem in (node, python):
        for component, dependencies in ecosystem.values():
            components.add(component)
            relationships.extend((component, ecosystem[target][0]) for target in dependencies)
    return {
        "components": sorted(components),
        "dependencies": sorted(relationships),
        "absentComponents": ABSENT_COMPONENTS,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True, help="new deployment directory")
    parser.add_argument("--expected", type=Path, required=True, help="new expectations JSON outside the deployment")
    parser.add_argument("--fancytree-cache", type=Path, required=True, help="verified npm-2.17.0.tgz from the Fancytree generator")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--dotnet-ruby", type=Path, help="existing deployment from tests/dotnet_ruby_integration.py")
    inputs.add_argument("--package-cache", type=Path, help="NuGet and RubyGems cache for the deployment rebuild")
    parser.add_argument("--dotnet", default="dotnet", help=".NET 10 SDK executable for the rebuild")
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    expected = args.expected.resolve()
    if fixture.exists() or expected.exists() or expected.is_relative_to(fixture):
        parser.error("fixture and expected must be new, and expected must be outside the fixture")
    fixture.parent.mkdir(parents=True, exist_ok=True)
    expected.parent.mkdir(parents=True, exist_ok=True)
    report = build_fixture(fixture, args.fancytree_cache.resolve(), args.dotnet_ruby,
                           args.package_cache.resolve() if args.package_cache else None, args.dotnet)
    with expected.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps(inventory_digest(fixture)))


if __name__ == "__main__":
    main()
