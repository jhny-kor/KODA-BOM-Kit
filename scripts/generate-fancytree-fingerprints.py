#!/usr/bin/env python3
"""Regenerate the embedded Fancytree fingerprint table on a connected build host."""

import argparse
import base64
import concurrent.futures
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from urllib.request import HTTPRedirectHandler, Request, build_opener


PACKAGE = "jquery.fancytree"
REGISTRY = "https://registry.npmjs.org/" + PACKAGE
GITHUB = "https://github.com/mar10/fancytree"
CODELOAD = "https://codeload.github.com/mar10/fancytree/tar.gz/"
TABLE = Path(__file__).resolve().parents[1] / "internal/staticjs/fancytree_fingerprints.tsv"
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?")
SCRIPT = re.compile(r"dist/(?:src/|modules/)?jquery\.fancytree(?:\.[a-z0-9-]+)?(?:\.min)?\.js")
MAX_ARCHIVE = 8 << 20
MAX_DECOMPRESSED = 64 << 20
MAX_SCRIPT = 512 << 10


def npm_tarball(version):
    return f"{REGISTRY}/-/{PACKAGE}-{version}.tgz"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"unexpected redirect from {req.full_url}")


def fetch(url, limit=MAX_ARCHIVE, headers=None):
    with build_opener(NoRedirect()).open(Request(url, headers=headers or {}), timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"download size exceeded limit for {url}")
    return data


def version_key(version):
    main, separator, prerelease = version.partition("-")
    return (*map(int, main.split(".")), not separator, prerelease)


def valid_npm_integrity(value):
    if not value.startswith("sha512-"):
        raise ValueError("npm release is missing SHA-512 integrity")
    if len(base64.b64decode(value.removeprefix("sha512-"), validate=True)) != 64:
        raise ValueError("invalid npm SHA-512 integrity")


def read_pins(table):
    npm, github = {}, {}
    for line in table.read_text(encoding="ascii").splitlines():
        if line.startswith("# npm\t"):
            _, version, integrity = line.split("\t")
            valid_npm_integrity(integrity)
            if not VERSION.fullmatch(version) or version in npm:
                raise ValueError(f"invalid or repeated npm version pin: {version}")
            npm[version] = integrity
        elif line.startswith("# github\t"):
            _, version, commit, digest = line.split("\t")
            if (not VERSION.fullmatch(version) or version in github
                    or not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise ValueError(f"invalid or repeated GitHub pin: {version}")
            github[version] = (commit, digest)
    if not npm or not github:
        raise ValueError("expected npm and early GitHub release pins in the existing catalog")
    return npm, github


def refresh_npm(pins):
    metadata = json.loads(fetch(REGISTRY, headers={"Accept": "application/vnd.npm.install-v1+json"}))
    if metadata.get("name") != PACKAGE:
        raise ValueError("unexpected npm package metadata")
    for version, record in metadata["versions"].items():
        if not VERSION.fullmatch(version):
            raise ValueError(f"unexpected published version: {version}")
        dist = record["dist"]
        if dist["tarball"] != npm_tarball(version):
            raise ValueError(f"unexpected registry artifact for {version}")
        integrity = dist["integrity"]
        valid_npm_integrity(integrity)
        if version in pins and pins[version] != integrity:
            raise ValueError(f"npm SHA-512 pin changed for {version}")
        pins[version] = integrity


def verify_archive(data, integrity, algorithm, url):
    if algorithm == "sha512":
        actual = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    else:
        actual = hashlib.sha256(data).hexdigest()
    if actual != integrity:
        raise ValueError(f"{algorithm} integrity mismatch for {url}")


def collect_release(source, version, pin, cache):
    if source == "npm":
        url, prefix, algorithm, integrity = npm_tarball(version), "package/", "sha512", pin
    else:
        commit, integrity = pin
        url, prefix, algorithm = CODELOAD + commit, f"fancytree-{commit}/", "sha256"
    cached = cache / f"{source}-{version}.tgz" if cache is not None else None
    if cached is not None and cached.exists():
        if cached.stat().st_size > MAX_ARCHIVE:
            raise ValueError(f"cached archive exceeds limit: {cached}")
        data = cached.read_bytes()
    else:
        data = fetch(url)
    verify_archive(data, integrity, algorithm, url)
    if cached is not None and not cached.exists():
        cached.write_bytes(data)

    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        raw = compressed.read(MAX_DECOMPRESSED + 1)
    if len(raw) > MAX_DECOMPRESSED:
        raise ValueError(f"inflated archive exceeds limit for {url}")

    selected, manifest = {}, None
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            if not member.name.startswith(prefix):
                continue
            name = member.name.removeprefix(prefix)
            if name == "package.json":
                if manifest is not None or not member.isfile() or not 0 < member.size <= 65536:
                    raise ValueError(f"invalid package manifest in {url}")
                with archive.extractfile(member) as stream:
                    manifest = json.load(stream)
            elif SCRIPT.fullmatch(name) and ".ui-deps." not in name:
                if name in selected or not member.isfile() or not 0 < member.size <= MAX_SCRIPT:
                    raise ValueError(f"invalid published script {name} in {url}")
                with archive.extractfile(member) as stream:
                    selected[name] = hashlib.sha256(stream.read()).hexdigest()

    if not isinstance(manifest, dict) or manifest.get("name") != PACKAGE or manifest.get("version") != version:
        raise ValueError(f"package name or version mismatch for {url}")
    repo = manifest.get("repository", {})
    if not isinstance(repo, dict) or repo.get("url") not in {GITHUB, GITHUB + ".git", "git+" + GITHUB + ".git"}:
        raise ValueError(f"unexpected package repository for {url}")
    if not selected:
        raise ValueError(f"no supported distribution scripts in {url}")
    return {(digest, version) for digest in selected.values()}


def generate(npm, github, cache):
    lines = [
        "# Generated by scripts/generate-fancytree-fingerprints.py. Exact upstream Fancytree JavaScript bytes.",
        f"# npm tarballs: {REGISTRY}/-/{PACKAGE}-<version>.tgz (SHA-512 integrity)",
        f"# Early GitHub tags: {GITHUB}/releases (tag commit and archive SHA-256)",
        "# Scope: dist core and first-party individual modules. Bundles with dependencies are excluded.",
        "# One SHA-256 can occur in multiple releases. Keep all SHA-256, version pairs.",
    ]
    lines.extend(f"# npm\t{version}\t{npm[version]}" for version in sorted(npm, key=version_key))
    lines.extend(f"# github\t{version}\t{github[version][0]}\t{github[version][1]}" for version in sorted(github, key=version_key))
    releases = [("npm", version, pin) for version, pin in npm.items()]
    releases.extend(("github", version, pin) for version, pin in github.items())
    rows = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        for result in executor.map(lambda args: collect_release(*args, cache), releases):
            rows.update(result)
    lines.extend(f"{digest}\t{version}" for digest, version in sorted(rows))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh-npm", action="store_true", help="include newly published pinned npm versions")
    parser.add_argument("--cache", type=Path, help="use or populate a cache of verified release archives")
    parser.add_argument("--check", action="store_true", help="verify reproducibility without writing the table")
    args = parser.parse_args()
    if args.cache is not None:
        args.cache.mkdir(parents=True, exist_ok=True)
    npm, github = read_pins(TABLE)
    if args.refresh_npm:
        refresh_npm(npm)
    data = generate(npm, github, args.cache)
    if args.check:
        if data.encode("ascii") != TABLE.read_bytes():
            raise SystemExit("fingerprint table does not match verified release archives")
    else:
        TABLE.write_bytes(data.encode("ascii"))


if __name__ == "__main__":
    main()
