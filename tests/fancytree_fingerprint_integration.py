#!/usr/bin/env python3
"""Check real upstream Fancytree bytes in an offline Linux scan."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zipfile

from validate_outputs import validate


REPO = Path(__file__).resolve().parents[1]
CATALOG = REPO / "internal/staticjs/fancytree_fingerprints.tsv"
PURL = "pkg:npm/jquery.fancytree@2.17.0"
POSITIVE = "dfd716a6b66607262fb51caede4c1a874093f2e16883f2dbcae068f43903687b"
AMBIGUOUS = "2ba477097c3727ba95dddf974e86fd84852b4d412fafc2bab6f6c6be3c436390"
ARCHIVED = "application.ear!/web/app.war!/ui-bundle.js"
STANDALONE = "ui/jquery.fancytree.menu.min.js"


def script(cache, version, module, expected_digest):
    path = f"package/dist/src/jquery.fancytree.{module}.js"
    with tarfile.open(cache / f"npm-{version}.tgz", mode="r:gz") as archive:
        with archive.extractfile(path) as stream:
            data = stream.read()
    assert hashlib.sha256(data).hexdigest() == expected_digest, path
    return data


def exercise(stage, cache, baseline):
    stage = stage.resolve(strict=True)
    positive = script(cache, "2.17.0", "menu", POSITIVE)
    ambiguous = script(cache, "2.5.1-0", "childcounter", AMBIGUOUS)
    with tempfile.TemporaryDirectory(prefix="koda-fancytree-fingerprint-") as temporary:
        work = Path(temporary)
        fixtures, output = work / "fixtures", work / "output"
        fixtures.mkdir()
        (fixtures / "ui").mkdir()
        output.mkdir(mode=0o777)
        output.chmod(0o777)
        (fixtures / STANDALONE).write_bytes(positive)
        (fixtures / "ui/jquery.fancytree.modified.min.js").write_bytes(positive + b"\n// local edit\n")
        war = io.BytesIO()
        with zipfile.ZipFile(war, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("ui-bundle.js", positive)
            archive.writestr("ambiguous.js", ambiguous)
        with zipfile.ZipFile(fixtures / "application.ear", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("web/app.war", war.getvalue())

        def invoke(binary, name):
            command = [
                "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "65534:65534", "--cpus", "2", "--memory", "1536m",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
                "--mount", f"type=bind,src={binary.resolve(strict=True)},dst=/koda-bom,readonly",
                "--mount", f"type=bind,src={fixtures},dst=/fixtures,readonly",
                "--mount", f"type=bind,src={output},dst=/results",
                "debian:bookworm-slim", "/koda-bom", "scan", "--target", "/fixtures",
                "--output-dir", f"/results/{name}", "--no-context",
            ]
            process = subprocess.run(command, capture_output=True, text=True, timeout=180)
            assert process.returncode == 3, (process.returncode, process.stdout, process.stderr)
            result, = (output / name).iterdir()
            return result

        result = invoke(stage / "koda-bom", "fingerprints")
        schemas = validate(result)
        collection = json.loads((result / "collection.json").read_text())
        assert collection["javascriptFingerprintCatalogSha256"] == hashlib.sha256(CATALOG.read_bytes()).hexdigest()
        assert sorted(collection["javascriptFingerprints"], key=lambda row: row["path"]) == [
            {"path": ARCHIVED, "purl": PURL, "sha256": POSITIVE},
            {"path": STANDALONE, "purl": PURL, "sha256": POSITIVE},
        ], collection
        issues = {item["path"]: item for item in collection["issues"] if "path" in item}
        collision = issues["application.ear!/web/app.war!/ambiguous.js"]
        assert collision["code"] == "static_js_fingerprint_ambiguous", collision
        assert "2.5.0, 2.5.1-0" in collision["message"], collision
        assert issues["ui/jquery.fancytree.modified.min.js"]["code"] == "static_js_identity_unconfirmed", issues
        cdx = json.loads((result / "sbom.cdx.json").read_text())
        spdx = json.loads((result / "sbom.spdx.json").read_text())
        component, = [item for item in cdx["components"] if item.get("purl", "").startswith("pkg:npm/jquery.fancytree@")]
        package, = [item for item in spdx["packages"] if item.get("name") == "jquery.fancytree"]
        assert component["purl"] == PURL and package["versionInfo"] == "2.17.0"
        assert {row["location"] for row in component["evidence"]["occurrences"]} == {ARCHIVED, STANDALONE}
        assert set(json.loads(package["comment"])["evidencePaths"]) == {ARCHIVED, STANDALONE}
        if baseline:
            old = invoke(baseline, "baseline")
            old_cdx = json.loads((old / "sbom.cdx.json").read_text())
            assert all(item.get("purl") != PURL for item in old_cdx.get("components", [])), old_cdx
    return {
        "passed": True, "validation": schemas, "network": "none",
        "fingerprintMatches": 2, "sharedBytesVersionUnconfirmed": True,
        "priorBuildMissedSameFile": True if baseline else None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True, help="verified archives from the fingerprint generator")
    parser.add_argument("--baseline", type=Path, help="optional pre-fingerprint Linux executable")
    args = parser.parse_args()
    print(json.dumps(exercise(args.stage, args.cache, args.baseline), indent=2))
