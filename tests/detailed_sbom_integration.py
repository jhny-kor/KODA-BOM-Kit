#!/usr/bin/env python3
"""Verify deployed JavaScript and imported AIX evidence with a Linux amd64 binary."""

import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import subprocess
import tempfile
import zipfile

from validate_outputs import validate


LISTENER_CPE = "cpe:2.3:a:oracle:rdbms_listener:19.25.0.0.0:*:*:*:*:*:*:*"
DATABASE_CPE = "cpe:2.3:a:oracle:database_server:19.25.0.0.0:*:*:*:*:*:*:*"
ORACLE_HOME = "/u01/private-fixture/app/oracle/dbhome_1"
ORACLE_GRID_HOME = "/u01/private-fixture/app/grid"
DATABASE_NAME = "FIXTURE_DB_PRIVATE_NAME"
UNRESOLVED_JS = "assets/jquery.fancytree.childcounter.min.js"
JQUERY_PURL = "pkg:npm/jquery@3.1.1"
FANCYTREE_PURL = "pkg:npm/jquery.fancytree@2.17.0"
JQUERY_UI_PURL = "pkg:npm/jquery-ui@1.14.2"
EAR_FANCYTREE_PATH = "app.ear!/apps/app.war!/assets/jquery.fancytree.wide.min.js"
EAR_JQUERY_PATH = "app.ear!/lib/web.jar!/META-INF/resources/jquery.min.js"
BOOT_JQUERY_UI_PATH = "boot.jar!/BOOT-INF/classes/static/jquery-ui.min.js"


def js_fixture(target):
    target.mkdir()
    jquery = "/*! jQuery v3.1.1 | (c) jQuery Foundation | jquery.org/license */\n"
    fancytree = (
        "/*!\n * jquery.fancytree.wide.js\n"
        " * (Extension module for jquery.fancytree.js: https://github.com/mar10/fancytree/)\n"
        " * @version 2.17.0\n */\n"
    )
    jquery_ui = "/*! jQuery UI - v1.14.2 - 2026-01-28\n * https://jqueryui.com\n */\n"
    (target / "jquery.min.js").write_text(jquery, encoding="utf-8")
    with zipfile.ZipFile(target / "app.war", "w", zipfile.ZIP_DEFLATED) as war:
        war.writestr("assets/jquery.bundle.js", jquery)
        war.writestr("assets/jquery.fancytree.wide.min.js", fancytree)
        war.writestr("assets/jquery-ui.min.js", jquery_ui)
        war.writestr(UNRESOLVED_JS, "/* FIXTURE_RAW_JS_NEVER_EXPORT */\n")
    nested_war = io.BytesIO()
    with zipfile.ZipFile(nested_war, "w", zipfile.ZIP_DEFLATED) as war:
        war.writestr("assets/jquery.fancytree.wide.min.js", fancytree)
    nested_jar = io.BytesIO()
    with zipfile.ZipFile(nested_jar, "w", zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("META-INF/resources/jquery.min.js", jquery)
    with zipfile.ZipFile(target / "app.ear", "w", zipfile.ZIP_DEFLATED) as ear:
        ear.writestr("apps/app.war", nested_war.getvalue())
        ear.writestr("lib/web.jar", nested_jar.getvalue())
    with zipfile.ZipFile(target / "boot.jar", "w", zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("BOOT-INF/classes/static/jquery-ui.min.js", jquery_ui)


def aix_os_sources():
    return {
        "oslevel.txt": "7200-05-10-2420\n",
        "lslpp.txt": "bos.rte:bos.rte:7.2.5.0: : :C:F:Base Operating System:::::::::/:2420\n",
        "emgr.txt": "There is no efix data on this system.\n",
    }


def aix_home_sources(home, *, listener_present, patch_id, release, grid=False):
    product = "GI" if grid else "DATABASE"
    return {
        "oracle-home.txt": f"{home}\n",
        "opatch.txt": (
            f"Oracle Home : {home}\n"
            "Interim patches (1) :\n"
            f"Patch {patch_id} : applied on Tue Oct 15 02:55:20 UTC 2024\n"
            f'Patch description: "{product} RELEASE UPDATE : {release} ({patch_id})"\n'
            "OPatch succeeded.\n"
        ),
        "listener.txt": (
            "01 f7 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 02 00 00 00 00\n"
            if listener_present else "absent\n"
        ),
        "sqlpatch.csv": (
            "database_id,patch_id,action,status,action_time\n"
            f"{DATABASE_NAME},{patch_id},APPLY,SUCCESS,2024-10-15T03:00:00\n"
        ),
    }


def write_aix_fixture(directory, schema, sources):
    directory.mkdir()
    manifest = [schema]
    for name, data in sources.items():
        manifest.append(f"{name}\t{'omitted' if data is None else 'ok'}")
        if data is not None:
            path = directory / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(data, encoding="utf-8")
    (directory / "capture.tsv").write_text("\n".join(manifest) + "\n", encoding="utf-8")


def aix_fixture(directory, *, listener_present, sql_provided=True):
    sources = aix_os_sources()
    sources.update(aix_home_sources(
        ORACLE_HOME, listener_present=listener_present, patch_id="36912597", release="19.25.0.0.241015",
    ))
    if not sql_provided:
        sources["sqlpatch.csv"] = None
    write_aix_fixture(directory, "koda-aix-evidence-v1", sources)


def aix_multiple_homes_fixture(directory, *, reverse=False, unconfirmed=False):
    sources = aix_os_sources()
    database = aix_home_sources(
        ORACLE_HOME, listener_present=True, patch_id="36912597", release="19.25.0.0.241015",
    )
    grid = aix_home_sources(
        ORACLE_GRID_HOME, listener_present=True, patch_id="36916690", release="19.25.0.0.241015", grid=True,
    )
    if unconfirmed:
        grid["opatch.txt"] = grid["opatch.txt"].replace("GI RELEASE UPDATE : 19.25.0.0.241015", "Interim patch")
    grid["sqlpatch.csv"] = None
    for index, home in enumerate((grid, database) if reverse else (database, grid), start=1):
        sources.update({f"homes/{index}/{name}": data for name, data in home.items()})
    write_aix_fixture(directory, "koda-aix-evidence-v2", sources)


def load_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_export(result):
    for name in ("sbom.cdx.json", "sbom.spdx.json", "inventory.syft.json", "collection.json"):
        assert (result / name).is_file(), (result, name)
    schemas = validate(result)
    checksum_paths = {
        line.split("  ", 1)[1] for line in (result / "SHA256SUMS").read_text().splitlines()
    }
    assert checksum_paths == {path.name for path in result.iterdir() if path.name != "SHA256SUMS"}
    for path in result.glob("*.json"):
        text = path.read_text()
        for private in (ORACLE_HOME, ORACLE_GRID_HOME, DATABASE_NAME, "FIXTURE_RAW_JS_NEVER_EXPORT"):
            assert private not in text, (path.name, private)
    return schemas, load_json(result / "sbom.cdx.json"), load_json(result / "sbom.spdx.json")


def check_js(result, cdx, spdx):
    purls = {component["purl"]: component for component in cdx["components"] if component.get("purl")}
    expected = {JQUERY_PURL, FANCYTREE_PURL, JQUERY_UI_PURL}
    assert expected <= purls.keys(), sorted(purls)
    assert all(component["name"] != "extension" for component in cdx["components"])
    assert not any(purl.startswith("pkg:npm/extension@") for purl in purls)
    spdx_by_purl = {
        ref["referenceLocator"]: package for package in spdx["packages"]
        for ref in package.get("externalRefs", []) if ref["referenceType"] == "purl"
    }
    assert expected <= spdx_by_purl.keys()
    jquery = [component for component in cdx["components"] if component.get("purl") == JQUERY_PURL]
    assert len(jquery) == 1, jquery
    for component, paths in [
        (jquery[0], {"jquery.min.js", "app.war!/assets/jquery.bundle.js", EAR_JQUERY_PATH}),
        (purls[FANCYTREE_PURL], {"app.war!/assets/jquery.fancytree.wide.min.js", EAR_FANCYTREE_PATH}),
        (purls[JQUERY_UI_PURL], {"app.war!/assets/jquery-ui.min.js", BOOT_JQUERY_UI_PATH}),
    ]:
        assert {item["location"] for item in component["evidence"]["occurrences"]} == paths, component
        assert {
            item["value"] for item in component["properties"]
            if item["name"].startswith("syft:location:") and item["name"].endswith(":path")
        } == paths, component
        package = spdx_by_purl[component["purl"]]
        assert package["sourceInfo"] == "Identified from deployed JavaScript files and archive entries", package
        comment = json.loads(package["comment"])
        assert set(comment["evidencePaths"]) == paths, comment
        assert comment["observation"] == "deployed JavaScript identity evidence", comment
    assert cdx["compositions"] == [{"aggregate": "incomplete"}], cdx["compositions"]
    collection = load_json(result / "collection.json")
    assert collection["status"] == "partial", collection
    timings = collection["phaseSeconds"]
    assert {"filesystemPreflight", "staticJavaScript", "packageCatalog", "sbomOutput"} <= timings.keys(), timings
    assert all(isinstance(value, (int, float)) and math.isfinite(value) and value >= 0
               for value in timings.values()), timings
    assert any(
        issue.get("collector") == "koda-static-javascript" and UNRESOLVED_JS in issue.get("path", "")
        for issue in collection["issues"]
    ), collection["issues"]
    return sorted(expected)


def check_aix(result, cdx, spdx, *, listener_present, sql_provided=True):
    cpes = {component.get("cpe"): component for component in cdx["components"]}
    spdx_cpes = {
        ref["referenceLocator"] for package in spdx["packages"]
        for ref in package.get("externalRefs", []) if ref["referenceType"] == "cpe23Type"
    }
    assert DATABASE_CPE in cpes and DATABASE_CPE in spdx_cpes, (cpes, spdx_cpes)
    assert (LISTENER_CPE in cpes) == (LISTENER_CPE in spdx_cpes) == listener_present
    assert any(
        component["name"] == "bos.rte" and component["version"] == "7.2.5.0"
        for component in cdx["components"]
    ), cdx["components"]
    if listener_present:
        listener = cpes[LISTENER_CPE]
        assert listener["version"] == "19.25.0.0.0", listener
        metadata = json.dumps(listener["properties"])
        assert all(token in metadata for token in ("36912597", "listener.txt", "installed inventory")), metadata
    collection = load_json(result / "collection.json")
    assert collection["status"] == ("completed" if sql_provided else "partial"), collection
    assert cdx["compositions"] == [{"aggregate": "incomplete"}], cdx["compositions"]
    evidence = collection["aixEvidence"]
    assert evidence["osLevel"] == "7200-05-10-2420", evidence
    fileset, = evidence["filesets"]
    assert fileset["type"] == "F" and fileset["fixState"] == "C", fileset
    home, = evidence["oracleHomes"]
    assert home["path"] == "oracle-home/" + hashlib.sha256(ORACLE_HOME.encode()).hexdigest(), home
    assert home["listenerInstalled"] == listener_present and home["patchIds"] == ["36912597"], home
    if sql_provided:
        sql_patch, = home["sqlPatchHistory"]
        assert sql_patch["action"] == "APPLY" and sql_patch["status"] == "SUCCESS", sql_patch
    else:
        assert not home.get("sqlPatchHistory"), home
        assert any(issue["code"] == "oracle_sqlpatch_not_provided" for issue in collection["issues"])


def check_aix_multiple_homes(result, cdx, spdx, *, reverse=False):
    expected = {
        "oracle-home/" + hashlib.sha256(ORACLE_HOME.encode()).hexdigest(): {
            "prefix": "homes/2" if reverse else "homes/1", "patch": "36912597", "product": "Oracle Database Server", "basis": "database_ru",
        },
        "oracle-home/" + hashlib.sha256(ORACLE_GRID_HOME.encode()).hexdigest(): {
            "prefix": "homes/1" if reverse else "homes/2", "patch": "36916690", "product": "Oracle Grid Infrastructure", "basis": "grid_ru",
        },
    }
    collection = load_json(result / "collection.json")
    assert collection["status"] == "completed", collection["issues"]
    assert cdx["compositions"] == [{"aggregate": "incomplete"}], cdx["compositions"]
    homes = {home["path"]: home for home in collection["aixEvidence"]["oracleHomes"]}
    digests = collection["aixEvidence"]["evidenceSha256"]
    assert homes.keys() == expected.keys(), homes
    for home_id, fixture in expected.items():
        home = homes[home_id]
        assert home["evidencePrefix"] == fixture["prefix"], home
        assert home["patchIds"] == [fixture["patch"]], home
        assert home["listenerInstalled"] and home["listenerVersion"] == "19.25.0.0.0", home
        assert home["listenerVersionSource"] == "opatch_inventory_ru" and home["listenerReleaseBasis"] == fixture["basis"], home
        assert home["listenerReleasePatchIds"] == [fixture["patch"]], home

    cdx_oracle = [component for component in cdx["components"] if component["name"].startswith("Oracle ")]
    spdx_oracle = [package for package in spdx["packages"] if package["name"].startswith("Oracle ")]
    assert len(cdx_oracle) == len(spdx_oracle) == 4, (cdx_oracle, spdx_oracle)
    assert len({component["bom-ref"] for component in cdx_oracle}) == 4, cdx_oracle
    assert len({package["SPDXID"] for package in spdx_oracle}) == 4, spdx_oracle
    cdx_refs, spdx_refs = {}, {}
    for component in cdx_oracle:
        props = {prop["name"]: prop["value"] for prop in component["properties"]}
        home_id = props["syft:metadata:homeId"]
        fixture = expected[home_id]
        name = component["name"]
        assert name in {fixture["product"], "Oracle RDBMS Listener"}, component
        assert props["syft:metadata:release"] == "19.25.0.0.241015", props
        assert props["syft:metadata:opatchInventoryPatchIds:0"] == fixture["patch"], props
        assert props["syft:metadata:observation"] == "installed inventory", props
        paths = {item["location"] for item in component["evidence"]["occurrences"]}
        filename = "listener.txt" if name == "Oracle RDBMS Listener" else "opatch.txt"
        assert f"{fixture['prefix']}/{filename}" in paths, component
        assert all(path.startswith(f"{fixture['prefix']}/") for path in paths), component
        assert (component.get("cpe") == LISTENER_CPE) == (name == "Oracle RDBMS Listener"), component
        if name == "Oracle RDBMS Listener":
            assert props["syft:metadata:versionSource"] == "opatch_inventory_ru", props
            assert props["syft:metadata:inventoryStatus"] == "completed", props
            assert props["syft:metadata:listenerExecutableObserved"] == "true", props
            assert props["syft:metadata:listenerReleaseBasis"] == fixture["basis"], props
            assert props["syft:metadata:listenerReleasePatchIds:0"] == fixture["patch"], props
            for prop, filename in (("opatchEvidenceSha256", "opatch.txt"), ("listenerEvidenceSha256", "listener.txt")):
                assert props[f"syft:metadata:{prop}"] == digests[f"{fixture['prefix']}/{filename}"], props
        cdx_refs[home_id, name] = component["bom-ref"]
    for package in spdx_oracle:
        comment = json.loads(package["comment"])
        home_id = comment["homeId"]
        fixture = expected[home_id]
        name = package["name"]
        assert name in {fixture["product"], "Oracle RDBMS Listener"}, package
        assert comment["release"] == "19.25.0.0.241015", comment
        assert comment["opatchInventoryPatchIds"] == [fixture["patch"]], comment
        assert comment["observation"] == "installed inventory", comment
        filename = "listener.txt" if name == "Oracle RDBMS Listener" else "opatch.txt"
        assert f"{fixture['prefix']}/{filename}" in comment["evidencePaths"], comment
        assert all(path.startswith(f"{fixture['prefix']}/") for path in comment["evidencePaths"]), comment
        cpes = {ref["referenceLocator"] for ref in package.get("externalRefs", []) if ref["referenceType"] == "cpe23Type"}
        assert (LISTENER_CPE in cpes) == (name == "Oracle RDBMS Listener"), package
        if name == "Oracle RDBMS Listener":
            assert comment["versionSource"] == "opatch_inventory_ru" and comment["inventoryStatus"] == "completed", comment
            assert comment["listenerExecutableObserved"] and comment["listenerReleaseBasis"] == fixture["basis"], comment
            assert comment["listenerReleasePatchIds"] == [fixture["patch"]], comment
            for field, filename in (("opatchEvidenceSha256", "opatch.txt"), ("listenerEvidenceSha256", "listener.txt")):
                assert comment[field] == digests[f"{fixture['prefix']}/{filename}"], comment
        spdx_refs[home_id, name] = package["SPDXID"]
    assert cdx_refs.keys() == spdx_refs.keys() == {
        (home_id, name) for home_id, fixture in expected.items()
        for name in (fixture["product"], "Oracle RDBMS Listener")
    }
    return cdx_refs, spdx_refs


def check_unconfirmed_listener(result, cdx, spdx):
    collection = load_json(result / "collection.json")
    assert collection["status"] == "partial", collection
    assert any(issue["code"] == "oracle_listener_version_unknown" and issue["path"] == "homes/2/listener.txt"
               for issue in collection["issues"]), collection["issues"]
    cdx_listener, = (item for item in cdx["components"] if item["name"] == "Oracle RDBMS Listener" and not item.get("cpe"))
    assert not cdx_listener.get("version") and not cdx_listener.get("purl"), cdx_listener
    spdx_listener, = (item for item in spdx["packages"] if item["name"] == "Oracle RDBMS Listener" and not item.get("externalRefs"))
    assert not spdx_listener.get("versionInfo"), spdx_listener
    comment = json.loads(spdx_listener["comment"])
    assert comment["listenerExecutableObserved"] and "versionSource" not in comment and "listenerReleaseBasis" not in comment, comment
    assert "release" not in comment, comment
    assert comment["opatchInventoryPatchIds"] == ["36916690"] and "listenerReleasePatchIds" not in comment, comment


def check_tracker(tracker_root, js_result, aix_result, multiple_homes_result, unconfirmed_result):
    python = tracker_root / ".venv/bin/python"
    script = """\
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(sys.argv[1]) / "apps/api"))
from koda_tracker.collection_coverage import coverage_for_bom
from koda_tracker.cpe_analysis import enrich_cpe_findings
from koda_tracker.sbom import normalized_identity, parse_sbom
from koda_tracker.vulnerability import VulnerabilityContext

js_result, aix_result, multiple_homes_result, unconfirmed_result = map(Path, sys.argv[2:])
identifier = "CVE-2025-30733"
record = {"id": identifier, "configurations": [{"nodes": [{
    "operator": "OR", "cpeMatch": [{
        "criteria": "cpe:2.3:a:oracle:rdbms_listener:*:*:*:*:*:*:*:*",
        "vulnerable": True, "versionStartIncluding": "19.3", "versionEndIncluding": "19.26",
    }],
}]}]}
context = VulnerabilityContext(None, {}, {identifier: record}, {}, {})
formats = {}
for name in ("sbom.cdx.json", "sbom.spdx.json"):
    js, _ = parse_sbom((js_result / name).read_bytes())
    js_evidence, js_root = coverage_for_bom(js)
    assert js_evidence["collectionCoverage"]["status"] == "partial", js_evidence
    assert any(issue["code"] == "static_js_identity_unconfirmed" for issue in js_evidence["collectionCoverage"]["issueCounts"])
    assert (js_root is not None) == name.endswith(".spdx.json"), js_root
    jquery, = (entry for entry in js["components"] if entry.get("purl") == "pkg:npm/jquery@3.1.1")
    assert normalized_identity(jquery) == ("purl:pkg:npm/jquery", "identified")
    aix, _ = parse_sbom((aix_result / name).read_bytes())
    aix_evidence, aix_root = coverage_for_bom(aix)
    assert aix_evidence["collectionCoverage"]["sourceType"] == "aix-evidence", aix_evidence
    assert (aix_root is not None) == name.endswith(".spdx.json"), aix_root
    findings, summary = enrich_cpe_findings(
        [entry for entry in aix["components"] if aix_root is None or entry.get("bom-ref") != aix_root], context, []
    )
    assert summary["componentCoverage"]["evaluated"] == 1, summary
    finding, = findings
    assert finding["id"] == identifier and finding["version"] == "19.25.0.0.0", (findings, summary)
    multi_aix, _ = parse_sbom((multiple_homes_result / name).read_bytes())
    listeners = [entry for entry in multi_aix["components"] if entry["name"] == "Oracle RDBMS Listener"]
    refs = {entry["bom-ref"] for entry in listeners}
    assert len(listeners) == len(refs) == 2, listeners
    multi_findings, multi_summary = enrich_cpe_findings(multi_aix["components"], context, [])
    assert len(multi_findings) == 2 and {item["bomRef"] for item in multi_findings} == refs, (multi_findings, multi_summary)
    assert all(item["id"] == identifier for item in multi_findings), multi_findings
    assert multi_summary["addedFindings"] == 2 and multi_summary["matchedExisting"] == 0, multi_summary
    scoped = []
    for item in multi_findings:
        evidence = item["oracleHomeEvidence"]
        assert len(evidence["listenerReleasePatchIds"]) == 1, item
        patch, = evidence["listenerReleasePatchIds"]
        assert evidence["opatchInventoryPatchIds"] == [patch], item
        assert len(evidence["opatchEvidenceSha256"]) == len(evidence["listenerEvidenceSha256"]) == 64, item
        assert evidence["listenerExecutableObserved"] and evidence["versionSource"] == "opatch_inventory_ru", item
        assert evidence["inventoryStatus"] == "completed", item
        assert item.get("patchApplicability", evidence.get("patchApplicability")) == "unverified", item
        scoped.append((evidence["homeId"], patch, evidence["listenerReleaseBasis"]))
    assert len({home for home, _, _ in scoped}) == 2, scoped
    assert {(patch, basis) for _, patch, basis in scoped} == {("36912597", "database_ru"), ("36916690", "grid_ru")}, scoped
    missing_version, _ = parse_sbom((unconfirmed_result / name).read_bytes())
    unknown_listener, = (entry for entry in missing_version["components"]
                         if entry["name"] == "Oracle RDBMS Listener" and not entry.get("version"))
    confirmed, missing_summary = enrich_cpe_findings(missing_version["components"], context, [])
    assert len(confirmed) == 1 and confirmed[0]["bomRef"] != unknown_listener["bom-ref"], confirmed
    missing_reasons = missing_summary["componentCoverage"]["reasons"]
    assert {"code": "oracle_listener_version_unconfirmed", "count": 1} in missing_reasons, missing_reasons
    formats[name] = {"purl": jquery["purl"], "matchedFixtureCve": identifier,
                     "collectionCoverage": aix_evidence["collectionCoverage"], "componentCoverage": summary["componentCoverage"],
                     "listenerInventoryInstances": len(refs), "sameVersionCveFindings": len(multi_findings),
                     "listenerPatchObservations": sorted(scoped), "unconfirmedListenerReported": True}
assert formats["sbom.cdx.json"] == formats["sbom.spdx.json"], formats
print(json.dumps(formats))
"""
    process = subprocess.run(
        [str(python), "-c", script, str(tracker_root), str(js_result), str(aix_result), str(multiple_homes_result), str(unconfirmed_result)],
        capture_output=True, text=True, timeout=60,
    )
    assert process.returncode == 0, (process.stdout, process.stderr)
    return json.loads(process.stdout)


def exercise(stage, tracker_root):
    stage = stage.resolve(strict=True)
    binary = stage / "koda-bom"
    assert binary.is_file(), binary
    with tempfile.TemporaryDirectory(prefix="koda-detailed-sbom-") as temporary:
        work = Path(temporary)
        work.chmod(0o755)
        output = work / "output"
        output.mkdir()
        output.chmod(0o777)
        fixtures = work / "fixtures"
        fixtures.mkdir()
        js_fixture(fixtures / "application")
        aix_fixture(fixtures / "aix-listener", listener_present=True)
        aix_fixture(fixtures / "aix-without-listener", listener_present=False, sql_provided=False)
        aix_multiple_homes_fixture(fixtures / "aix-multiple-homes")
        aix_multiple_homes_fixture(fixtures / "aix-multiple-homes-reordered", reverse=True)
        aix_multiple_homes_fixture(fixtures / "aix-unconfirmed-listener", unconfirmed=True)
        malformed = fixtures / "aix-malformed"
        malformed.mkdir()
        (malformed / "capture.tsv").write_text("koda-aix-evidence-v1\noslevel.txt\tok\n")

        def invoke(arguments, expected):
            before = set(output.iterdir())
            command = [
                "docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", "65534:65534", "--cpus", "2", "--memory", "1536m",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=512m",
                "--mount", f"type=bind,src={stage},dst=/release,readonly",
                "--mount", f"type=bind,src={fixtures},dst=/fixtures,readonly",
                "--mount", f"type=bind,src={output},dst=/results",
                "debian:bookworm-slim", "/release/koda-bom", *arguments, "--output-dir", "/results",
            ]
            process = subprocess.run(command, capture_output=True, text=True, timeout=180)
            assert process.returncode == expected, (process.returncode, process.stdout, process.stderr)
            created = set(output.iterdir()) - before
            if expected == 2:
                assert not created and not process.stdout.strip(), (created, process.stdout)
                return None
            result, = created
            assert process.stdout.splitlines()[-1] == f"/results/{result.name}", process.stdout
            return result

        js_result = invoke(["scan", "--target", "/fixtures/application", "--no-context"], 3)
        js_schemas, js_cdx, js_spdx = verify_export(js_result)
        purls = check_js(js_result, js_cdx, js_spdx)
        aix_result = invoke(["aix-import", "--evidence", "/fixtures/aix-listener"], 0)
        aix_schemas, aix_cdx, aix_spdx = verify_export(aix_result)
        check_aix(aix_result, aix_cdx, aix_spdx, listener_present=True)
        negative_result = invoke(["aix-import", "--evidence", "/fixtures/aix-without-listener"], 3)
        negative_schemas, negative_cdx, negative_spdx = verify_export(negative_result)
        check_aix(negative_result, negative_cdx, negative_spdx, listener_present=False, sql_provided=False)
        multiple_homes = invoke(["aix-import", "--evidence", "/fixtures/aix-multiple-homes"], 0)
        multiple_schemas, multiple_cdx, multiple_spdx = verify_export(multiple_homes)
        home_refs = check_aix_multiple_homes(multiple_homes, multiple_cdx, multiple_spdx)
        reordered = invoke(["aix-import", "--evidence", "/fixtures/aix-multiple-homes-reordered"], 0)
        _, reordered_cdx, reordered_spdx = verify_export(reordered)
        assert home_refs == check_aix_multiple_homes(reordered, reordered_cdx, reordered_spdx, reverse=True)
        unconfirmed = invoke(["aix-import", "--evidence", "/fixtures/aix-unconfirmed-listener"], 3)
        unconfirmed_schemas, unconfirmed_cdx, unconfirmed_spdx = verify_export(unconfirmed)
        check_unconfirmed_listener(unconfirmed, unconfirmed_cdx, unconfirmed_spdx)
        invoke(["aix-import", "--evidence", "/fixtures/aix-malformed"], 2)
        tracker = "skipped"
        if tracker_root:
            tracker = check_tracker(tracker_root.resolve(), js_result, aix_result, multiple_homes, unconfirmed)
    return {
        "passed": True, "architecture": "linux/amd64", "network": "none", "rootfs": "read-only",
        "binarySHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "javascript": {"purls": purls, "validation": js_schemas, "nestedPaths": [
            EAR_FANCYTREE_PATH, EAR_JQUERY_PATH, BOOT_JQUERY_UI_PATH,
        ]},
        "aix": {
            "listenerCpe": LISTENER_CPE, "validation": aix_schemas,
            "partialValidation": negative_schemas, "malformedManifestRejected": True,
            "multipleHomesValidation": multiple_schemas, "oracleHomeIds": sorted({home_id for home_id, _ in home_refs[0]}),
            "oracleHomeRefsStableAcrossCaptureOrder": True,
            "unconfirmedListenerValidation": unconfirmed_schemas,
        },
        "tracker": tracker,
        "scope": "Synthetic WAR/EAR/JAR and AIX evidence. Tracker check uses parser and in-memory NVD applicability fixture.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True, type=Path, help="Directory with the Linux amd64 koda-bom binary")
    parser.add_argument("--tracker-root", type=Path, help="Optional Tracker checkout with an initialized .venv")
    args = parser.parse_args()
    print(json.dumps(exercise(args.stage, args.tracker_root), indent=2))
