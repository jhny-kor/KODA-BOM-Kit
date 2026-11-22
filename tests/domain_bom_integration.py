#!/usr/bin/env python3
"""Check evidence-derived service, model and manufacturing BOMs through the CLI."""

import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from bomset_integration import checksum, edges, entities, read_document, verify_references, write_document
from validate_outputs import require, require_unoptimized, validate


CANARY = "DOMAIN_FIXTURE_PRIVATE_VALUE"


def properties(item):
    return {prop["name"]: prop["value"] for prop in item.get("properties", [])}


def create_fixtures(work):
    weights = work / "model.safetensors"
    header = json.dumps({"weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                         "__metadata__": {"private": CANARY}}, separators=(",", ":")).encode()
    weights.write_bytes(struct.pack("<Q", len(header)) + header + struct.pack("<f", 1.0))
    model = work / "model.json"
    write_document(model, {"schema": "koda-model-1", "name": "fixture model", "version": "1.0",
                           "sha256": checksum(weights), "license": "Apache-2.0", "task": "text-generation",
                           "architecture": "transformer", "source": "https://example.invalid/model",
                           "baseModels": [{"name": "base model", "version": "0.9"}],
                           "datasets": [{"name": "training dataset", "version": "2026-11", "license": "CC0-1.0"}]})
    services = work / "services.json"
    write_document(services, {"schema": "koda-services-1", "services": [
        {"id": "frontend", "name": "frontend", "provider": "fixture provider", "version": "1.0",
         "endpoints": ["https://example.invalid/frontend"], "authenticated": True, "trustBoundary": True,
         "trustZone": "external", "data": [{"flow": "outbound", "classification": "confidential", "name": "customer record"}],
         "dependsOn": ["backend"]},
        {"id": "backend", "name": "backend", "endpoints": ["https://example.invalid/backend"]},
    ]})
    api = work / "openapi.json"
    write_document(api, {"openapi": "3.1.0", "info": {"title": "declared API", "version": "2.0"},
                        "servers": [{"url": "https://example.invalid/api"}], "security": [{"bearer": []}],
                        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
                        "paths": {"/public": {"get": {"security": [], "responses": {"200": {"description": "OK"}}}}},
                        "x-private-fixture": CANARY})
    artifact = work / "product.bin"
    artifact.write_bytes(b"fixture build output\n")
    provenance = work / "provenance.json"
    write_document(provenance, {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "product.bin", "digest": {"sha256": checksum(artifact)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {"buildType": "https://example.invalid/build/v1",
                                "externalParameters": {"secret": CANARY},
                                "internalParameters": {"secret": CANARY},
                                "resolvedDependencies": [{"uri": "https://example.invalid/source.tar", "digest": {"sha256": "a" * 64}}]},
            "runDetails": {"builder": {"id": "https://example.invalid/builder"},
                           "metadata": {"invocationId": "fixture-job-42", "startedOn": "2026-11-21T00:00:00Z",
                                        "finishedOn": "2026-11-21T00:01:00Z"}},
        },
    })
    manufacturing = work / "manufacturing.json"
    write_document(manufacturing, {"schema": "koda-manufacturing-1", "observedAt": "2026-11-21T00:00:00Z",
                                   "observation": "reported", "product": {"id": "device", "name": "assembled device"},
                                   "parts": [{"id": "board", "name": "main board", "partNumber": "BOARD-1"}],
                                   "steps": [{"name": "assemble board", "action": "assembly", "inputIds": ["board"]},
                                             {"name": "inspect device", "action": "inspection"}]})
    return {"manufacturing": manufacturing, "weights": weights, "model": model, "services": services, "api": api,
            "artifact": artifact, "provenance": provenance}


def verify_formulation(document):
    all_refs = {}
    resources = []
    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            if "bom-ref" in value:
                require(value["bom-ref"] not in all_refs, "duplicate formulation reference")
                all_refs[value["bom-ref"]] = value
            if "ref" in value:
                resources.append(value["ref"])
            for item in value.values():
                visit(item)
    visit(document)
    require(set(resources) <= all_refs.keys(), "unresolved formulation resource")
    for formula in document.get("formulation", []):
        for workflow in formula.get("workflows", []):
            task_refs = {task["bom-ref"] for task in workflow.get("tasks", [])}
            for edge in workflow.get("taskDependencies", []):
                require(edge["ref"] in task_refs and set(edge.get("dependsOn", [])) <= task_refs,
                        "invalid task dependency")


def exercise(binary):
    require_unoptimized()
    binary = Path(binary).resolve(strict=True)
    report = []
    with tempfile.TemporaryDirectory(prefix="koda-domain-bom-qa-") as directory:
        work = Path(directory)
        fixtures = create_fixtures(work)
        output = work / "output"
        output.mkdir()

        def invoke(arguments, success=True):
            before = set(output.iterdir())
            result = subprocess.run([str(binary), "domain-bom", "--output-dir", str(output), *map(str, arguments)],
                                    capture_output=True, text=True, timeout=180)
            if not success:
                require(result.returncode != 0, "invalid evidence accepted")
                require(set(output.iterdir()) == before, "failed evidence conversion published output")
                require(CANARY not in result.stdout + result.stderr, "private fixture leaked in error")
                return None
            require(result.returncode == 0, (result.returncode, result.stderr))
            created = set(output.iterdir()) - before
            require(len(created) == 1, "domain conversion must publish one directory")
            target = created.pop()
            require(Path(result.stdout.strip()).resolve() == target.resolve(), "CLI output path mismatch")
            validation = validate(target)
            for path in target.glob("*.json"):
                require(CANARY not in path.read_text(), "private evidence fields exported")
            return target, validation

        arguments = ["--saas-evidence", fixtures["services"], "--saas-evidence", fixtures["api"],
                     "--model-evidence", fixtures["model"], "--model-artifact", fixtures["weights"],
                     "--provenance", fixtures["provenance"], "--provenance-artifact", fixtures["artifact"],
                     "--cyclonedx-17"]
        target, validation = invoke(arguments)
        for prefix in ("saasbom", "aibom", "mbom"):
            for suffix in (".cdx.json", ".cdx-1.7.json"):
                require((target / (prefix + suffix)).is_file(), "domain output missing")
                verify_references(read_document(target / (prefix + suffix)))
        saas = read_document(target / "saasbom.cdx.json")
        services = {service["name"]: service for service in saas["services"]}
        front, back, api = [services[name] for name in ("frontend", "backend", "declared API")]
        require((front["bom-ref"], "dependsOn", back["bom-ref"]) in edges(saas), "service dependency lost")
        require(front["authenticated"] is True and front["x-trust-boundary"] is True, "service trust metadata lost")
        require(front["data"][0]["classification"] == "confidential" and front["data"][0]["flow"] == "outbound",
                "service data flow lost")
        require(api["authenticated"] is False, "anonymous OpenAPI operation interpreted as authentication required")
        model_doc = read_document(target / "aibom.cdx.json")
        components = {item["name"]: item for item in model_doc["components"]}
        model = components["fixture model"]
        require(model["hashes"] == [{"alg": "SHA-256", "content": checksum(fixtures["weights"])}], "model artifact hash mismatch")
        require(properties(model)["koda:domain:format"] == "safetensors", "model format observation lost")
        for name in ("base model", "training dataset"):
            require((model["bom-ref"], "dependsOn", components[name]["bom-ref"]) in edges(model_doc), "model lineage lost")
        require(model["modelCard"]["modelParameters"]["datasets"] == [{"ref": components["training dataset"]["bom-ref"]}],
                "model-card dataset reference lost")
        manufacturing = read_document(target / "mbom.cdx.json")
        product = next(item for item in manufacturing["components"]
                       if any(h.get("content") == checksum(fixtures["artifact"]) for h in item.get("hashes", [])))
        require(manufacturing.get("formulation"), "manufacturing formulation missing")
        verify_formulation(manufacturing)
        require(any("https://example.invalid/source.tar" in json.dumps(item) for item in manufacturing["components"]),
                "build input missing")
        require("https://example.invalid/builder" in json.dumps(manufacturing), "builder evidence missing")
        require(any(edge[0] == product["bom-ref"] for edge in edges(manufacturing)), "build product relationships missing")
        report.append({"case": "three domain BOMs in both schema versions", "validation": validation,
                       "serviceCount": len(services), "modelComponents": len(components)})

        standalone, _ = invoke(["--model-artifact", fixtures["weights"]])
        doc = read_document(standalone / "aibom.cdx.json")
        require(len(doc["components"]) == 1 and properties(doc["components"][0])["koda:domain:model-metadata"] == "local-header-observation",
                "standalone model artifact observation missing")
        report.append({"case": "local safetensors observation without declaration"})

        physical, _ = invoke(["--provenance", fixtures["manufacturing"], "--cyclonedx-17"])
        document = read_document(physical / "mbom.cdx.json")
        verify_formulation(document)
        workflow = document["formulation"][0]["workflows"][0]
        tasks = {task["name"]: task for task in workflow["tasks"]}
        require(set(tasks) == {"assemble board", "inspect device"}, "manufacturing steps lost")
        assembly, inspection = tasks["assemble board"], tasks["inspect device"]
        require(workflow["taskDependencies"] == [{"ref": inspection["bom-ref"], "dependsOn": [assembly["bom-ref"]]}],
                "manufacturing step order lost")
        report.append({"case": "physical assembly and inspection evidence without a software artifact"})

        changed = work / "changed-artifact"
        changed.write_bytes(b"different fixture")
        invoke(["--model-evidence", fixtures["model"], "--model-artifact", changed], success=False)
        invoke(["--provenance", fixtures["provenance"], "--provenance-artifact", changed], success=False)
        bad = work / "bad-services.json"
        value = read_document(fixtures["services"])
        value["services"][0]["dependsOn"] = ["missing-service"]
        write_document(bad, value)
        invoke(["--saas-evidence", bad], success=False)
        value["services"][0]["dependsOn"] = ["backend"]
        value["services"][0]["endpoints"] = ["https://user:" + CANARY + "@example.invalid/api"]
        write_document(bad, value)
        invoke(["--saas-evidence", bad], success=False)
        invoke(["--model-evidence", fixtures["model"]], success=False)
        invoke(["--provenance", fixtures["provenance"]], success=False)
        report.append({"case": "rejected mismatched artifacts, missing pairs, unknown dependency and credential-bearing endpoint"})
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps({"passed": True, "binarySHA256": checksum(args.binary), "cases": exercise(args.binary)}, indent=2))
