#!/usr/bin/env python3
"""Upload KODA CycloneDX and SPDX JSON and verify Tracker inventory retention."""

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)
from uuid import UUID, uuid4

COVERAGE = "koda:collection:coverage:v1"
SPDX_ROOTS = {
    "SPDXRef-DocumentRoot-Directory-local-filesystem": "local-filesystem",
    "SPDXRef-DocumentRoot-Directory-IBM-AIX-evidence": "IBM AIX evidence",
}
SPDX_TYPES = {
    "APPLICATION": "application", "FRAMEWORK": "framework", "LIBRARY": "library",
    "CONTAINER": "container", "OPERATING-SYSTEM": "operating-system", "DEVICE": "device",
    "FIRMWARE": "firmware", "FILE": "file",
}
ROW_FIELDS = ("bomRef", "componentType", "group", "name", "version", "purl")


class VerificationError(ValueError):
    pass


@dataclass
class Document:
    file: Path
    format: str
    media_type: str
    sha256: str
    coverage: dict | None
    rows: Counter
    document_rows: list
    normalized_edges: set
    inventory_edges: Counter
    inventory: Counter
    cpe_by_ref: dict
    spdx_relationships: list | None = None


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The authenticated requests carry credentials or the SBOM. Require the
        # configured origin to handle them directly.
        return None


class Tracker:
    def __init__(self, base_url, timeout):
        url = urlsplit(base_url)
        if url.scheme not in {"https", "http"} or not url.hostname or url.username or url.password:
            raise VerificationError("KODA_TRACKER_URL must identify Tracker without URL credentials")
        if url.query or url.fragment:
            raise VerificationError("KODA_TRACKER_URL must omit query and fragment")
        if url.scheme == "http":
            try:
                loopback = ipaddress.ip_address(url.hostname).is_loopback
            except ValueError:
                loopback = url.hostname.lower() == "localhost"
            if not loopback:
                raise VerificationError("Use HTTPS to connect to Tracker outside loopback")
        self.url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()), RejectRedirects())
        self.csrf = ""

    def request(self, path, *, headers=None, data=None, status=200):
        req = Request(self.url + path, data=data, headers=headers or {})
        try:
            response = self.opener.open(req, timeout=self.timeout)
        except HTTPError as exc:
            exc.close()
            raise VerificationError(f"{req.get_method()} {path} returned HTTP {exc.code}; expected {status}") from None
        except (URLError, OSError, ValueError) as exc:
            raise VerificationError(f"{req.get_method()} {path} failed ({type(exc).__name__})") from None
        if response.status != status:
            response.close()
            raise VerificationError(f"{req.get_method()} {path} returned HTTP {response.status}; expected {status}")
        return response

    def json(self, path, payload=None, *, status=200):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        with self.request(path, data=data, headers=headers, status=status) as response:
            return json.load(response)

    def login(self, username, password):
        payload = self.json("/api/v1/auth/login", {"username": username, "password": password})
        self.csrf = payload.get("csrfToken")
        if not self.csrf:
            raise VerificationError("Tracker did not establish an authenticated session")

    def scope(self, service_id, environment_id, create_scope):
        if create_scope:
            environments = self.json("/api/v1/environments")
            if not environments:
                raise VerificationError("Tracker test instance has no active environment")
            environment_id = environments[0]["id"]
            service = self.json("/api/v1/services", {
                "slug": "inventory-check-" + uuid4().hex[:12],
                "name": "SBOM inventory parity verification",
            }, status=201)
            service_id = service["id"]
        return service_id, environment_id

    def upload(self, document, service_id, environment_id, release):
        boundary = "koda-inventory-" + uuid4().hex
        fields = {"serviceId": service_id, "environmentId": environment_id, "releaseVersion": release + "-" + document.format}
        parts = [
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'
            for key, value in fields.items()
        ]
        filename = "sbom.spdx.json" if document.format == "spdx" else "sbom.cdx.json"
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="sbom"; filename="{filename}"\r\n'
                     f"Content-Type: {document.media_type}\r\n\r\n")
        prefix = "".join(parts).encode()
        suffix = f"\r\n--{boundary}--\r\n".encode()
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}",
                   "Content-Length": str(document.file.stat().st_size + len(prefix) + len(suffix)),
                   "X-CSRF-Token": self.csrf,
                   "Idempotency-Key": uuid4().hex}
        with document.file.open("rb") as sbom:
            def upload_chunks():
                yield prefix
                while chunk := sbom.read(1024 * 1024):
                    yield chunk
                yield suffix

            with self.request("/api/v1/sbom-runs", headers=headers, data=upload_chunks(), status=202) as response:
                result = json.load(response)
        run_id = result.get("runId", "")
        if not isinstance(run_id, str) or str(UUID(run_id)) != run_id:
            raise VerificationError("Tracker did not return a valid run identifier")
        return run_id

    def components(self, path):
        result = Counter()
        total = None
        page_size = 100
        page = 1
        while True:
            response = self.json(f"{path}/components?page={page}&size={page_size}")
            if total is None:
                total = response["total"]
            expected = min(page_size, total - (page - 1) * page_size)
            items = response["items"]
            if response["total"] != total or response["page"] != page or len(items) != expected:
                raise VerificationError("Tracker component pagination is inconsistent")
            result.update(tuple(item.get(field) or "" for field in ROW_FIELDS) for item in items)
            if page * page_size >= total:
                return result, total
            page += 1


def digest(stream):
    sha256 = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        sha256.update(chunk)
    return sha256.hexdigest()


def cdx_components(bom):
    pending = list(reversed(bom.get("components", [])))
    while pending:
        row = pending.pop()
        yield row
        pending.extend(reversed(row.get("components", [])))


def cdx_rows(bom):
    return Counter((
        row.get("bom-ref") or "", row.get("type") or "library", row.get("group") or "",
        row.get("name") or row.get("bom-ref") or "unknown", row.get("version") or "", row.get("purl") or "",
    ) for row in cdx_components(bom))


def cdx_edges(bom):
    return {(row["ref"], target) for row in bom.get("dependencies", []) for target in row.get("dependsOn", [])}


def metadata_values(bom, name):
    return [prop["value"] for prop in bom.get("metadata", {}).get("properties", []) if prop.get("name") == name]


def spdx_refs(package, category, types):
    candidates = {
        ref["referenceLocator"] for ref in package.get("externalRefs", [])
        if ref["referenceCategory"] == category and ref["referenceType"] in types
    }
    if len(candidates) > 1:
        raise VerificationError("SPDX package has conflicting identity references")
    return next(iter(candidates), "")


def inventory_view(rows, document_refs, edges):
    components = Counter()
    by_ref = {}
    for row, count in rows.items():
        ref, _, _, name, version, purl = row
        if ref in document_refs:
            continue
        identity = (name, version, purl)
        components[identity] += count
        if ref:
            if ref in by_ref or count != 1:
                raise VerificationError("Source SBOM uses a duplicate component reference")
            by_ref[ref] = identity
    translated_edges = Counter(
        (by_ref[source], by_ref[target]) for source, target in edges
        if source in by_ref and target in by_ref
    )
    return components, translated_edges


def load_document(path, format, *, require_coverage=True):
    with path.open("rb") as source:
        sha256 = digest(source)
        source.seek(0)
        bom = json.load(source)
    document_rows = []
    relationships = None
    if format != "spdx":
        if bom.get("bomFormat") != "CycloneDX":
            raise VerificationError("CycloneDX input must be a CycloneDX JSON document")
        raw_claim = metadata_values(bom, COVERAGE)
        if len(raw_claim) > 1 or (require_coverage and not raw_claim):
            raise VerificationError("CycloneDX input is missing a unique KODA collection claim")
        coverage = json.loads(raw_claim[0]) if raw_claim else None
        rows = cdx_rows(bom)
        edges = cdx_edges(bom)
        cpes = {row.get("bom-ref", ""): row["cpe"] for row in cdx_components(bom) if row.get("cpe")}
        # Syft encodes operating-system metadata as a CycloneDX component. KODA
        # reports the observed packages separately. Keep this row in API/DB checks.
        if coverage is not None and sum(rows.values()) == coverage["componentCount"] + 1:
            for row in bom.get("components", []):
                ref = row.get("bom-ref", "")
                name, version = row.get("name"), row.get("version", "")
                distro_id = [p["value"] for p in row.get("properties", []) if p.get("name") == "syft:distro:id"]
                if (row.get("type") == "operating-system" and not row.get("purl")
                        and ref == (f"os:{name}@{version}" if version else f"os:{name}")
                        and distro_id == [name] and row.get("swid", {}).get("tagId") == name):
                    document_rows.append({"bomRef": ref, "reason": "cyclonedxDistributionMetadata"})
        media = "application/vnd.cyclonedx+json"
    else:
        if bom.get("spdxVersion") != "SPDX-2.3" or not bom.get("comment", "").startswith(COVERAGE + " "):
            raise VerificationError("--spdx must point to a KODA SPDX 2.3 JSON document")
        coverage = json.loads(bom["comment"][len(COVERAGE) + 1:])
        packages = {p["SPDXID"]: p for p in bom.get("packages", [])}
        if len(packages) != len(bom.get("packages", [])):
            raise VerificationError("Source SPDX has duplicate package identifiers")
        relationships = bom.get("relationships", [])
        rows = Counter((
            ref, SPDX_TYPES.get(p.get("primaryPackagePurpose"), "library"), "", p["name"],
            p.get("versionInfo") or "", spdx_refs(p, "PACKAGE-MANAGER", {"purl"}),
        ) for ref, p in packages.items())
        cpes = {}
        for ref, package in packages.items():
            if cpe := spdx_refs(package, "SECURITY", {"cpe23Type", "cpe22Type"}):
                cpes[ref] = cpe
        edges = set()
        describes = set()
        for relation in relationships:
            left, right, kind = (relation[k] for k in ("spdxElementId", "relatedSpdxElement", "relationshipType"))
            if kind == "DESCRIBES" and left == "SPDXRef-DOCUMENT":
                describes.add(right)
            if left in packages and right in packages:
                if kind == "DEPENDS_ON":
                    edges.add((left, right))
                elif kind == "DEPENDENCY_OF":
                    edges.add((right, left))
        if len(describes) == 1:
            ref = next(iter(describes))
            package = packages.get(ref)
            if (ref in SPDX_ROOTS and package and package.get("name") == SPDX_ROOTS[ref]
                    and package.get("primaryPackagePurpose") == "FILE"
                    and not package.get("versionInfo") and not package.get("externalRefs")):
                document_rows.append({"bomRef": ref, "reason": "spdxDocumentRoot"})
        media = "application/spdx+json"
    refs = {entry["bomRef"] for entry in document_rows}
    if len(refs) > 1 or (coverage is not None and sum(rows.values()) - len(document_rows) != coverage.get("componentCount")):
        raise VerificationError(f"{format} source count disagrees with its collection coverage")
    inventory, inventory_edges = inventory_view(rows, refs, edges)
    return Document(path, format, media, sha256, coverage, rows, document_rows,
                    edges, inventory_edges, inventory, cpes, relationships)


def row_diff(expected, actual, fields):
    return {
        "missing": [dict(zip(fields, row), count=count) for row, count in sorted((expected - actual).items())],
        "added": [dict(zip(fields, row), count=count) for row, count in sorted((actual - expected).items())],
    }


def edge_counts(edges):
    return [{"from": source, "to": target, "count": count}
            for (source, target), count in sorted(edges.items())]


def verify_normalized(document, run_id, exporter, timeout):
    if not exporter:
        return {"status": "notRun", "reason": "Tracker's public API exposes component rows and original bytes only"}
    try:
        environment = {key: value for key, value in os.environ.items() if not key.startswith("KODA_TRACKER_")}
        process = subprocess.run([str(exporter.resolve()), run_id], capture_output=True, check=True, timeout=timeout,
                                 env=environment)
        result = json.loads(process.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise VerificationError("Could not read normalized Tracker BOM using the configured exporter") from None
    if not isinstance(result, dict) or result.get("bomFormat") != "CycloneDX":
        raise VerificationError("Normalized BOM exporter must write a CycloneDX JSON object")
    rows = row_diff(document.rows, cdx_rows(result), ROW_FIELDS)
    edges = cdx_edges(result)
    missing, added = sorted(document.normalized_edges - edges), sorted(edges - document.normalized_edges)
    cpes = {row.get("bom-ref", ""): row["cpe"] for row in cdx_components(result) if row.get("cpe")}
    preserved_relationships = None
    if document.spdx_relationships is not None:
        originals = metadata_values(result, "koda:spdx:relationships")
        preserved_relationships = False
        if len(originals) == 1:
            try:
                preserved_relationships = json.loads(originals[0]) == document.spdx_relationships
            except (TypeError, ValueError):
                pass
    passed = not (rows["missing"] or rows["added"] or missing or added or cpes != document.cpe_by_ref
                  or preserved_relationships is False)
    return {
        "status": "passed" if passed else "failed", "componentRows": rows, "cpeMatched": cpes == document.cpe_by_ref,
        "dependencyEdges": len(edges), "missingDependencyEdges": missing, "addedDependencyEdges": added,
        "retainedOriginalSpdxRelationships": preserved_relationships,
    }


def verify_upload(tracker, document, service, environment, release, args):
    run_id = tracker.upload(document, service, environment, release)
    path = "/api/v1/sbom-runs/" + run_id
    with tracker.request(path + "/artifact") as artifact:
        downloaded_sha256 = digest(artifact)
    detail = tracker.json(path)
    actual, total = tracker.components(path)
    difference = row_diff(document.rows, actual, ROW_FIELDS)
    normalized = verify_normalized(document, run_id, args.normalized_bom_command, args.timeout)
    hash_matches = document.sha256 == downloaded_sha256 == detail.get("sha256")
    coverage_matches = ("collectionCoverageState" not in detail and (
        detail.get("collectionCoverage") == document.coverage if document.coverage is not None
        else "collectionCoverage" not in detail
    ))
    passed = (hash_matches and coverage_matches and not difference["missing"] and not difference["added"]
              and total == detail.get("componentCount") and normalized["status"] != "failed")
    return {
        "passed": passed, "runId": run_id, "uploadStatus": 202, "sourceSha256": document.sha256,
        "artifactSha256": downloaded_sha256, "originalUnchanged": hash_matches,
        "sourceComponentRows": sum(document.rows.values()), "trackerComponentRows": total,
        "collectedComponents": document.coverage["componentCount"] if document.coverage is not None else None,
        "formatMetadataRows": document.document_rows, "coverageMatches": coverage_matches,
        "collectionStatus": document.coverage["status"] if document.coverage is not None else None,
        "sourceDependencyEdges": len(document.normalized_edges), "componentRows": difference, "normalized": normalized,
    }


def write_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cyclonedx", type=Path, required=True)
    parser.add_argument("--spdx", type=Path, required=True)
    parser.add_argument("--peer-cyclonedx", action="append", nargs=2, default=[], metavar=("NAME", "PATH"),
                        help="also upload a named third-party CycloneDX JSON document")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--service-id")
    parser.add_argument("--environment-id")
    parser.add_argument("--create-test-service", action="store_true",
                        help="create a dedicated service using the first active environment in a disposable Tracker")
    parser.add_argument("--normalized-bom-command", type=Path,
                        help="optional read-only executable that receives a run ID and prints its persisted normalized BOM")
    parser.add_argument("--timeout", type=float, default=360, help="request and exporter timeout in seconds")
    args = parser.parse_args()
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    if args.create_test_service:
        if args.service_id or args.environment_id:
            parser.error("--create-test-service cannot be combined with scope IDs")
    elif not (args.service_id and args.environment_id):
        parser.error("provide --service-id and --environment-id, or --create-test-service")
    if args.normalized_bom_command and not (
        args.normalized_bom_command.is_file() and os.access(args.normalized_bom_command, os.X_OK)
    ):
        parser.error("--normalized-bom-command must be an executable file")
    peers = {}
    for name, path in args.peer_cyclonedx:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", name) or name in {"cyclonedx", "spdx"} or name in peers:
            parser.error("--peer-cyclonedx names must be unique short lowercase identifiers")
        peers[name] = Path(path)
    if args.output.resolve() in {path.resolve() for path in (args.cyclonedx, args.spdx, *peers.values())}:
        parser.error("--output must differ from the input files")
    credentials = [os.environ.get(name) for name in ("KODA_TRACKER_URL", "KODA_TRACKER_USERNAME", "KODA_TRACKER_PASSWORD")]
    if not all(credentials):
        parser.error("set KODA_TRACKER_URL, KODA_TRACKER_USERNAME and KODA_TRACKER_PASSWORD")
    report = {"schemaVersion": 1, "passed": False, "uploads": {}}
    try:
        cdx = load_document(args.cyclonedx, "cyclonedx")
        spdx = load_document(args.spdx, "spdx")
        identities = row_diff(cdx.inventory, spdx.inventory, ("name", "version", "purl"))
        spdx_only = spdx.inventory_edges - cdx.inventory_edges
        cdx_only = cdx.inventory_edges - spdx.inventory_edges
        encoding_parity = cdx.coverage == spdx.coverage and not (
            identities["missing"] or identities["added"] or spdx_only or cdx_only)
        report["sourceFormatParity"] = {
            "passed": encoding_parity, "componentDifferencesFromCycloneDX": identities,
            "packageDependencyEdges": {"cyclonedx": sum(cdx.inventory_edges.values()),
                                       "spdx": sum(spdx.inventory_edges.values())},
            "onlyCycloneDxPackageEdges": edge_counts(cdx_only), "onlySpdxPackageEdges": edge_counts(spdx_only),
        }
        tracker = Tracker(credentials[0], args.timeout)
        tracker.login(*credentials[1:])
        service, environment = tracker.scope(args.service_id, args.environment_id, args.create_test_service)
        release = "inventory-check-" + uuid4().hex[:12]
        for document in (cdx, spdx):
            report["uploads"][document.format] = verify_upload(tracker, document, service, environment, release, args)
        for name, path in peers.items():
            try:
                peer = load_document(path, name, require_coverage=False)
                report["uploads"][name] = verify_upload(tracker, peer, service, environment, release, args)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                report["uploads"][name] = {
                    "passed": False,
                    "error": str(exc) if isinstance(exc, VerificationError) else f"Verification failed ({type(exc).__name__})",
                }
        report["passed"] = encoding_parity and all(item["passed"] for item in report["uploads"].values())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # Never persist/expose a credential, sent headers, or remote response body.
        report["error"] = str(exc) if isinstance(exc, VerificationError) else f"Inventory verification failed ({type(exc).__name__})"
    write_report(args.output, report)
    if not report["passed"]:
        print(f"Tracker inventory verification failed. See {args.output}", file=sys.stderr)
        return 1
    print(f"Tracker inventory verification passed. Evidence at {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
