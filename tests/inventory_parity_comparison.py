#!/usr/bin/env python3
"""Checks that inventory comparison distinguishes dependency and identity changes."""

import runpy
import tempfile
import unittest
from pathlib import Path

compare_run = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/compare-sbom-inventory.py"))
inventory = compare_run["inventory"]
compare = compare_run["compare"]
expected_gaps = compare_run["expected_gaps"]
deployment_digest = compare_run["deployment_digest"]
spdx_path_evidence = compare_run["spdx_path_evidence"]
compare_path_evidence = compare_run["compare_path_evidence"]
path_gaps = compare_run["path_gaps"]


def component(ref, name, version, purl=""):
    return {"bom-ref": ref, "type": "library", "name": name, "version": version, "purl": purl}


def cdx(components, edges=()):
    return {
        "bomFormat": "CycloneDX", "components": components,
        "metadata": {"component": {"bom-ref": "source", "type": "application", "name": "deployment"}},
        "dependencies": [{"ref": source, "dependsOn": [destination]} for source, destination in edges],
    }


def with_path(node, path):
    return dict(node, evidence={"occurrences": [{"location": path}]})


def spdx_inventory(components, edges):
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [{"SPDXID": node["bom-ref"], "name": node["name"], "versionInfo": node["version"],
                      "externalRefs": [{"referenceType": "purl", "referenceLocator": node["purl"]}]}
                     for node in components],
        "files": [{"SPDXID": "file-" + node["bom-ref"],
                   "fileName": node["evidence"]["occurrences"][0]["location"]} for node in components],
        "relationships": [
            {"spdxElementId": node["bom-ref"], "relatedSpdxElement": "file-" + node["bom-ref"],
             "relationshipType": "OTHER", "comment": "evident-by: package evidence"} for node in components
        ] + [{"spdxElementId": target, "relatedSpdxElement": source, "relationshipType": "DEPENDENCY_OF"}
             for source, target in edges],
    }


class ComparisonTests(unittest.TestCase):
    def test_version_change_and_direction(self):
        parent = component("p", "parent", "1", "pkg:npm/parent@1")
        child = component("c", "child", "2", "pkg:npm/child@2")
        changed = dict(child, version="3", purl="pkg:npm/child@3")
        left = inventory(cdx([parent, child], [("source", "p"), ("p", "c")]))
        right = inventory(cdx([parent, changed], [("c", "p")]))
        result = compare(left, right, "koda", "syft")
        self.assertEqual(result["versionDifferences"], [{"coordinate": "pkg:npm/child", "koda": ["2"], "syft": ["3"]}])
        self.assertEqual(result["dependenciesOnlyIn"]["koda"], [("pkg:npm/parent@1", "pkg:npm/child@2")])
        self.assertEqual(result["dependenciesOnlyIn"]["syft"], [("pkg:npm/child@3", "pkg:npm/parent@1")])
        self.assertEqual(left.other_edges, {"document->package": [("source", "p")]})

    def test_edges_distinct_and_manifest_not_counted(self):
        first = component("a", "openssl", "3", "pkg:rpm/openssl@3?arch=i686")
        second = dict(first, purl="pkg:rpm/openssl@3?arch=x86_64", **{"bom-ref": "b"})
        child = component("c", "libc", "2", "pkg:rpm/libc@2")
        manifest = {"bom-ref": "m", "type": "application", "name": "lock",
                    "properties": [{"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"}]}
        left = inventory(cdx([first, second, child, manifest], [("a", "c"), ("b", "c"), ("m", "c")]))
        right = inventory(cdx([second, child], [("b", "c")]))
        self.assertEqual(left.identities, right.identities)
        self.assertEqual(left.exact_edges - right.exact_edges,
                         {("pkg:rpm/openssl@3?arch=i686", "pkg:rpm/libc@2")})
        self.assertEqual(len(left.components), 3)
        self.assertEqual(left.excluded, {"manifest": 1})

    def test_scope_and_encoding(self):
        koda = inventory(cdx([component("a", "Fixture", "1"), component("b", "Scoped", "2", "pkg:npm/%40Legacy/Scoped@2")]))
        peer = inventory(cdx([component("a", "Fixture", "1", "pkg:nuget/Fixture@1")]))
        result = compare(koda, peer, "koda", "trivy")
        self.assertIn("pkg:npm/%40Legacy/Scoped@2", koda.identities)
        self.assertEqual(result["sameNameAndVersionWithDifferentIdentityEncoding"],
                         [["library:/Fixture@1", "pkg:nuget/fixture@1"]])
        self.assertEqual(expected_gaps(koda, set(), set(), {"library:/Fixture@1"})["unexpectedComponents"],
                         ["library:/Fixture@1"])

    def test_deployment_digest_stable_and_changes_on_content(self):
        with tempfile.TemporaryDirectory() as folder:
            deployment = Path(folder)
            (deployment / "app.js").write_text("before")
            (deployment / "shim").symlink_to("app.js")
            before = deployment_digest(deployment)
            self.assertEqual(before, deployment_digest(deployment))
            (deployment / "app.js").write_text("after")
            self.assertNotEqual(before, deployment_digest(deployment))

    def test_swapped_peer_paths_fail_with_identical_qualified_purl_edges(self):
        consumer = "pkg:npm/consumer@1.0.0"
        old_peer, new_peer = "pkg:npm/peer@4.0.0", "pkg:npm/peer@6.0.0"
        old_path = "node_modules/.pnpm/consumer@1.0.0_peer@4.0.0/node_modules/consumer/package.json"
        new_path = "node_modules/.pnpm/consumer@1.0.0_peer@6.0.0/node_modules/consumer/package.json"
        old_peer_path = "node_modules/.pnpm/peer@4.0.0/node_modules/peer/package.json"
        new_peer_path = "node_modules/.pnpm/peer@6.0.0/node_modules/peer/package.json"
        components = [with_path(component(ref, name, version, purl), path)
                      for ref, name, version, purl, path in (
                          ("a", "consumer", "1.0.0", consumer, old_path),
                          ("b", "consumer", "1.0.0", consumer, new_path),
                          ("old", "peer", "4.0.0", old_peer, old_peer_path),
                          ("new", "peer", "6.0.0", new_peer, new_peer_path),
                      )]
        bindings = [("a", "old"), ("b", "new")]
        swapped_bindings = [("a", "new"), ("b", "old")]
        correct = inventory(cdx(components, bindings))
        swapped = inventory(cdx(components, swapped_bindings))
        self.assertEqual(correct.exact_edges, swapped.exact_edges)

        correct_spdx = spdx_path_evidence(spdx_inventory(components, bindings))
        swapped_spdx = spdx_path_evidence(spdx_inventory(components, swapped_bindings))
        self.assertEqual(correct.path_evidence.edges, correct_spdx.edges)
        self.assertEqual(swapped.path_evidence.edges, swapped_spdx.edges)
        parity = compare_path_evidence(correct.path_evidence, swapped_spdx, "cyclonedx", "spdx", same_collector=True)
        self.assertEqual(parity["sharedOccurrenceCount"], 4)
        self.assertEqual(len(parity["dependenciesOnlyIn"]["cyclonedx"]), 2)
        self.assertEqual(len(parity["dependenciesOnlyIn"]["spdx"]), 2)

        expected = {"occurrences": [[consumer, old_path]],
                    "occurrenceDependencies": [[[consumer, old_path], [old_peer, old_peer_path]]],
                    "absentOccurrenceDependencies": [[[consumer, old_path], [new_peer, new_peer_path]]]}
        for observed in (correct.path_evidence, correct_spdx):
            self.assertFalse(any(path_gaps(observed, expected).values()))
        for observed in (swapped.path_evidence, swapped_spdx):
            gaps = path_gaps(observed, expected)
            self.assertEqual(len(gaps["missingOccurrenceDependencies"]), 1)
            self.assertEqual(len(gaps["unexpectedOccurrenceDependencies"]), 1)

    def test_multiple_paths_do_not_create_multiple_edges_and_missing_peer_paths_are_unverified(self):
        parent = "pkg:npm/parent@1"
        child = "pkg:npm/child@2"
        one = with_path(component("p", "parent", "1", parent), "a/package.json")
        two = with_path(component("q", "child", "2", child), "dep/package.json")
        document = cdx([one, two], [("p", "q")])
        precise = inventory(document)
        self.assertEqual(precise.path_evidence.edges, {((parent, "a/package.json"), (child, "dep/package.json"))})
        one["evidence"]["occurrences"].append({"location": "b/package.json"})
        ambiguous = inventory(document)
        self.assertEqual(ambiguous.path_evidence.edges, set())
        self.assertEqual(ambiguous.path_evidence.ambiguous_edges, {("p", "q")})
        other = inventory(cdx([component("p", "parent", "1", parent), two], [("p", "q")]))
        self.assertEqual(other.path_evidence.pathless_refs, {"p"})
        comparison = compare(precise, other, "koda", "trivy")["pathComparison"]
        self.assertEqual(comparison["sharedOccurrenceCount"], 1)
        self.assertEqual(comparison["dependenciesOnlyIn"], {"koda": [], "trivy": []})
        uncertain = path_gaps(ambiguous.path_evidence, {
            "absentOccurrenceDependencies": [[[parent, "a/package.json"], [child, "dep/package.json"]]],
        })
        self.assertEqual(len(uncertain["unverifiedAbsentOccurrenceDependencies"]), 1)

    def test_format_parity_counts_duplicate_purl_rows_and_edges_without_unique_paths(self):
        provider = with_path(component("p", "provider", "2", "pkg:npm/provider@2"), "provider/package.json")
        one = with_path(component("a", "consumer", "1", "pkg:npm/consumer@1"), "consumer/package.json")
        two = dict(one, **{"bom-ref": "b"})
        cyclonedx = inventory(cdx([provider, one, two], [("a", "p"), ("b", "p")])).path_evidence
        spdx = spdx_path_evidence(spdx_inventory([provider, one], []))
        # The original set comparison missed the duplicate row and, without
        # unique paths on either side, any of its relationships.
        comparison = compare_path_evidence(cyclonedx, spdx, "cyclonedx", "spdx", same_collector=True)
        self.assertEqual(comparison["observedOccurrencesOnlyIn"], {"cyclonedx": [], "spdx": []})
        self.assertEqual(comparison["dependenciesOnlyIn"], {"cyclonedx": [], "spdx": []})
        self.assertEqual(comparison["qualifiedPackageRowsOnlyIn"], {"cyclonedx": {one["purl"]: 1}, "spdx": {}})
        self.assertEqual(comparison["qualifiedDependenciesOnlyIn"],
                         {"cyclonedx": [(one["purl"], provider["purl"], 2)], "spdx": []})

        spdx = spdx_path_evidence(spdx_inventory([provider, one, two], [("b", "p")]))
        comparison = compare_path_evidence(cyclonedx, spdx, "cyclonedx", "spdx", same_collector=True)
        self.assertEqual(comparison["qualifiedPackageRowsOnlyIn"], {"cyclonedx": {}, "spdx": {}})
        self.assertEqual(comparison["qualifiedDependenciesOnlyIn"],
                         {"cyclonedx": [(one["purl"], provider["purl"], 1)], "spdx": []})


if __name__ == "__main__":
    unittest.main()
