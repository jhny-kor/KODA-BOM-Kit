#!/usr/bin/env python3
"""Verify replay relationships against saved KODA observations, using stdlib only.

The host SBOM is deliberately never opened. Legacy container package evidence is
read one child BOM at a time. Node identities are matched by evidence properties,
independently of the exporter's reference hashing implementation.
"""

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import sys


PREFIX = "koda:obom:"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def values(item, name):
    return [p["value"] for p in item.get("properties", []) if p["name"] == name]


def prop(item, name):
    result = values(item, PREFIX + name)
    require(len(result) <= 1, "duplicate singleton OBOM property")
    return result[0] if result else ""


def socket_key(socket):
    return (socket["protocol"], socket["address"], socket["port"], socket["bindScope"])


def socket_label(socket):
    address = socket["address"]
    if ":" in address:
        address = "[" + address + "]"
    return f"{address}:{socket['port']}"


def annotation_key(value):
    protocol, endpoint = value.split("/", 1)
    endpoint, scope = endpoint.rsplit(" (", 1)
    address, port = endpoint.rsplit(":", 1)
    require(scope.endswith(")"), "invalid source socket annotation")
    return (protocol, address.removeprefix("[").removesuffix("]"), int(port), scope[:-1])


class Verifier:
    def __init__(self, source, document):
        self.source = source
        self.document = document
        self.metadata = document["metadata"]
        self.host = self.metadata["component"]
        self.host_ref = self.host["bom-ref"]
        self.components = document.get("components", [])
        self.services = document.get("services", [])
        self.nodes = {}
        for node in [self.host] + self.components + self.services:
            ref = node["bom-ref"]
            require(ref not in self.nodes, "duplicate graph reference")
            self.nodes[ref] = node
        self.edges = {}
        for row in document.get("dependencies", []):
            ref, targets = row["ref"], row.get("dependsOn", [])
            require(ref in self.nodes, "dependency source is unresolved")
            require(ref not in self.edges, "duplicate dependency source")
            require(len(targets) == len(set(targets)), "duplicate dependency target")
            require(all(target in self.nodes for target in targets), "dependency target is unresolved")
            self.edges[ref] = set(targets)
        self.expected_edges = defaultdict(set)
        self.checked = {self.host_ref}
        self.counts = Counter()

    def one(self, candidates, description):
        candidates = list(candidates)
        require(len(candidates) == 1, f"expected one {description}, found {len(candidates)}")
        node = candidates[0]
        self.checked.add(node["bom-ref"])
        return node

    def edge(self, source, target):
        if target:
            self.expected_edges[source].add(target)

    def package(self, scope, evidence):
        purl, name = evidence.get("purl", ""), evidence.get("package", "")
        if not purl and not name:
            return ""
        candidates = [node for node in self.components
                      if node.get("type") == "library" and prop(node, "scope") == scope
                      and not prop(node, "source-bom-ref")]
        if purl:
            candidates = [node for node in candidates if node.get("purl") == purl]
        else:
            candidates = [node for node in candidates if not node.get("purl")
                          and node["name"] == name
                          and node.get("version", "") == evidence.get("installedVersion", "")]
        node = self.one(candidates, "installed package owner")
        require(prop(node, "version-evidence") == "installed-owner", "package version evidence changed")
        if name:
            require(node["name"] == name, "package owner name differs from source")
            require(node.get("version", "") == evidence.get("installedVersion", ""),
                    "package owner version differs from source")
        return node["bom-ref"]

    def listener(self, scope, owner, socket, package_backed, category):
        candidates = [node for node in self.services
                      if prop(node, "scope") == scope
                      and prop(node, "observation") == "listening-socket"
                      and (prop(node, "protocol"), prop(node, "bind-address"),
                           prop(node, "port"), prop(node, "bind-scope"))
                      == (socket["protocol"], socket["address"], str(socket["port"]), socket["bindScope"])
                      and self.edges.get(node["bom-ref"], set()) == ({owner} if owner else set())]
        node = self.one(candidates, "listener with its observed owner")
        protocol = socket["protocol"].removesuffix("6")
        require(node.get("endpoints") == [protocol + "://" + socket_label(socket)],
                "listener endpoint differs from observed bind")
        require(prop(node, "owner") == ("" if owner else "unknown"), "listener ownership status changed")
        self.edge(scope, node["bom-ref"])
        self.edge(node["bom-ref"], owner)
        self.counts[category + "_endpoints"] += 1
        if package_backed:
            self.counts[category + "_package_backed_endpoints"] += 1
        if not owner:
            self.counts["unknown_owner_endpoints"] += 1

    def processes(self, scope, records, category):
        for record in records:
            node = self.one((node for node in self.components
                             if prop(node, "scope") == scope
                             and prop(node, "pid") == str(record["pid"])
                             and prop(node, "executable") == record["executable"]), "observed process")
            ref = node["bom-ref"]
            require(node.get("type") == "application" and prop(node, "state") == "running",
                    "process type or runtime state changed")
            comparable = bool(record.get("filesystemComparable"))
            require(prop(node, "filesystem-comparable") == str(comparable).lower(),
                    "process filesystem comparability changed")
            require(prop(node, "executable-deleted") == ("true" if record.get("executableDeleted") else ""),
                    "deleted executable observation changed")
            self.edge(scope, ref)
            executable_package = ""
            runtime_files = record.get("runtimeFiles", []) if comparable else []
            for evidence in runtime_files:
                file_node = self.one((self.nodes[target] for target in self.edges.get(ref, set())
                                      if self.nodes[target].get("type") == "file"
                                      and self.nodes[target]["name"] == evidence["path"]
                                      and prop(self.nodes[target], "scope") == scope), "process runtime file")
                file_ref = file_node["bom-ref"]
                for key, expected in [("state", evidence.get("state", "")),
                                      ("deleted", str(bool(evidence.get("deleted"))).lower()),
                                      ("device", evidence.get("device", "")),
                                      ("inode", str(evidence.get("inode", 0)))]:
                    require(prop(file_node, key) == expected, "runtime file evidence differs from source")
                package_ref = self.package(scope, evidence)
                self.edge(ref, file_ref)
                self.edge(file_ref, package_ref)
                self.edge(ref, package_ref)
                if evidence["path"] == record["executable"]:
                    executable_package = package_ref
                self.counts["runtime_files"] += 1
            require(prop(node, "executable-package") == executable_package,
                    "executable package owner differs from source")
            for socket in record.get("listeningSockets", []):
                self.listener(scope, ref, socket, bool(executable_package), category)
            self.counts[category + "_processes"] += 1
            if not comparable:
                self.counts["noncomparable_processes"] += 1

    def legacy_container(self, scope, directory, child):
        owners, executable_names = defaultdict(list), defaultdict(set)
        for observation in child.get("listeningSockets", []):
            for socket in observation["sockets"]:
                executable_names[socket_key(socket)].add(observation["executable"])
        path = directory / "sbom.cdx.json"
        if path.exists():
            # Only per-container BOMs are opened. Host package data is sourced
            # from context.runtimeFiles and needs no host BOM scan.
            for original in read_json(path).get("components", []):
                annotations = values(original, "koda:runtime:listening")
                if not annotations:
                    continue
                node = self.one((node for node in self.components
                                 if prop(node, "scope") == scope
                                 and prop(node, "source-bom-ref") == original["bom-ref"]),
                                "legacy container package owner")
                for key in ("type", "name", "version", "purl"):
                    require(node.get(key, "") == original.get(key, ""),
                            "legacy package identity differs from source BOM")
                require(prop(node, "version-evidence") == "installed-owner", "legacy package evidence changed")
                require(values(node, "koda:runtime:listening") == annotations, "legacy socket evidence changed")
                for annotation in annotations:
                    owners[annotation_key(annotation)].append(node["bom-ref"])
        else:
            require(prop(self.nodes[scope], "package-attribution") == "missing-cyclonedx-evidence",
                    "missing legacy package evidence was not disclosed")
        for observation in child.get("listeningSockets", []):
            node = self.one((node for node in self.components
                             if prop(node, "scope") == scope
                             and prop(node, "observation") == "listening-executable"
                             and node["name"] == observation["executable"]), "legacy listening executable")
            ref = node["bom-ref"]
            require(node.get("type") == "application" and prop(node, "state") == "running",
                    "legacy executable runtime state changed")
            self.edge(scope, ref)
            for socket in observation["sockets"]:
                key = socket_key(socket)
                unique_owner = len(owners[key]) == 1 and len(executable_names[key]) == 1
                if unique_owner:
                    self.edge(ref, owners[key][0])
                self.listener(scope, ref, socket, unique_owner, "container")
            self.counts["legacy_listening_executables"] += 1

    def verify(self):
        collection = read_json(self.source / "collection.json")
        context = read_json(self.source / "context.json")
        require(collection.get("schema") == "koda-sbom-collection-v1", "unsupported collection schema")
        require(collection.get("status") in ("completed", "partial"), "source collection was not successful")
        require(context.get("mode") == "live-host", "source is not a live-host observation")
        require(self.metadata.get("lifecycles") == [{"phase": "operations"}], "operations lifecycle missing")
        require(self.document.get("compositions") == [{"aggregate": "incomplete"}],
                "observed graph must retain incomplete coverage")
        require(self.host.get("type") == "device" and prop(self.host, "role") == "host", "host root missing")
        require(prop(self.host, "collection-status") == collection["status"], "host collection status differs")
        if collection.get("host") is not None:
            require(json.loads(prop(self.host, "host-identity")) == collection["host"], "host identity differs")
        require(self.metadata.get("timestamp", "") == collection.get("startedAt", ""), "collection time differs")
        require(prop(self.metadata, "source-status") == collection["status"], "source status differs")
        require(prop(self.metadata, "context-status") == context.get("status", ""), "context status differs")
        require(prop(self.metadata, "container-scope") == collection.get("runtimeContainerScope", "legacy-unspecified"),
                "container observation scope differs")
        require("unverified" in prop(self.metadata, "package-version-semantics"), "loaded-version uncertainty missing")
        require("unverified" in prop(self.metadata, "network-semantics"), "reachability uncertainty missing")
        for name, expected in [("distribution", collection.get("distribution")),
                               ("running-kernel", context.get("runningKernel")),
                               ("kernel-flavor", context.get("kernelFlavor")),
                               ("loaded-modules", context.get("loadedModules")),
                               ("settings", context.get("settings")),
                               ("livepatch", context.get("livepatch"))]:
            actual = prop(self.host, name)
            if expected is not None and expected != "":
                require(actual and json.loads(actual) == expected, "host runtime context differs")
        self.processes(self.host_ref, context.get("processLinks", []), "host")
        for socket in context.get("unattributedSockets", []):
            self.listener(self.host_ref, "", socket, False, "host")
        for unit in context.get("enabledServices", []):
            node = self.one((node for node in self.services
                             if prop(node, "scope") == self.host_ref
                             and prop(node, "observation") == "enabled-systemd-unit"
                             and node["name"] == unit["unit"]), "enabled systemd unit")
            require(prop(node, "state") == unit.get("state", ""), "systemd unit state differs")
            require(prop(node, "executable") == unit.get("executable", ""), "systemd executable differs")
            require(values(node, PREFIX + "declared-listen") == unit.get("listen", []), "systemd declaration differs")
            require(not node.get("endpoints"), "declared systemd listen was promoted to an observed endpoint")
            self.edge(self.host_ref, node["bom-ref"])
            self.edge(node["bom-ref"], self.package(self.host_ref, {"purl": unit.get("purl", "")}))
            self.counts["enabled_units"] += 1
        for record in collection.get("containers", []) + collection.get("images", []):
            node = self.one((node for node in self.components
                             if node.get("type") == "container"
                             and values(node, "koda:container:id") == [record["id"]]), "observed container")
            ref = node["bom-ref"]
            state = record.get("state") or ("running" if record.get("pid", 0) > 0 else "unknown")
            for key, expected in [("scope", self.host_ref), ("state", state),
                                  ("collection-status", record.get("status", "")),
                                  ("image", record.get("image", "")), ("image-id", record.get("imageId", "")),
                                  ("runtime", record.get("runtime", "")), ("pod", record.get("pod", "")),
                                  ("pod-namespace", record.get("podNamespace", ""))]:
                require(prop(node, key) == expected, "container identity or state differs")
            self.edge(self.host_ref, ref)
            self.counts["containers"] += 1
            if state != "running" or not record.get("output") or record.get("status") in ("failed", "not_collected"):
                self.counts["containers_without_runtime"] += 1
                continue
            directory = (self.source / record["output"]).resolve()
            require(directory.is_relative_to(self.source.resolve()), "child evidence escapes source directory")
            child = read_json(directory / "collection.json")
            require(child["container"]["id"] == record["id"], "parent and child container identities differ")
            if child.get("status") not in ("completed", "partial"):
                self.counts["containers_without_runtime"] += 1
                continue
            require(child["container"].get("state", "running") in ("", "running"), "child runtime state conflicts")
            observation = child.get("runtimeObservation", "")
            require(prop(node, "runtime-observation") == observation, "child observation status differs")
            if child.get("processLinks") or observation:
                self.processes(ref, child.get("processLinks", []), "container")
                self.counts["modern_containers"] += 1
                if observation in ("disabled", "unknown"):
                    self.counts["disabled_or_unknown_containers"] += 1
            else:
                require(record["id"] + ": listening executables only"
                        in values(self.metadata, PREFIX + "legacy-container-runtime"), "legacy evidence limits missing")
                self.legacy_container(ref, directory, child)
                self.counts["legacy_containers"] += 1
        runtime_refs = {ref for ref, node in self.nodes.items()
                        if ref == self.host_ref or prop(node, "scope")}
        require(runtime_refs == self.checked, "unexpected or unverified runtime graph nodes")
        for ref in runtime_refs:
            require(self.edges.get(ref, set()) == self.expected_edges[ref], "runtime dependency relationships differ")
        self.counts["verified_nodes"] = len(self.checked)
        self.counts["verified_relationships"] = sum(len(targets) for targets in self.expected_edges.values())
        return self.counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_collection", type=Path)
    parser.add_argument("replay_output", type=Path)
    args = parser.parse_args()
    paths = [args.replay_output / "obom.cdx.json"]
    companion = args.replay_output / "obom.cdx-1.7.json"
    if companion.exists():
        paths.append(companion)
    baseline = None
    counts = None
    for path in paths:
        document = read_json(path)
        expected_version = "1.7" if path == companion else "1.6"
        require(document.get("bomFormat") == "CycloneDX" and document.get("specVersion") == expected_version,
                "unexpected CycloneDX version")
        counts = Verifier(args.source_collection, document).verify()
        normalized = {key: value for key, value in document.items() if key != "specVersion"}
        if baseline is not None:
            require(normalized == baseline, "1.6 and 1.7 replay graph content differs")
        baseline = normalized
    fields = ["containers", "modern_containers", "legacy_containers", "containers_without_runtime",
              "disabled_or_unknown_containers", "host_processes", "container_processes",
              "legacy_listening_executables", "runtime_files", "noncomparable_processes", "enabled_units",
              "host_endpoints", "container_endpoints", "unknown_owner_endpoints",
              "host_package_backed_endpoints", "container_package_backed_endpoints",
              "verified_nodes", "verified_relationships"]
    # Deliberately omit source paths, host names, identifiers, and bind addresses.
    result = {field: counts[field] for field in fields}
    result["documents"] = len(paths)
    result["verified_package_backed_endpoints"] = (counts["host_package_backed_endpoints"]
                                                    + counts["container_package_backed_endpoints"])
    print(json.dumps({"status": "verified", "counts": result}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, KeyError, OSError, ValueError) as error:
        # JSON and OS exception strings can contain source paths or private data.
        detail = str(error) if isinstance(error, AssertionError) else type(error).__name__
        print("OBOM replay verification failed: " + detail, file=sys.stderr)
        sys.exit(1)
