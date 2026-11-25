#!/usr/bin/env python3
"""Scan a prepared live Linux container, then replay its OBOM and assess its recorded risks."""

import argparse
import csv
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from bomset_integration import checksum, read_document
from validate_outputs import require, require_unoptimized, validate


# A 1024-bit RSA host key is a recorded weakness. Only the public half exists.
WEAK_HOST_KEY = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC2Mo9/XKp+Mz+/SGubMSoSFq/wcud8OrnONULsyqmQVKuBHtB4PfXWgZzgH"
                 "jRRpei4LdgzmmBzZGXAWEM17tdL8XMv/bF5dlUINVTveJ2t4lS4XACRXxBA57Y0WpmaaWt2ENHK8AxNq9idglnuns1J4Uwd1X6fYR"
                 "yq5zAYP5C22Q==")
# GLOBAL os.system, then REDUCE. The collector inspects opcodes and never unpickles.
DANGEROUS_PICKLE = b"\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03."
FIXTURE = {
    "etc/cron.d/report": "0 1 * * * root /usr/local/bin/report\n",
    "etc/cron.daily/clean": "#!/bin/sh\n",
    "etc/ssh/ssh_host_rsa_key.pub": WEAK_HOST_KEY + "\n",
    "etc/crypto-policies/config": "LEGACY\n",
    "etc/sysconfig/iptables": "*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 8081 -j ACCEPT\nCOMMIT\n",
    "etc/nginx/conf.d/app.conf": "upstream api { server 10.0.0.5:8080; }\nserver { location / { proxy_pass http://api; } }\n",
    "srv/models/ckpt/config.json": '{"model_type":"bert","architectures":["BertModel"]}',
}
# Port 8081 (0x1F91) is accepted by the declared firewall and stays listening
# while a client holds a loopback connection to it; port 7070 (0x1B9E) is not
# accepted. The scan starts once /proc shows both listeners and the connection.
SETUP = """set -e
cp -R /work/root/. /
chmod 755 /etc/cron.daily/clean
await() {
  i=0
  until cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk "$1"; do
    i=$((i + 1)); [ "$i" -lt 100 ] || exit 1; sleep 0.1
  done
}
nc -lk -p 8081 -e /bin/cat &
sleep 120 | nc -l -p 7070 >/dev/null &
await '$2 ~ /:1F91$/ && $4 == "0A" {a=1} $2 ~ /:1B9E$/ && $4 == "0A" {b=1} END {exit !(a && b)}'
sleep 120 | nc 127.0.0.1 8081 >/dev/null &
await '$3 ~ /:1F91$/ && $4 == "01" {f=1} END {exit !f}'
/koda-bom --cyclonedx-17 --output-dir /work/out || [ $? -eq 3 ]
"""


def exercise(binary, platform, image):
    require_unoptimized()
    binary = Path(binary).resolve(strict=True)
    report = []
    with tempfile.TemporaryDirectory(prefix="koda-runtime-smoke-") as temporary:
        work = Path(temporary)

        def run(arguments, writable=False):
            command = ["docker", "run", "--rm", "--platform", platform, "--pull", "never", "--network", "none",
                       "--security-opt", "no-new-privileges", "--memory", "2g",
                       "-v", f"{binary}:/koda-bom:ro", "-v", f"{work}:/work", image, *arguments]
            if not writable:
                command[3:3] = ["--read-only"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            require(result.returncode == 0, (arguments[:3], result.returncode, result.stdout, result.stderr))

        for name, content in FIXTURE.items():
            path = work / "root" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (work / "root/srv/models/ckpt/pytorch_model.bin").write_bytes(DANGEROUS_PICKLE)
        (work / "setup.sh").write_text(SETUP)
        run(["sh", "/work/setup.sh"], writable=True)
        results = list((work / "out").iterdir())
        require(len(results) == 1 and results[0].is_dir(), ("expected one result directory", results))
        directory = results[0]
        validate(directory)
        saas = read_document(directory / "boms" / "saasbom.cdx.json")
        require(any(s.get("name") == "api" for s in saas.get("services", [])), "declared proxy backend not discovered")
        report.append({"case": "live container scan with jobs, listeners, firewall, weak crypto, proxy and model"})

        replay = subprocess.run([sys.executable, str(Path(__file__).with_name("verify_obom_replay.py")),
                                 str(directory), str(directory)], capture_output=True, text=True, timeout=120)
        require(replay.returncode == 0, ("OBOM replay failed", replay.stdout, replay.stderr))
        counts = json.loads(replay.stdout)["counts"]
        jobs = {s["name"] for s in read_document(directory / "obom.cdx.json").get("services", [])}
        require({"cron etc/cron.d/report:1", "cron etc/cron.daily/clean"} <= jobs and counts["local_connections"] >= 1
                and counts["host_endpoints"] >= 2, ("runtime graph lacks the prepared observations", counts))
        report.append({"case": "OBOM replay of scheduled jobs, local connection and firewall verdicts",
                       "verifiedNodes": counts["verified_nodes"], "verifiedRelationships": counts["verified_relationships"]})

        inside = "/work/out/" + directory.name
        run(["/koda-bom", "assess", "--sbom", inside + "/bom.cdx.json", "--context", inside + "/context.json",
             "--output", "/work/risks.json"])
        assessment = read_document(work / "risks.json")
        risks = {(r["id"], r["componentName"]): r["status"] for r in assessment["risks"]}
        require(assessment["findings"] == [] and "advisoriesAt" not in assessment, "advisory fields without advisories")
        for identifier in ("KODA-RISK-LEGACY-CRYPTO-POLICY", "KODA-RISK-RSA-KEY-BELOW-2048", "KODA-RISK-PICKLE-DANGEROUS-IMPORTS"):
            require(any(i == identifier and s == "risk_observed" for (i, _), s in risks.items()), ("risk missing", identifier, risks))
        listeners = {name.rsplit(":", 1)[-1]: s for (i, name), s in risks.items() if i == "KODA-RISK-LISTENER-FIREWALL-ACCEPT"}
        require(listeners.get("8081") == "risk_observed" and "7070" not in listeners,
                ("only the accepted listener is a risk", listeners))
        report.append({"case": "recorded risks without advisories", "risks": len(risks)})

        busybox = [c["purl"] for c in read_document(directory / "sbom.cdx.json")["components"]
                   if c.get("purl", "").startswith("pkg:apk/alpine/busybox@")]
        require(len(busybox) == 1, ("expected one busybox package", busybox))
        base, _, query = busybox[0].partition("?")
        distro = dict(pair.split("=", 1) for pair in query.split("&"))["distro"]
        (work / "rules.json").write_text(json.dumps({"schema": "koda-advisory-rules-v1", "publishedAt": "2026-11-18T00:00:00Z", "rules": [
            {"id": "SMOKE-BUSYBOX", "source": "runtime smoke", "component": {"purl": "pkg:apk/alpine/busybox?distro=" + distro},
             "affectedVersions": [base.split("@", 1)[1]]}]}))
        run(["/koda-bom", "assess", "--sbom", inside + "/bom.cdx.json", "--context", inside + "/context.json",
             "--advisories", "/work/rules.json", "--output", "/work/advisories.json"])
        findings = read_document(work / "advisories.json")["findings"]
        require(len(findings) == 1 and findings[0]["status"] == "affected_version_observed",
                ("a host package used by running processes must match once", findings))
        report.append({"case": "advisory matches a host package once in the merged BOM"})

        run(["/koda-bom", "nis-sbom", "--sbom", inside + "/sbom.cdx.json", "--organization", "SMOKE", "--output", "/work/nis.csv"])
        with open(work / "nis.csv", encoding="utf-8-sig", newline="") as table:
            header, *rows = csv.reader(table)
        box = [row for row in rows if row[7] == "busybox"]
        require(len(header) == 20 and len(box) == 1 and box[0][0] == "NIS 1.0" and box[0][10] == "alpine"
                and box[0][14] == busybox[0] and re.fullmatch(r"SMOKE-\d{8}-000001", box[0][4]),
                ("NIS-SBOM table lacks the busybox row", header, box))
        report.append({"case": "NIS-SBOM 1.0 table of the collected SBOM", "rows": len(rows)})
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--docker-platform", choices=("linux/arm64", "linux/amd64"), default="linux/arm64")
    parser.add_argument("--image", default="alpine:3.21")
    arguments = parser.parse_args()
    print(json.dumps({"passed": True, "binarySHA256": checksum(arguments.binary),
                      "cases": exercise(arguments.binary, arguments.docker_platform, arguments.image)}, indent=2))
