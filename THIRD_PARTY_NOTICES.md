# Third-party notices

KODA SBOM Linux source code is provided under Apache-2.0; see `LICENSE`.

This executable embeds Anchore Syft v1.57.1 and its transitive Go dependencies. These components retain their respective licenses. A release contains `licenses/inventory.json` listing the modules actually linked for Linux amd64 and copies of their license/notice texts. A missing license is reported and stops the strict release packaging step. Go standard-library licensing is included as `licenses/GO-LICENSE`. This file does not relicense those components or claim that every dependency is Apache-2.0.

Schema fixtures used only by build-host tests are copied from CycloneDX specifications 1.6 and 1.7 and SPDX specification 2.3. Their upstream license texts, source URLs and SHA-256 values are retained in `tests/schemas/`. They are not required on the target server.

Syft: https://github.com/anchore/syft/tree/v1.57.1
CycloneDX 1.6: https://github.com/CycloneDX/specification/tree/1.6
CycloneDX 1.7: https://github.com/CycloneDX/specification/tree/1.7.1
SPDX: https://github.com/spdx/spdx-spec/tree/v2.3
