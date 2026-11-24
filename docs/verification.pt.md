# Compilação e verificação

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="verification.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="verification.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

O KODA BOM Kit 0.1.9 fornece um arquivo offline Linux amd64 e SHA-256. Identifique o binário testado pelo hash exato e ambiente. A coleta Linux abrange x86_64 e ARM64, e arquivos Docker/OCI são tratados como linux/amd64. O inventário macOS/Windows usa comandos fixos de leitura. A execução Windows continua sem verificação. Resultados antigos correspondem às respectivas compilações.

[Publicação 0.1.9](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9)

## Formatos e integridade

Os padrões são CycloneDX 1.6 e SPDX 2.3. `--cyclonedx-17` acrescenta 1.7 usando o mesmo inventário. Com `--format cyclonedx`, gera dois documentos. Com `--format spdx`, a combinação é recusada antes da saída. `scan`, `aix-import`, `asset-import`, `platform-inventory`, `reconcile` e os auxiliares aceitam a opção. Confira os arquivos esperados conforme as opções.

| Saída | Formato |
|---|---|
| `sbom.cdx.json` | CycloneDX 1.6 |
| `sbom.spdx.json` | SPDX 2.3 |
| `sbom.cdx-1.7.json` | CycloneDX 1.7 (`--cyclonedx-17`) |

```bash
./koda-bom scan --target /path/to/input --no-context \
  --output-dir /path/to/results --format both --cyclonedx-17
python3 tests/validate_outputs.py /path/to/actual-scan-result
```

`tests/validate_outputs.py` verifica esquemas locais, identidades, evidências, propriedades, significado das licenças, relações, escopo e entradas ausentes/duplicadas no manifesto. Os esquemas 1.7 vêm de 1.7.1, commit `b29bae660048e0ad2fbc5f2972927b442ce951c4`, com procedência em `tests/schemas/provenance.json`. São 704 licenças em 1.6 e 811 em 1.7. As 107 adicionais usam `license.name` em 1.6 e `license.id` em 1.7. Confira também coleta parcial em `collection.json`.

## Verificação na máquina de compilação

Prepare Go, Python, Docker, módulos em cache e dependências dos esquemas. `trusted_go_sha256` deve ser o hash verificado do Go. `GOPROXY=off` usa o cache preparado. O controle de publicação recusa `python3 -O` e `PYTHONOPTIMIZE`. O servidor executa o binário empacotado. No macOS, use `shasum -a 256 -c SHA256SUMS`.

```bash
go test -count=1 ./...
go vet ./...
python3 -m pip install 'jsonschema>=4,<5'
GOPROXY=off ./scripts/build-release.sh --go /path/to/go --go-sha256 "$trusted_go_sha256"
python3 tests/release_guards.py
stage=/path/to/unpacked-linux-amd64-release
(cd "$stage" && sha256sum -c SHA256SUMS)
python3 tests/check_binary.py "$stage/koda-bom"
python3 tests/docker_integration.py --binary "$stage/koda-bom"
python3 tests/directory_integration.py --stage "$stage"
```

## Testes de integração

Execute os comandos na distribuição final extraída. Prepare caches antes de desligar a rede. .NET/Ruby requer SDK .NET 10. Go/Rust requer módulos em cache e o ELF ripgrep fixado, ou `--rust-binary`. Fancytree compara npm SHA-512 ou GitHub SHA-256. Testes compatíveis aceitam `--tracker-root /path/to/tracker` para o analisador real local.

`domain_bom_integration.py` executa o binário diretamente. Rode esse teste em Linux amd64.

```bash
python3 tests/default_bom_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/bomset_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/runtime_smoke_integration.py --binary "$stage/koda-bom" --docker-platform linux/amd64
python3 tests/domain_bom_integration.py --binary "$stage/koda-bom"
python3 tests/dotnet_ruby_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/go_rust_binary_integration.py --stage "$stage" --go /path/to/go
python3 scripts/generate-fancytree-fingerprints.py --cache /path/to/upstream-cache --check
python3 tests/fancytree_fingerprint_integration.py --stage "$stage" --cache /path/to/upstream-cache
python3 tests/multi_directory_integration.py --stage "$stage"
python3 tests/supplier_reconcile_integration.py --stage "$stage"
python3 tests/detailed_sbom_integration.py --stage "$stage"
python3 tests/livepatch_integration.py --stage "$stage"
```

Os testes cobrem Java aninhado, pyz/pex, Go/Rust, procedência, limites de diretórios, hashes de fornecedor, PURL e dependências. Casos Linux cobrem sockets, contêineres, firmware, serviços, configuração, integridade e certificados. Casos AIX verificam Oracle Home, Listener e OPatch. BMC/NIC/OT físicos, armazenamento Kubernetes real e clientes de patches com assinatura precisam de evidências do ambiente. GitHub Actions (`.github/workflows/ci.yml`) executa a cada push em `main` e a cada pull request a formatação, vet para todos os alvos de build, os testes Go, as proteções de release, a verificação do binário e as suítes de contêiner acima que não exigem caches externos; `docs.yml` verifica alterações só de documentação. Builds de release, suítes com caches externos e verificações em VM continuam no host de build.

[tests/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests) · [tests/schemas/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/tests/schemas) · [scripts/](https://github.com/jhny-kor/KODA-BOM-Kit/blob/v0.1.9/scripts)

## Kernels Linux e reprodução de VM

Execute testes exclusivos de Linux em Linux. O macOS pode compilá-los para a arquitetura do contêiner. Use o binário final nas VM. RHCK `4.18.0-193.el8.x86_64` e UEK R6 `5.4.17-2011.1.2.el8uek.x86_64` iniciam separadamente com RPM assinados em `tests/oracle-vm/kernels.json`. Preserve procedência, assinaturas, IDs de imagens, logs seriais, referência e validações.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go test -c -o hostcontext.test ./internal/hostcontext
docker run --rm --network none -v "$PWD":/repo:ro -w /repo/internal/hostcontext \
  debian:bookworm-slim /repo/hostcontext.test
```

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200
python3 tests/oracle-vm/validate.py /path/to/actual-rhck-run/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-rhck-run/validation.json
python3 tests/oracle-vm/validate.py /path/to/actual-uek-run/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /path/to/actual-uek-run/validation.json
```

O executor Oracle usa QEMU system TCG, 4 GiB, duas CPUs e PID 1 estático próprio, sem rede ou disco do convidado. Verifica uname, proc, carregamento de loop e kernels instalados/ativos. Ubuntu inicia `6.8.0-47-generic` a partir de pacotes autenticados. GRUB, UEFI/Secure Boot, systemd completo, SELinux enforcing, drivers físicos e serviços exigem testes adicionais. Contêineres Oracle compartilham o kernel do host.

[Oracle VM](tests/oracle-vm/README.pt.md) · [Ubuntu VM](tests/ubuntu-vm/README.pt.md)

## Chamadas de sistema, recursos e análise

Rastreie o binário final em contêiner isolado. Se a emulação ARM64 não interpretar ptrace, `trace-network.sh` retorna 77. Uma alternativa é QEMU guest syscall, com o ambiente registrado. Afirmar zero tentativas requer rastreamento válido. Clientes e daemons chamados pelo auxiliar livepatch têm comportamento de rede próprio.

```bash
docker build --platform linux/amd64 -t local/koda-sbom-trace:20261029 -f tests/Dockerfile.trace .
bash tests/trace-network.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results

docker build --platform linux/arm64 -t local/koda-sbom-qemu-trace:20261029 -f tests/Dockerfile.qemu-trace .
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-results
bash tests/trace-qemu.sh /path/to/koda-bom /path/to/fixture /path/to/qa-live-host live-host
```

Os limites são 1,000,000 arquivos regulares selecionados e 30 minutos. Teste limites, opções inválidas, cancelamento, permissões, corrupção e exclusões. `--max-files 0 --timeout 0` remove esses limites. Registre duração e RSS máximo do caso real. Duas tarefas paralelas não impõem teto de memória. Tracker usa banco temporário isolado e ambos os formatos. Avisos locais dependem de regras e observações. Implantação e correção de CVE exigem evidência própria.

## Documentação

[Execução offline e inspeção](air-gapped.pt.md) · [Compilação e verificação](verification.pt.md) · [Resultados de verificação](verification-results.pt.md)
