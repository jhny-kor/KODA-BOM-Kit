# Validação de VM com kernel real Ubuntu 24.04.1

<!-- koda-doc-nav -->
<p align="center">
  <a href="README.md"><img src="../../badges/en.svg" alt="English"></a>
  <a href="README.ja.md"><img src="../../badges/ja.svg" alt="日本語"></a>
  <a href="README.zh.md"><img src="../../badges/zh.svg" alt="简体中文"></a>
  <a href="README.zh-hant.md"><img src="../../badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="README.ko.md"><img src="../../badges/ko.svg" alt="한국어"></a>
  <a href="README.es.md"><img src="../../badges/es.svg" alt="Español"></a>
  <a href="README.fr.md"><img src="../../badges/fr.svg" alt="Français"></a>
  <a href="README.vi.md"><img src="../../badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="README.th.md"><img src="../../badges/th.svg" alt="ไทย"></a>
  <a href="README.tr.md"><img src="../../badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="../../badges/release.svg" alt="v0.1.9"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Esta é uma ferramenta de teste do KODA BOM Kit. Não é dependência do executável implantado no servidor isolado. Inicia diretamente Ubuntu Base **24.04.1 amd64** e o kernel Ubuntu oficial **6.8.0-47-generic / pacote 6.8.0-47.47** usando initramfs personalizado. QEMU user-mode e fixtures de diretório não comprovam boot de kernel real.

O Ubuntu Base vem de um espelho arquivado da distribuição. SHA256SUMS.gpg é verificado com Ubuntu CD Image Automatic Signing Key (2012), `843938DF228D22F7B3742BC0D94AA3F0EFE21092`. O keyring do arquivo Ubuntu nesse rootfs autenticado verifica noble-updates InRelease de 2024-10-18 do serviço Snapshot oficial. A cadeia conecta Release assinado → Packages.xz → SHA-256 e tamanho dos dois DEBs. Preserve todas as URLs de entrada, checksums, logs de assinatura e IDs de imagens Docker.

O host precisa de Go, Python 3 com `jsonschema`, Docker e GnuPG (`gpg`/`gpgv`). Reutiliza a imagem de ferramentas Oracle VM. Essas ferramentas não são instaladas no servidor de destino. Execute na raiz do projeto, substituindo `<ID>` pelo ID real da execução.

```bash
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .
python3 tests/ubuntu-vm/prepare.py --work-dir /tmp/koda-sbom-ubuntu-vm-012 \
  --binary /path/to/final/koda-bom --go /path/to/go/bin/go
python3 tests/ubuntu-vm/run.py --work-dir /tmp/koda-sbom-ubuntu-vm-012
python3 tests/ubuntu-vm/validate.py /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/results \
  --binary /path/to/final/koda-bom \
  --report /tmp/koda-sbom-ubuntu-vm-012/runs/ubuntu-<ID>/validation.json
```

`init.go` reutiliza a exportação limitada e o baseline independente do Oracle. O Ubuntu possui driver loop embutido, então o teste carrega um `dummy.ko` real para verificar observação de módulos. Registra independentemente uname e proc release em execução, SO, SHA do coletor e módulos carregados. Compara os dois SBOMs com schemas oficiais fixados, checksums, versões/source/PURL DEB originais e kernels/módulos instalados. Repita prepare, run e validate sempre que fornecer um novo binário final.

O rootfs usa `dpkg --unpack` para extrair DEBs originais e criar um banco dpkg real. Exceções de dependências são permitidas e os pacotes permanecem desempacotados. Isso não comprova instalação apt normal ou configuração concluída. Boot systemd completo, GRUB, UEFI/Secure Boot, serviços de produção e hardware físico exigem testes separados. QEMU não tem NIC nem disco. Docker usa `--network none`, rootfs somente leitura e capabilities removidas. Instalação de live patches comerciais ou por assinatura fica fora do teste.

A validação 0.1.3 passa `--max-files 0 --timeout 0` para desativar os dois limites do coletor. O watchdog separado de 11 minutos do PID 1 e o timeout QEMU do host permanecem.

Preserve juntos proveniência, logs de assinatura e dpkg, `command.json`, `serial.log`, `boot-report.json`, `baseline.json`, os dois SBOMs e `validation.json`. Mantenha a saída 3 de coleta parcial. Não a converta em saída 0 de coleta completa.
