# Ferramenta de validação de boot direto do kernel Oracle Linux 8.2

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
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="../../badges/release.svg" alt="v0.1.8"></a>
  <a href="../../../LICENSE"><img src="../../badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

`init.go` é o **PID 1 da VM de validação** do KODA BOM Kit. A restrição `//go:build ignore` o exclui dos testes normais de pacotes Go. Compile-o explicitamente com o comando abaixo.

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags='-s -w' -o /path/to/init tests/oracle-vm/init.go
```

Python, Go, Docker e QEMU são ferramentas de validação no PC de compilação. Entregue o executável `koda-bom` ao servidor isolado. Esta ferramenta e o interpretador Python não são dependências do executável implantado.

## Reprodução

O runner emula x86_64 com TCG em um contêiner QEMU no host ARM64. A VM possui 4 GiB de RAM e 2 vCPUs, com limite de memória do contêiner de 6 GiB. Execute na raiz do projeto no PC externo. Substitua `<ID>` pelo ID real exibido por `run.py` e preserve relatórios anteriores.

```bash
docker pull --platform linux/amd64 oraclelinux:8.2
docker build --platform linux/arm64 -t local/koda-sbom-oracle-vm:20261029 \
  -f tests/oracle-vm/Dockerfile .

python3 tests/oracle-vm/prepare.py --work-dir /tmp/koda-oracle-vm-check \
  --binary /path/to/final-release/koda-bom --go /path/to/go1.26.11/bin/go
python3 tests/oracle-vm/run.py --work-dir /tmp/koda-oracle-vm-check --flavor both --timeout 1200

# Replace <ID> with the actual run.py ID. Keep earlier validation reports.
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/rhck-<ID>/results \
  --expected-kernel 4.18.0-193.el8.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/rhck-<ID>/validation.json
python3 tests/oracle-vm/validate.py /tmp/koda-oracle-vm-check/runs/uek-<ID>/results \
  --expected-kernel 5.4.17-2011.1.2.el8uek.x86_64 --binary /path/to/final-release/koda-bom \
  --report /tmp/koda-oracle-vm-check/runs/uek-<ID>/validation.json
```

O host exige `jsonschema` e verifica offline os schemas oficiais fixados em `tests/schemas`. Downloads de preparação precisam de rede. A VM do kernel roda sem conexão externa. Preserve o ID da imagem usada porque uma tag pode mudar.

`prepare.py` verifica SHA-256 e tamanho dos quatro RPMs fixados em [kernels.json](../../../tests/oracle-vm/kernels.json), totalizando 120,245,036 bytes, e a impressão digital da chave Oracle Linux 8. Importa a chave pública para o banco RPM de um novo contêiner Oracle de teste, verifica assinaturas com `rpm -Kv` e instala kernels com `--nodeps --noscripts --notriggers`. Cria um sistema de arquivos para validar imagens de kernel, módulos e metadados RPM. Scripts normais de instalação, dracut e configuração GRUB ficam fora do procedimento.

Execute novamente `prepare.py` com o binário final no diretório existente para reconstruir coletor, PID 1 e initramfs a partir do sistema de arquivos kernel/RPM em cache. Inicie novamente as duas VMs e compare o **SHA-256 do binário final** ao baseline. Resultados de uma compilação anterior não validam uma nova versão.

Preserve `input-provenance.json`, `rpm-signature-install.log` e, por execução, `command.json`, `serial.log`, `boot-report.json`, `validation.json`, `results/baseline.json`, os dois SBOMs e checksums. A proveniência registra hashes de RPM, kernel, initramfs, PID 1 e coletor, além dos IDs das imagens Oracle/QEMU. Um relatório de validação separado associa as evidências ao SHA-256 do arquivo distribuído.

## Preparação do convidado

O initramfs contém o sistema de arquivos Oracle Linux 8.2, o banco RPM dos dois kernels instalados, imagens em `/boot`, as duas árvores `/lib/modules`, `/koda-bom` em teste e a ferramenta como `/init`. RHCK e UEK devem iniciar diretamente com suas próprias imagens. Somente contêiner ou QEMU user-mode não fornece essa evidência de boot. Opcionalmente coloque um módulo de versão correspondente extraído do RPM oficial no caminho abaixo.

```text
/vm-test/modules/<exact uname -r>/loop.ko
```

A ferramenta registra o SHA-256 do módulo e tenta carregá-lo com `init_module`. Registra estados e erros distintos quando o módulo falta, já foi carregado ou falha por assinatura/dependências. Compare `loadedModulesAfter` com `loadedModules` do coletor para confirmar o carregamento real. Um módulo não observado não comprova ausência da funcionalidade.

QEMU não recebe interface de rede externa nem disco virtual. O runner usa `-accel tcg,thread=single -cpu max -smp 2 -m 4096`. O convidado de teste usa `random.trust_cpu=on` para evitar espera de `getrandom` no início do boot. Esse argumento de teste não é recomendação de produção. Preserve configurações reais de CPU/aceleração e checksums de kernel, RPM, initramfs e coletor nos registros do host.

## Execução e coleta

A ferramenta monta `/proc`, `/sys`, `/dev`, `/tmp`, `/results` e define um hostname sintético. O baseline independente registra uname, `/proc/sys/kernel/osrelease`, OS release, módulos antes/depois, linha de comando do kernel e checksum do coletor. Hostname e linha de comando pertencem somente a essa evidência sintética de VM. A política normal de coleta permanece aplicável. O coletor executa uma vez com o comando abaixo.

```text
/koda-bom scan --output-dir /results --timeout 0 --max-files 0 \
  --exclude /vm-test/** --exclude /init --exclude /koda-bom
```

Use live-host padrão sem `--target /payload`. A validação 0.1.3 define limites de arquivos e tempo do coletor como 0 para desativá-los. O watchdog separado de 11 minutos do PID 1 e o timeout QEMU do host permanecem para liberar recursos. stdout e stderr são limitados individualmente a 1 MiB e gravados separadamente. Código de saída, tempo e erros ficam em `/results/baseline.json`. Saída 3 indica coleta parcial e deve ser preservada.

Os resultados são transmitidos pela saída serial como **base64(gzip(tar))** entre estes marcadores.

```text
KODA_VM_RESULT_BEGIN
<base64 stream>
KODA_VM_RESULT_END
```

Se o total descompactado exceder 256 MiB ou 10,000 arquivos, somente um baseline explicando a falha é exportado. Após exportar, sync e poweroff são tentados. Se falharem, PID 1 permanece ativo para evitar kernel panic. O runner do host deve encerrar QEMU se o convidado ultrapassar o prazo.

## Verificações obrigatórias

- Uname do baseline corresponde a proc release e RHCK/UEK iniciam as versões previstas.
- `context.json.mode=live-host` e `runningKernel` correspondem exatamente ao baseline independente.
- UEK informa `kernelFlavor=UEK` e RHCK segue o contrato atual `RHCK-compatible`.
- O inventário nativo preserva ambos os kernels instalados e epoch/version/release/arch/source package de cada RPM.
- Kernels instalados são diferenciados do kernel em execução identificado por context.
- `metadata.kernelVersion` e `versionMagic` correspondem a cada árvore instalada. Módulos carregados correspondem ao baseline do kernel ativo.
- Os dois schemas SBOM e checksums passam. Falhas e estados parciais são relatados fielmente.

## Limites da validação

- Kernels convidados Oracle RHCK/UEK reais são iniciados. A validação de servidores físicos x86_64 exige atividade separada.
- O espaço de usuário Oracle Linux 8.2 e kernels oficiais rodam em initramfs personalizado. Boot systemd completo, instalação GRUB, UEFI/Secure Boot, SELinux enforcing e integração de serviços de produção ficam fora do teste.
- O teste `loop` verifica carregamento e observação de um módulo real. Não cobre todos os drivers ou hardwares. Módulos instalados de kernels inativos não devem ser considerados carregados.
- Saída `3` e `collection.status=partial` são aceitas com os motivos preservados. Aprovar identificação do kernel, saída padrão e integridade não comprova coleta completa de todos os arquivos.
