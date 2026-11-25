# Inventário de hardware e software

<!-- koda-doc-nav -->
<p align="center">
  <a href="asset-inventory.md"><img src="badges/en.svg" alt="English"></a>
  <a href="asset-inventory.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="asset-inventory.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="asset-inventory.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="asset-inventory.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="asset-inventory.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="asset-inventory.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="asset-inventory.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="asset-inventory.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="asset-inventory.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.9"><img src="badges/release.svg" alt="v0.1.9"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Use `koda-bom` compilado para o sistema e CPU de destino. No Linux, `scan` coleta pacotes e hardware. No Windows/macOS, `platform-inventory` chama ferramentas locais do sistema.

```sh
./koda-bom scan --output-dir ./reports

./koda-bom scan --output-dir ./reports --asset-tag 'web-01'

./koda-bom scan --output-dir ./reports --cyclonedx-17

./koda-bom scan --asset-evidence ./bmc.json --asset-evidence ./nic.json --output-dir ./reports

./koda-bom asset-import --asset-evidence ./network-assets.json --output-dir ./reports

./koda-bom platform-inventory --output-dir ./reports
```

No PowerShell, use `.\koda-bom.exe platform-inventory --output-dir .\reports`. Diretórios/imagens usam o sistema de arquivos selecionado. Hardware ativo é observado no host `/` com contexto habilitado. Arquivos Docker/OCI suportam Linux amd64. Importe um CycloneDX verificado no Tracker e mantenha versões e checksums juntos.

## Evidências coletadas

| Área | Conteúdo e interpretação |
|---|---|
| Hardware | CPU/microcódigo, mitigações, placa, BIOS/UEFI, ESRT, PCI/drivers, NVMe/SCSI, USB, TPM. RAID/HBA `mpt3sas`, `qla2xxx`, `lpfc`, `hpsa`, `smartpqi`, RDMA `fw_ver`, NVIDIA Video BIOS, amdgpu `vbios_version`. NIC por ioctl somente leitura equivalente a `ethtool -i`. megaraid_sas exige exportação. Como root, a tabela SMBIOS bruta fornece fabricante, número de peça, capacidade e velocidade dos módulos de memória, modelo e potência das fontes e slots com seu endereço PCI; números de série são registrados como SHA-256 |
| BMC | IPMI `Get Device ID` somente leitura via `/dev/ipmi0`, com root e `ipmi_si`/`ipmi_devintf`. Revisão, fabricante IANA, produto e revisão auxiliar. Ausências explicadas. Redfish ajuda a comparar versões públicas do fabricante |
| CPU | x86 `cpuidSignature`/`familyModelStepping`, topologia, fabricante/núcleo ARM e revisão como `r3p1`. Núcleos desconhecidos preservam códigos. USB `bcdDevice` identifica a revisão do dispositivo |
| Externos | Redfish expandido, fwupd/devlink JSON e esquema comum. Firmware ativo/armazenado separado, campos dependentes do modelo |
| Execução | Substituições de executáveis/bibliotecas, identidade do arquivo e pacote proprietário único. `restart_review` indica substituição. A versão em memória exige evidências além da versão instalada |
| Identidade | SHA-256 de machine-id e UUID/séries DMI normalizados no host `/`, mesmo com `--no-context`. machine-id/UUID em minúsculas, séries sem espaços externos. Valores genéricos/UUID zero omitidos. Hashes são pseudônimos potencialmente dedutíveis. `--asset-tag` aceita uma linha de 128 caracteres. Contêiner `container-visible` |
| Sockets | TCP LISTEN/UDP sem conexão no namespace do coletor, atribuídos por descritores. `bindScope` é `all-interfaces`, `loopback`, `address`. Alcance de firewall/roteamento requer evidência separada. Sem proprietário em `context.json.unattributedSockets`. Conexões TCP de saída estabelecidas são registradas por processo e destino em `outboundConnections`, com `remoteScope` (`loopback`, `private`, `link-local`, `public`, `local-host`) |
| Segurança/reinício | SELinux atual/configurado, AppArmor/perfis, lockdown, FIPS e argumentos permitidos. Credenciais excluídas. `kernelConfig` lê `y`/`m` de `/proc/config.gz` ou `/boot/config-<running-kernel>`. Reboot-required, módulos atuais ausentes e kernel mais novo da mesma família geram sinais. Com sinais `reboot.recommended=true`, caso contrário `not_observed`. Família inferida da versão |
| SSH | Declarações globais `sshd_config`/`sshd_config.d/*.conf`, como `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `KbdInteractiveAuthentication`, `LoginGraceTime`, `MaxStartups`, `X11Forwarding`, `AllowTcpForwarding`. Exclui `Match`. Valores efetivos dependem de `Include` |
| Módulos/programas | `kernel.tainted`, `taintedModules`, nomes, `O`/`E`/`P`, version/srcversion. Mesmo root sem pacote/componente/produto em `unidentifiedExecutables`, caminho/PID. Trata usr-merge |
| Integridade | Hashes RPM/dpkg/apk contra executáveis/`.so`. Exclui configuração/ghost. `modified`/`missing` em `collection.json.integrity.findings` e propriedades. 8 GiB/host, 1 GiB/contêiner, depois `partial`. prelink pode causar diferenças |
| Origem | apt Packages texto/gz/lz4 por nome, histórico dnf, yum `from_repo`. `repository`, `local-file`, `not-recorded`. Histórico ausente, dnf5/apk sem classificação. Omite URL/caminhos. DB dnf copiada temporariamente e aberta somente leitura |
| Inicialização | systemd wants/requires, units/drop-ins, primeiro `ExecStart`, ativação por socket, PURL. Exclui units mascaradas. Processos em `system.slice` determinam estado, slices próprios podem parecer parados. Timers habilitados registram o agendamento `On*` e o serviço que iniciam |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge dispositivo/BIOS e Lenovo ThinkSystem dispositivo. Modelos desconhecidos, HPE/BMC sem CPE inferido |
| Certificados | Impressão X.509, validade, algoritmos, tamanho/estado. SHA-1/MD5, RSA <2048, DSA. Algoritmos clássicos `nistQuantumSecurityLevel=0`. Exclui nomes de sujeito/emissor e chaves privadas. Ignora lojas do sistema e arquivos >20 certificados. Chaves públicas de host SSH (`etc/ssh/ssh_host_*_key.pub`) também são registradas com a impressão SHA-256 do OpenSSH |
| Aplicações | snap ativo/DEB embutido, flatpak ativo/AppStream, conda com nome do canal, `.pyz`/`.pex`, JAR, JS estático, Go/Rust. Hashes Docker/OCI e digests verificados |

## Contêineres e resultados

Cada contêiner ativo recebe `containers/<name>/`. Kubernetes usa namespace/pod/contêiner e adiciona 12 caracteres de ID em colisões. Metadados Docker/containerd/Podman/CRI-O são lidos em disco, sem API. O root é localizado por dispositivos mountinfo. Inclui camadas de imagem/escrita, exclui volumes/bind mounts. Sockets pertencem aos processos do contêiner, priorizando pacotes e main module para Go. Root invisível/tempo excedido gera `not_collected` com motivo. `--no-containers` desativa a coleta.

Contêineres parados e imagens não usadas suportam Docker overlay2, containerd overlayfs com k3s/RKE2 e Podman/CRI-O rootful. Reconstrói camadas temporariamente com whiteout/opaque e apaga a cópia após coleta. Omite dispositivos e bits set-ID. Ignora root >16 GiB ou espaço menor que tamanho +1 GiB. Estado `state: stopped` ou `state: image`, sem sockets. Mudanças concorrentes podem impedir a coleta. Outros drivers/Podman rootless não suportados. `--no-images` desativa essa etapa.

Gera sete perfis em `boms/` e combina em `bom.cdx.json`. AI-BOM usa `aibom.cdx.json`. Saídas compatíveis CycloneDX 1.6 `sbom.cdx.json` e SPDX 2.3 `sbom.spdx.json`, 1.7 opcional via `--cyclonedx-17`. SPDX usa `OTHER` e anotações sem tipo equivalente. Host `koda:host:*`, contêiner `koda:container:*`, sockets `koda:runtime:listening`/`koda:runtime:bind-scope`. Confira `assets.json`, `context.json`, `collection.json`, `inventory.syft.json`, verifique `SHA256SUMS`.

## Evidência comum de ativos

Até oito arquivos, 8 MiB cada. `parentId` referencia `id` do mesmo arquivo. Omita versões desconhecidas. Redfish exige objetos expandidos, além das listas URI. SHA-256 identifica o arquivo importado.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-18T01:00:00Z",
  "assets": [
    {"id": "board", "kind": "device", "name": "Controller", "model": "Model-A"},
    {
      "id": "firmware",
      "parentId": "board",
      "kind": "firmware",
      "name": "Controller firmware",
      "version": "1.2",
      "properties": {"applicationState": "Active", "storedVersion": "1.3"}
    }
  ]
}
```

## Ativos criptográficos e TLS

Certificados, chaves públicas e algoritmos tornam-se `cryptographic-asset`. Emissores candidatos são verificados por assinatura. Diretivas permitidas Nginx/Apache/sshd são evidência de configuração. JKS v1/v2 preserva cadeias públicas e SHA-256 de alias, ignora chaves cifradas e indica integridade `not-verified` sem senha.

Importe metadados públicos PKCS#12/HSM/KMS por `--asset-evidence`. `related-crypto-material` aceita tipo/tamanho/estado, `algorithmRef`, `properties.storageType`, `keyAlias`. O `dependsOn` do consumidor referencia a chave no mesmo arquivo.

O exemplo mostra negociação TLS medida externamente. Substitua impressões, destino e horário. Hash correspondente liga serviço → protocolo → certificado.

```json
{
  "schema": "koda-assets-1",
  "observedAt": "2026-11-21T01:00:00Z",
  "assets": [
    {
      "id": "cert", "kind": "cryptographic-asset", "name": "Peer certificate",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
    },
    {
      "id": "session", "kind": "cryptographic-asset", "name": "TLS session",
      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
        "type": "tls", "version": "1.3", "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384"}]
      }},
      "properties": {
        "endpoint": "example.invalid:443", "transport": "tcp",
        "sessionObservedAt": "2026-11-21T01:00:00Z", "observationState": "negotiated",
        "certificateSHA256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      }
    }
  ]
}
```

## Avaliação offline

Reavalie resultados arquivados com novos avisos.

```sh
./koda-bom assess \
  --sbom ./reports/COLLECTION/bom.cdx.json \
  --context ./reports/COLLECTION/context.json \
  --advisories ./advisory-rules.json \
  --kev ./known_exploited_vulnerabilities.json \
  --output ./assessment.json
```

`--advisories`/`--context`/`--kev` são opcionais. Contexto verifica SBOM e contexto via `SHA256SUMS`. KEV acrescenta prioridade. Aceita regras explícitas, OSV com versões/PURL exatos, CSAF 2.0 com IDs exatos/status incondicional. Intervalos, condições ou combinações sem suporte interrompem a avaliação com motivo.

```json
{
  "schema": "koda-advisory-rules-v1",
  "publishedAt": "2026-11-18T00:00:00Z",
  "rules": [
    {
      "id": "EXAMPLE-2026-001",
      "source": "Example vendor advisory",
      "component": {"kind": "firmware", "name": "BMC firmware", "model": "Model-A"},
      "affectedVersions": ["1.0"],
      "fixedVersions": ["1.1"],
      "remediation": "Verify firmware activation according to the vendor advisory"
    },
    {
      "id": "LOCAL-IP-FORWARD",
      "source": "Internal server baseline",
      "setting": {"product": "Linux kernel", "name": "net.ipv4.ip_forward", "equals": "0"}
    }
  ]
}
```

Use distro com release e versões exatas. Conflitos SBOM/PURL geram `review_required`. Considera epoch RPM. Máximo 1.000.000 entradas exatas por execução. Regras aceitam `supportEndsAt` e `affectedSemver` em ecossistemas compatíveis. Arquivos substituídos/firmware armazenado exigem revisão de ativação. Ativos desconhecidos/versões fora dos avisos exigem revisão. Compare Linux físico/Windows com o inventário do fabricante. Inventário nativo Windows/macOS concentra-se em OS, hardware e aplicações instaladas.

O array `risks` do relatório lista os riscos que o coletor registrou no BOM, com origem `KODA collection evidence`; eles não exigem arquivo de avisos e ficam separados dos `findings` de avisos. `sbom.cdx.json` e `sbom.spdx.json` contêm os riscos criptográficos, e o `bom.cdx.json` combinado acrescenta os de AI-BOM e OBOM. Em `bom.cdx.json`, os avisos ignoram os nós OBOM que repetem um pacote do host; pacotes de contêineres em execução são comparados por meio de seus nós OBOM, que cobrem apenas os pacotes usados por seus processos. Avalie `containers/<name>/sbom.cdx.json` para o inventário completo de um contêiner. `risk_observed` indica que a evidência registrada mostra a condição; `review_required`, que ela não pôde ser descartada.

| ID da constatação | Status | Evidência registrada |
|---|---|---|
| `KODA-RISK-RSA-KEY-BELOW-2048`, `KODA-RISK-DSA-KEY` | `risk_observed` | Certificado ou chave de host SSH com RSA abaixo de 2048 bits, ou DSA |
| `KODA-RISK-MD5-SIGNATURE`, `KODA-RISK-SHA1-SIGNATURE` | `risk_observed` | Certificado assinado com MD5 ou SHA-1, exceto quando o coletor o verificou como autoassinado |
| `KODA-RISK-LEGACY-TLS-ALLOWED`, `KODA-RISK-LEGACY-CRYPTO-POLICY` | `risk_observed` | Configuração que permite protocolos anteriores ao TLS 1.2, ou a política criptográfica de sistema LEGACY |
| `KODA-RISK-PICKLE-DANGEROUS-IMPORTS` | `risk_observed` | O pickle de um arquivo de modelo, ou de um checkpoint de um diretório de modelo, importa chamáveis que podem executar código |
| `KODA-RISK-PICKLE-UNKNOWN-IMPORTS` | `review_required` | O pickle importa módulos fora da lista permitida, ou a inspeção ficou incompleta |
| `KODA-RISK-LISTENER-FIREWALL-ACCEPT` | `risk_observed`, `review_required` | Escuta do host fora do loopback aceita pelas regras de firewall declaradas; origens restritas, regras não avaliadas ou a ausência de declaração de firewall ativa (`none-observed`) exigem revisão |

## Tabela NIS-SBOM

`nis-sbom` converte um SBOM CycloneDX coletado nos 20 campos básicos do NIS-SBOM 1.0 (tabela 35 do guia coreano "SW 공급망 보안 가이드라인 1.0"). O guia define os campos e um formato de tabela, não um esquema de arquivo; por isso o resultado é um CSV em UTF-8 com uma linha por componente de software. Apenas componentes de software são listados. Hardware, arquivos e ativos criptográficos ficam de fora.

```sh
./koda-bom nis-sbom \
  --sbom ./reports/COLLECTION/sbom.cdx.json \
  --organization EXAMPLE \
  --output ./nis-sbom.csv
```

`--organization` e `--sequence` (padrão 1) formam o ID do SBOM `EXAMPLE-YYYYMMDD-000001`. `--product`, `--product-version` e `--author` substituem o nome do alvo analisado e o do coletor. O fornecedor é o registrado no SBOM ou, na falta dele, o namespace do PURL. Apenas hashes SHA-256 ou mais fortes são listados. `SBOM Type` segue a fase do ciclo de vida registrada no SBOM e é `Deployed` quando não há nenhuma. `SPDX Doc. ID` e `Component Alias` ficam vazios. `Vul. DB` e `Vul. Info` ficam vazios porque o coletor não compara vulnerabilidades. Um valor que uma planilha executaria como fórmula recebe um `'` inicial.

## Observações TCP

`--network-evidence` compara medições existentes com sockets do host/OBOM arquivado. `hostField` é `machineIdSha256`, `productUuidSha256`, `assetTag` explícito. `scope` é `host` ou ID completo de contêiner com 64 caracteres.

```json
{
  "schema": "koda-network-observations-1",
  "hostField": "assetTag",
  "hostValue": "app-01",
  "observations": [{
    "scope": "host",
    "protocol": "tcp",
    "bindAddress": "0.0.0.0",
    "targetAddress": "192.0.2.10",
    "port": 443,
    "vantage": "branch-office",
    "observedAt": "2026-11-21T09:30:00+09:00",
    "result": "connected"
  }]
}
```

Resultados `connected`, `refused`, `timed-out`. Proprietários ambíguos ou sockets ausentes ficam sem associação. Cada ponto/horário exige observação própria. O coletor não testa conexões. [Matriz de suporte](support-matrix.pt.md) · [Evidências adicionais](additional-bom.pt.md)
