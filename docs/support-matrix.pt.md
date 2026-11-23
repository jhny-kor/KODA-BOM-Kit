# Escopo de coleta e limites

<!-- koda-doc-nav -->
<p align="center">
  <a href="support-matrix.md"><img src="badges/en.svg" alt="English"></a>
  <a href="support-matrix.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="support-matrix.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="support-matrix.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="support-matrix.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="support-matrix.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="support-matrix.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="support-matrix.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="support-matrix.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="support-matrix.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->


Esta matriz descreve evidências identificáveis. Consulte estados e motivos em `collection.json`. A completude depende de metadados legíveis, formatos e permissões. Avaliação de vulnerabilidades exige avisos correspondentes.

## Sete BOMs CycloneDX

O host `/` gera documentos em `boms/` e a combinação `bom.cdx.json`. `--cyclonedx-17` adiciona 1.7. Ausência de evidência é explícita com `no-evidence` e cobertura desconhecida. [Categorias CycloneDX](https://github.com/CycloneDX/specification#readme)

| BOM | Evidências disponíveis | Complementos |
|---|---|---|
| SBOM | Pacotes OS/linguagem, versões/PURL, licenças/dependências, JAR, módulos, contêineres | CycloneDX/SPDX fornecedor/CI ligado ao SHA-256 para dependências estáticas/de compilação, em `build-sbom.cdx.json` |
| HBOM | CPU/placa/dispositivos/drivers/firmware, DIMM EDAC, sensores, módulos de memória SMBIOS (fabricante, número de peça, velocidade), fontes de alimentação e slots | Redfish/registros de peças invisíveis, números, fornecedores, ciclo de vida |
| CBOM | Certificados/chaves/algoritmos públicos, emissores verificados, TLS/SSH, JKS, chaves públicas de host SSH, política criptográfica do sistema e declarações OpenSSL de protocolo/cifra/grupo | TLS medido e metadados públicos exportados de HSM/KMS/lojas protegidas |
| OBOM | Host/contêiner/processo/arquivo/pacote/socket e systemd, destinos TCP de saída por processo, timers do systemd, tarefas cron e regras de firewall declaradas | Kubernetes do mesmo cluster, Pod/workload/Service/Ingress, labels, `--network-evidence` do host |
| SaaSBOM | Especificações/OpenAPI para `saasbom.cdx.json`. Também OpenAPI YAML e backends declarados na configuração do nginx, Apache e HAProxy | Provedor/catálogo/API, dependências externas, autenticação, confiança, fluxos classificados |
| AI-BOM | Configuração, quantização/contexto, índices, cabeçalhos/tamanhos GGUF/safetensors, Ollama. SHA-256 completo de artefatos explícitos. `aibom.cdx.json`. Também cabeçalhos ONNX, segurança de importações pickle do PyTorch, cartões de modelo e refs de cache do Hugging Face, e o modelo indicado ao iniciar um servidor de modelos | Identidade/revisão/pesos, linhagem, cartões/licenças, fontes de treinamento/avaliação |
| MBOM | SLSA correspondente ou montagem/testes declarados em `mbom.cdx.json` `formulation` | Etapas/ferramentas/entradas/saídas/execuções CI, histórico de fabricação/inspeção |

## Camadas

| Camada | Evidências e limites |
|---|---|
| OS | os-release/vendor release, DB RPM/DEB/APK. Permissões, corrupção, source package/module stream ausente podem limitar |
| Hardware/firmware | CPU/microcódigo/CPUID/topologia/ARM, DMI, BIOS/UEFI/ESRT, PCI, NVMe/SCSI, USB, TPM. RAID/HBA, RDMA, GPU VBIOS e NIC dependem do driver. megaraid_sas exige exportação, BMC root/IPMI e comparação de revisão. VM/contêiner pode refletir host físico |
| Externos | Redfish expandido, fwupd/devlink/JSON comum. Preserva estado/versão relatados, revise itens sem associação |
| Windows/macOS | Sistema/OS/firmware/aplicações. Windows inclui verificações de compilação cruzada. Dependências internas/atualizações exigem mais dados |
| Execução | Executáveis/bibliotecas e pacote proprietário no mesmo escopo. Substituição justifica revisão de reinício |
| Identidade | SHA-256 machine-id/UUID/séries e tag explícito no host `/`. Permissões/valores genéricos afetam disponibilidade. Pseudonimização |
| Sockets | TCP LISTEN/UDP do mesmo namespace e FDs. Bind não determina firewall. Sem proprietário `unattributedSockets` |
| Conexões de saída | TCP estabelecido cuja porta local não está em escuta, por processo e destino remoto, até 16.384 sockets. Porta local fixa para porta efêmera do par conta como conexão aceita. Só aparecem conexões abertas no momento da coleta. Apenas processos do host. Uma conexão para uma porta em que este host escuta liga o processo cliente a esse socket e ao processo dono dele |
| Tarefas agendadas | `/etc/crontab`, `/etc/cron.d`, crontabs de usuário e scripts `cron.{hourly,daily,weekly,monthly}`, além de timers do systemd habilitados com seu agendamento `On*`. Só o caminho absoluto do programa é mantido; os argumentos são descartados |
| Firewall | Arquivos iptables-save (RHEL/Debian/ufw), zona padrão do firewalld com seus serviços e cadeias nftables com hook input e includes literais. São declarações de arquivo; o conjunto de regras carregado no kernel não é lido. Cadeia base sem política aceita; ufw com `ENABLED=no` é registrado como `disabled`, e um framework cuja unidade systemd está instalada mas não habilitada nem em execução, ou mascarada, como `not-enabled`; nenhum dos dois conta como ativo. Regras só de loopback, de estado estabelecido ou negadas não contam como portas abertas; aceitar TCP/UDP de todo o protocolo abre todas as suas portas. Sockets em escuta fora do loopback no namespace de rede do host recebem `firewall-declared`: `accept-declared`, `accept-declared-restricted`, `policy-accept-declared`, `no-accept-declared`, `undetermined` ou `none-observed` quando nenhuma declaração ativa foi lida. Sockets de contêineres têm namespace de rede próprio e não recebem valor. Portas que contêineres publicam via NAT passam por regras FORWARD, que não são avaliadas |
| Configurações/reinício | SELinux, AppArmor, lockdown, FIPS, arranque permitido, kernel `y`/`m`, reboot-required, módulos/kernel mais novo da família. Ausência de sinais não prova que reinício seja desnecessário |
| SSH | Declarações globais, exclui `Match`, não calcula precedência efetiva de `Include` |
| Taint/módulos | `kernel.tainted`, `/proc/modules`, sysfs version/srcversion disponíveis |
| Executáveis desconhecidos | Mesmo root sem pacote/componente/produto. Exclui outros namespaces de montagem. Requer investigação |
| Origem | apt texto/gz/lz4 por nome, dnf/yumdb. Listas removidas, dnf5/apk sem suporte. Omite URL/caminhos |
| Serviços | systemd wants/requires, units/drop-ins, cgroup v1/v2. Primeiro ExecStart. Caminhos relativos sem pacote. Slice próprio pode parecer parado. Sem SysV. Timers habilitados registram o agendamento `On*` e o serviço que iniciam |
| CPE | Intel Xeon/Core, AMD EPYC/Ryzen, Dell PowerEdge dispositivo/BIOS, Lenovo ThinkSystem. Lacunas de dicionário/modelo podem impedir associação. Sem HPE/BMC |
| Integridade | Hashes de executáveis/bibliotecas RPM/dpkg/apk. Exclui config/ghost. 8 GiB host, 1 GiB contêiner. prelink pode causar falso desvio |
| CBOM | PEM/DER, chaves/algoritmos públicos, cadeias JKS v1/v2 e hashes de alias. Ignora chaves cifradas, integridade JKS não verificada. Exclui nomes, chaves privadas, PKCS#12, lojas OS e arquivos >20 certificados. Inclui chaves públicas de host SSH. `crypto-policies` e MinProtocol/CipherString/Ciphersuites/Groups do `openssl.cnf` são declarações; `.include` e a ativação de seções não são resolvidos |
| Kernel | uname, imagens/módulos instalados, vermagic, RPM. Distingue ativo/instalado. Módulo ausente pode ser recurso embutido |
| Livepatch | sysfs, Oracle raw Ksplice, helper Ksplice/Uptrack/Canonical opcional. Divergências boot/kernel/hora invalidam aplicação. CVE exige análise |
| Java | JDK/JRE release, manifestos JAR/WAR/EAR, Maven. Shaded alterado/removido limita |
| PHP | Pacote/intérprete, Composer instalado, PEAR. Exclui lock isolado. Exploração depende da configuração |
| snap/flatpak/conda | snap current/DEB, flatpak active/AppStream, conda-meta. PURL generic snap/flatpak, versão ausente sem AppStream, apenas nome do canal conda |
| Python | dist-info/egg-info, venv, metadados reais `.pyz`/`.pex`. Ausência/permissões limitam |
| Node/JS | node_modules/runtime, jQuery/jQuery UI/Fancytree em arquivos e EAR/WAR/ZIP/JAR. Nome apenas é insuficiente. Estruturas e limites suportados |
| Go/Rust | Build info Go, cargo-auditable ELF. Sem dados, dependências desconhecidas. Corrupção/excesso gera parcial |
| .NET | `.deps.json`, DLL gerenciada, recursos de versão. DLL isolada sem NuGet PURL, single-file precisa verificação |
| Ruby | specifications/gems instalados e default. Gemfile.lock isolado/metadados removidos insuficientes |
| Servidores nativos | httpd/nginx/OpenSSL/OpenSSH/Redis/PostgreSQL/MySQL/MariaDB. Binários próprios/strip/cópias estáticas podem ficar desconhecidos |
| Servidores Java | Tomcat ServerInfo/manifest/catalina.jar, WebLogic/JBoss/WildFly instalação/patch. `.patch_storage` isolado não prova aplicação. JEUS sem fixtures reais não verificado |
| Parados/imagens | Docker overlay2, containerd overlayfs/k3s/RKE2, Podman/CRI-O rootful. Reconstrução temporária 16 GiB/root e espaço verificado. Sem outros drivers/rootless nem sockets |
| Ativos | Roots procfs, metadados em disco, `containers/<name>/`. Exclui volumes/bind mounts e sandbox Kubernetes. Root invisível explicado. Sem API, sockets apenas de processos do contêiner |
| Imagens | Docker/OCI tar Linux amd64 explícito, hash/digest verificado. Conteúdo da imagem, kernel/execução host observados separadamente |
| AIX/Oracle | `aix-import` filesets, fixes temporários, OPatch por Home, SQL opcional. Até oito Homes por servidor. Estado de execução exige evidência |

Instalações manuais preservam local/instância. Nome e versão iguais podem ter patches distintos. CPE desconhecido permanece vazio. Use identificadores confirmados e provas na revisão posterior.

Padrões CycloneDX 1.6/SPDX 2.3, com 1.7 opcional. [Inventário e avaliação](asset-inventory.pt.md) explica `assess`, OSV/CSAF exatos e esquemas. [Evidência adicional](additional-bom.pt.md) cobre serviços, modelos e fabricação.

## Cenários de regressão

Cobrem PHP/Composer, Node runtime/node_modules, builds JDK completos, instalação/patch WebLogic, Tomcat manual/AJP/HTTP2, releases httpd/mod_http2, origem/alias/rewrite nginx, cópias OpenSSL CLI/libssl/libcrypto e kernels UEK/RHCK ativos/instalados. Os cenários verificam identificação. A conclusão sobre vulnerabilidade requer comparação com avisos.
