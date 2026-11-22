# Resultados de verificação

<!-- koda-doc-nav -->
<p align="center">
  <a href="verification-results.md"><img src="badges/en.svg" alt="English"></a>
  <a href="verification-results.ja.md"><img src="badges/ja.svg" alt="日本語"></a>
  <a href="verification-results.zh.md"><img src="badges/zh.svg" alt="简体中文"></a>
  <a href="verification-results.zh-hant.md"><img src="badges/zh-hant.svg" alt="繁體中文"></a>
  <a href="%EA%B2%80%EC%A6%9D%EA%B2%B0%EA%B3%BC.ko.md"><img src="badges/ko.svg" alt="한국어"></a>
  <a href="verification-results.es.md"><img src="badges/es.svg" alt="Español"></a>
  <a href="verification-results.fr.md"><img src="badges/fr.svg" alt="Français"></a>
  <a href="verification-results.vi.md"><img src="badges/vi.svg" alt="Tiếng Việt"></a>
  <strong>Português</strong>
  <a href="verification-results.th.md"><img src="badges/th.svg" alt="ไทย"></a>
  <a href="verification-results.tr.md"><img src="badges/tr.svg" alt="Türkçe"></a>
</p>
<p align="center">
  <a href="https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8"><img src="badges/release.svg" alt="v0.1.8"></a>
  <a href="../LICENSE"><img src="badges/license.svg" alt="Apache-2.0"></a>
</p>
<!-- /koda-doc-nav -->

Os registros do KODA BOM Kit e versões antigas incluem data, hash, ambiente, resultados parciais e áreas pendentes. A publicação oficial 0.1.8 identifica arquivo, checksum e escopo. Cada novo binário requer suas próprias provas.

[Publicação 0.1.8](https://github.com/jhny-kor/KODA-BOM-Kit/releases/tag/v0.1.8)

## 2026-11-21 — divisão e mesclagem

`f0610ca-worktree-00ed83f2acd8` testou `scan --separate-boms`, `bom-split`, `bom-merge` e `domain-bom` com dois resultados 0.1.6 arquivados. Todos os componentes e vínculos foram comparados, acrescentando uma relação entre raízes por mesclagem. Dez pares de IDs de certificados Ubuntu representavam 20 posições preservadas. A mesclagem teve zero IDs duplicados. Linux ARM64 combinou quatro BOM observados com entradas sintéticas OpenAPI, modelo, SLSA e fabricação. TCP 18443 real foi ligado ao Perl e pacote. Esquemas e hashes passaram. Autenticidade e evidência de campo exigem verificação própria.

| Arquivo | Componentes antes / depois | Relações antes / depois |
|---|---:|---:|
| ubuntu | 158,522 / 158,522 | 18,795,889 / 18,795,890 |
| archive-2 | 31,064 / 31,064 | 42,524 / 42,525 |

## 2026-11-21 — relações operacionais

`f0610ca-worktree-06f22395e26f` regenerou OBOM de duas coletas parciais. Sockets são contados por namespace/processo. Debian ARM64 vinculou `127.0.0.1:18443/tcp` a `/usr/bin/perl` e `perl-base`, verificou três peças Redfish, exemplos TLS, duas relações de build e 11 checksums. OBOM regenerados eram idênticos. Cinco recursos Kubernetes sintéticos foram ligados a IDs completos arquivados. Clusters reais, hardware e sessões TLS ficaram fora.

| Arquivo | Contêineres | Sockets host + contêineres | Pacote host + contêineres | Relações comparadas |
|---|---:|---:|---:|---:|
| ubuntu | 65 | 101 + 109 | 10 + 66 | 3,250 |
| archive-2 | 0 | 60 + 0 | 51 + 0 | 6,193 |

## 2026-11-21 — 12 correções Daybreak

Foram tratados achados de KODA-SBOM-Maker `cc86c1b`. Cobrem isolamento Go, hash do fluxo extraído, limite de 256 camadas e reutilização de hashes, índices ZIP/ZIP64 limitados, whiteouts validados, diretórios exclusivos, correlação de avisos indexada/limitada, recusa de Python otimizado, leitura em raízes verificadas, IDs curtos seguros, conflitos RPM com epoch e percurso cancelável em blocos de 256 entradas.

Go, vet e controles de publicação passaram em macOS ARM64. Go 1.26.11 / Syft 1.57.1 gerou Linux amd64 estático offline. Passaram 306 checksums e testes CLI/diretórios em Debian sem rede. Antes/depois coincidiram 88 pacotes, um SO, 20 dispositivos e 15 drivers. Ambas as coletas foram parciais com motivos. Outras plataformas foram compiladas. Execução e novas VM ficaram pendentes.

```text
source: src8d8c9fe3e5b3
archive SHA-256: e6add9a97af192684b3939254791adcf4923645e377307344f71c9097bc2ebb3
koda-sbom SHA-256: 64dc47888ef64cea303ab4df4660dd89856eaa15d47cc4b48026b0eed33a3a22
```

## 2026-11-20 — 0.1.7

Linux, Go e vet passaram em Docker Desktop `7.0.14-linuxkit`. CPU coincidiu com lscpu, com 1,736 opções de kernel. Debian teve um pacote local não registrado entre 147. Rocky identificou 167 pacotes de repositório e instalações locais/sem registro. Nove contêineres ativos, 14 parados e 11 imagens sem uso produziram 35 SBOM em cerca de 3 min 30 s. Contagens 796, 71 e 51 coincidiram. Overlay2 preservou curl e coletou busybox sem uso. Um contêiner removido foi `not_collected`. x86 real, systemd, Kubernetes/k3s/Podman/CRI-O e novas VM não foram verificados.

## 2026-11-19 — 0.1.6

Debian 12 / Linux ARM64 / Docker Desktop `7.0.14-linuxkit` verificou identidade, sockets, 16 contêineres e cinco módulos externos. Em 735 arquivos, cerca de 89 MB, detectou exatamente um alterado e um movido/ausente. RSA-1024 e ECDSA P-384 verificaram validade e chaves fracas sem exportar chaves privadas. Hardware, snap/flatpak/conda e parte das configurações usaram casos sintéticos. RAID/NIC/BMC físicos, SELinux de produção, outros motores e novas VM ficaram pendentes.

## 2026-11-18 — 0.1.6-dev

Go, vet, auxiliares e shell passaram. Linux amd64/ARM64 e inventário básico macOS ARM64 real validaram esquemas e checksums. Windows apenas compilado. Arquivos removidos/substituídos, hashes de imagens e regras locais foram testados. O analisador Tracker local leu ambos CycloneDX. Produção e navegador não verificados. Preservada a semântica de 704/811 licenças e 107 adicionais. O total de checksums varia conforme o escopo.

## Histórico 0.1.2–0.1.5

0.1.5 acrescentou relações pnpm e Maven POM, 0.1.4 o auxiliar de diretórios, 0.1.3 limites de arquivos/tempo. Relacione hashes com `release.json`, `VERIFICATION.json` e `dist/evidence/v0.1.x/final-verification.json`, quando fornecidos. 0.1.2 repetiu Ubuntu e ambos kernels Oracle com o binário final. Clientes com assinatura e aplicação real de patches ficaram fora dos testes sintéticos.

## 2026-10-29 — implementação e VM Oracle

Passaram 68 verificações Linux e vet. Casos uid 65534, entradas/rootfs somente leitura, sem capacidades nem rede validaram esquemas, PURL, canários e falhas. Oracle tinha RPM 182, Python 5, binary 2. A trace guest syscall registrou zero tentativas de rede e execve adicionais. Ambos os formatos receberam HTTP 202 em Tracker SQLite isolado. Um caso pequeno 0.1.0 levou 0.78 s e RSS máximo 219,644 KiB.

VM Oracle Linux 8.2 iniciaram RHCK/UEK assinados, com uname/proc e loop coincidentes. Cada uma produziu 5,516 componentes, incluindo RPM 186, kernels 2, módulos 5,321, Python 5 e binary 2. As árvores tinham RHCK 2,478 e UEK 2,843 módulos. Passaram esquemas e cinco checksums por VM. Saída 3, coleta parcial e contexto completo preservaram arquivos protegidos, links externos, conflitos OpenSSH e avisos Syft.

| Kernel | Coleta / total segundos |
|---|---:|
| RHCK `4.18.0-193.el8.x86_64` | 218.445 / 235.169 |
| UEK `5.4.17-2011.1.2.el8uek.x86_64` | 252.524 / 269.963 |

## Limites da evidência

As primeiras VM usaram o hash 0.1.0 abaixo. Versões posteriores possuem relatórios próprios. Servidores x86 físicos, boot completo, serviços e patches do fornecedor ficaram fora. QEMU guest trace e ptrace nativo têm ambientes diferentes. Coleta ao vivo pode misturar momentos. Use uma janela estável ou snapshot somente leitura. Versões e ausência de observações não bastam para confirmar aplicabilidade ou correção de CVE.

```text
0.1.0 koda-sbom SHA-256: 98384927a272573b0ecd348a55e76d3700008c9677eb3dea16bb76ed2590724b
```

## Documentação

[Execução offline e inspeção](air-gapped.pt.md) · [Compilação e verificação](verification.pt.md) · [Resultados de verificação](verification-results.pt.md)
